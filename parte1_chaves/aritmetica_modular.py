"""Aritmética modular usada pelo RSA.

Implementada pelo grupo (não usar pow(a, -1, m) nem bibliotecas externas),
pois faz parte do critério "geração RSA, aritmética modular e Miller-Rabin".
"""


def mdc_estendido(a: int, b: int) -> tuple[int, int, int]:
    """Retorna (g, x, y) tais que a*x + b*y = g = mdc(a, b).

    Algoritmo de Euclides estendido em forma iterativa: evita o limite de
    recursão do Python para os inteiros de centenas de bits usados no RSA.
    """
    resto_anterior, resto_atual = a, b
    x_anterior, x_atual = 1, 0
    y_anterior, y_atual = 0, 1

    while resto_atual != 0:
        quociente = resto_anterior // resto_atual
        resto_anterior, resto_atual = resto_atual, resto_anterior - quociente * resto_atual
        x_anterior, x_atual = x_atual, x_anterior - quociente * x_atual
        y_anterior, y_atual = y_atual, y_anterior - quociente * y_atual

    return resto_anterior, x_anterior, y_anterior


def inverso_modular(a: int, m: int) -> int:
    """Retorna a^-1 mod m; lança ValueError se mdc(a, m) != 1."""
    if m <= 0:
        raise ValueError("módulo deve ser positivo")

    mdc, x, _ = mdc_estendido(a % m, m)
    if mdc != 1:
        raise ValueError(f"{a} não possui inverso módulo {m} (mdc = {mdc})")
    return x % m


def exp_modular(base: int, expoente: int, modulo: int) -> int:
    """Exponenciação modular por quadrados sucessivos (square-and-multiply).

    Expoente negativo é tratado como exponenciação pelo inverso modular de
    `base`, para simetria com o `pow` nativo do Python.
    """
    if modulo == 1:
        return 0
    if expoente < 0:
        base = inverso_modular(base, modulo)
        expoente = -expoente

    resultado = 1
    base %= modulo
    while expoente > 0:
        if expoente & 1:
            resultado = (resultado * base) % modulo
        base = (base * base) % modulo
        expoente >>= 1
    return resultado


def mmc(a: int, b: int) -> int:
    """Mínimo múltiplo comum: mmc(a, b) = a*b / mdc(a, b)."""
    return a // mdc_estendido(a, b)[0] * b
