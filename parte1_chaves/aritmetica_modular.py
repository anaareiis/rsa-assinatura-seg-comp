"""Aritmética modular usada pelo RSA.

Implementada pelo grupo (não usar pow(a, -1, m) nem bibliotecas externas),
pois faz parte do critério "geração RSA, aritmética modular e Miller-Rabin".
"""


def mdc_estendido(a: int, b: int) -> tuple[int, int, int]:
    """Retorna (g, x, y) tais que a*x + b*y = g = mdc(a, b)."""
    raise NotImplementedError("TODO Pessoa A")


def inverso_modular(a: int, m: int) -> int:
    """Retorna a^-1 mod m; lança ValueError se mdc(a, m) != 1."""
    raise NotImplementedError("TODO Pessoa A")


def exp_modular(base: int, expoente: int, modulo: int) -> int:
    """Exponenciação modular por quadrados sucessivos (square-and-multiply)."""
    raise NotImplementedError("TODO Pessoa A")
