"""Estruturas das chaves RSA e geração do par de chaves."""

from dataclasses import dataclass

from parte1_chaves.aritmetica_modular import inverso_modular, mdc_estendido, mmc
from parte1_chaves.miller_rabin import gerar_primo_provavel

TAMANHO_MINIMO_BITS = 2048
EXPOENTE_PUBLICO_PADRAO = 65537
_MARGEM_BITS_DIFERENCA_MINIMA = 100
# FIPS 186-5 Apêndice A.1.1, critério 2(d): |p - q| > 2^(nlen/2 - 100).


@dataclass(frozen=True)
class ChavePublica:
    n: int
    e: int

    @property
    def k(self) -> int:
        """Tamanho do módulo em bytes (k na RFC 8017)."""
        return (self.n.bit_length() + 7) // 8


@dataclass(frozen=True)
class ChavePrivada:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int    # d mod (p-1)       -> parâmetros CRT
    dq: int    # d mod (q-1)
    qinv: int  # q^-1 mod p

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def publica(self) -> ChavePublica:
        return ChavePublica(self.n, self.e)


def gerar_par_chaves(bits: int = TAMANHO_MINIMO_BITS,
                     e: int = EXPOENTE_PUBLICO_PADRAO) -> ChavePrivada:
    """Gera um par de chaves RSA com módulo de `bits` bits (>= 2048).

    Passos: gerar p e q de bits/2 com Miller-Rabin, garantir p != q,
    |p - q| grande e mdc(e, lambda(n)) == 1; calcular d = e^-1 mod lambda(n)
    (ou phi(n)) e os parâmetros CRT.
    """
    if bits < TAMANHO_MINIMO_BITS:
        raise ValueError(f"módulo deve ter no mínimo {TAMANHO_MINIMO_BITS} bits")
    if bits % 2 != 0:
        raise ValueError("bits deve ser par (bits/2 para cada primo)")

    p, q = _gerar_primos_distintos(bits // 2, e)
    n = p * q
    lambda_n = mmc(p - 1, q - 1)

    d = inverso_modular(e, lambda_n)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = inverso_modular(q, p)

    return ChavePrivada(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)


def _gerar_primos_distintos(bits_por_primo: int, e: int) -> tuple[int, int]:
    """Gera p e q com `bits_por_primo` bits cada, distintos, afastados e
    coprimos com `e` (condição necessária para d = e^-1 mod lambda(n) existir).
    """
    diferenca_minima = 1 << max(bits_por_primo - _MARGEM_BITS_DIFERENCA_MINIMA, 0)

    p = _gerar_primo_coprimo_com_expoente(bits_por_primo, e)
    while True:
        q = _gerar_primo_coprimo_com_expoente(bits_por_primo, e)
        if q != p and abs(p - q) >= diferenca_minima:
            return p, q


def _gerar_primo_coprimo_com_expoente(bits: int, e: int) -> int:
    """Gera primos até encontrar um com mdc(e, primo - 1) == 1."""
    while True:
        candidato = gerar_primo_provavel(bits)
        if mdc_estendido(e, candidato - 1)[0] == 1:
            return candidato
