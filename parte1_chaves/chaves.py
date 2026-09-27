"""Estruturas das chaves RSA e geração do par de chaves."""

from dataclasses import dataclass

TAMANHO_MINIMO_BITS = 2048
EXPOENTE_PUBLICO_PADRAO = 65537


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
    raise NotImplementedError("TODO Pessoa A")
