"""Teste probabilístico de primalidade de Miller-Rabin e geração de primos.

Referências: FIPS 186-5, Apêndice B.3; NIST SP 800-56B Rev. 2.
Aleatoriedade: usar o módulo `secrets` (CSPRNG), nunca `random`.
"""


def eh_provavel_primo(n: int, rodadas: int = 40) -> bool:
    """Retorna True se `n` passa em `rodadas` iterações de Miller-Rabin.

    Probabilidade de erro <= 4^-rodadas. Deve tratar n < 2, n par e
    pequenos primos antes do laço principal.
    """
    raise NotImplementedError("TODO Pessoa A")


def gerar_primo_provavel(bits: int) -> int:
    """Gera um primo provável com exatamente `bits` bits.

    Força o bit mais significativo (e o segundo, para que p*q tenha 2*bits)
    e o menos significativo (ímpar) antes de testar.
    """
    raise NotImplementedError("TODO Pessoa A")
