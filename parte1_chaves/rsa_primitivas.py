"""Primitivas RSA da RFC 8017, Seções 5.1 e 5.2.

RSAEP/RSAVP1 usam a chave pública; RSADP/RSASP1 usam a privada (com CRT).
Estas funções NÃO devem ser usadas diretamente sobre mensagens: sempre
passar por OAEP (cifragem) ou PSS (assinatura). Ver parte5_analise.
"""

from comum.erros import ErroParametro
from parte1_chaves.aritmetica_modular import exp_modular
from parte1_chaves.chaves import ChavePrivada, ChavePublica


def rsaep(chave: ChavePublica, m: int) -> int:
    """c = m^e mod n, com verificação 0 <= m < n."""
    _validar_representante(m, chave.n)
    return exp_modular(m, chave.e, chave.n)


def rsadp(chave: ChavePrivada, c: int) -> int:
    """m = c^d mod n usando o Teorema Chinês do Resto, com verificação 0 <= c < n."""
    _validar_representante(c, chave.n)
    return _decifrar_com_crt(chave, c)


def rsasp1(chave: ChavePrivada, m: int) -> int:
    """Primitiva de assinatura: matematicamente igual a RSADP."""
    return rsadp(chave, m)


def rsavp1(chave: ChavePublica, s: int) -> int:
    """Primitiva de verificação: matematicamente igual a RSAEP."""
    return rsaep(chave, s)


def _validar_representante(valor: int, n: int) -> None:
    """RFC 8017 §5: o representante inteiro deve estar em [0, n-1]."""
    if not 0 <= valor < n:
        raise ErroParametro("representante fora do intervalo [0, n-1]")


def _decifrar_com_crt(chave: ChavePrivada, c: int) -> int:
    """Teorema Chinês do Resto (RFC 8017 §5.1.2): opera com expoentes e
    módulos de metade do tamanho de n, cerca de 4x mais rápido que
    calcular c^d mod n diretamente.
    """
    m1 = exp_modular(c % chave.p, chave.dp, chave.p)
    m2 = exp_modular(c % chave.q, chave.dq, chave.q)
    h = (chave.qinv * (m1 - m2)) % chave.p
    return m2 + h * chave.q
