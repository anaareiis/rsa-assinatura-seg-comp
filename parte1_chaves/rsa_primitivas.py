"""Primitivas RSA da RFC 8017, Seções 5.1 e 5.2.

RSAEP/RSAVP1 usam a chave pública; RSADP/RSASP1 usam a privada (com CRT).
Estas funções NÃO devem ser usadas diretamente sobre mensagens: sempre
passar por OAEP (cifragem) ou PSS (assinatura). Ver parte5_analise.
"""

from parte1_chaves.chaves import ChavePrivada, ChavePublica


def rsaep(chave: ChavePublica, m: int) -> int:
    """c = m^e mod n, com verificação 0 <= m < n."""
    raise NotImplementedError("TODO Pessoa A")


def rsadp(chave: ChavePrivada, c: int) -> int:
    """m = c^d mod n usando o Teorema Chinês do Resto, com verificação 0 <= c < n."""
    raise NotImplementedError("TODO Pessoa A")


def rsasp1(chave: ChavePrivada, m: int) -> int:
    """Primitiva de assinatura: matematicamente igual a RSADP."""
    return rsadp(chave, m)


def rsavp1(chave: ChavePublica, s: int) -> int:
    """Primitiva de verificação: matematicamente igual a RSAEP."""
    return rsaep(chave, s)
