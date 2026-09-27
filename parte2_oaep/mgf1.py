"""MGF1 (RFC 8017, Apêndice B.2.1) com SHA3-256.

Usada tanto pelo OAEP (Parte II) quanto pelo PSS (Parte III).
"""

from comum.conversoes import i2osp
from comum.erros import ErroParametro
from comum.hash_sha3 import H_LEN, sha3_256


def mgf1(semente: bytes, tamanho_mascara: int) -> bytes:
    """T = H(semente || I2OSP(0,4)) || H(semente || I2OSP(1,4)) || ...

    Retorna os primeiros `tamanho_mascara` bytes de T.
    Lança ErroParametro se tamanho_mascara > 2^32 * H_LEN.
    """
    if not 0 <= tamanho_mascara <= (2 ** 32) * H_LEN:
        raise ErroParametro("tamanho de máscara inválido")

    # ceil(tamanho_mascara / H_LEN) blocos, cada um com um contador de 4 bytes
    blocos = (tamanho_mascara + H_LEN - 1) // H_LEN
    t = b"".join(sha3_256(semente + i2osp(contador, 4)) for contador in range(blocos))
    return t[:tamanho_mascara]
