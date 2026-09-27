"""MGF1 (RFC 8017, Apêndice B.2.1) com SHA3-256.

Usada tanto pelo OAEP (Parte II) quanto pelo PSS (Parte III).
"""


def mgf1(semente: bytes, tamanho_mascara: int) -> bytes:
    """T = H(semente || I2OSP(0,4)) || H(semente || I2OSP(1,4)) || ...

    Retorna os primeiros `tamanho_mascara` bytes de T.
    Lança ErroParametro se tamanho_mascara > 2^32 * H_LEN.
    """
    raise NotImplementedError("TODO Pessoa B")
