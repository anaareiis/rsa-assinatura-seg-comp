"""RSASSA-PSS (RFC 8017, Seções 8.1 e 9.1) com SHA3-256 e MGF1-SHA3-256.

A assinatura NÃO é "cifrar o hash": o digest passa pela codificação
probabilística EMSA-PSS (salt aleatório + MGF1) antes da primitiva RSASP1.
"""

from parte1_chaves.chaves import ChavePrivada, ChavePublica

TAMANHO_SALT_PADRAO = 32  # sLen = hLen


def emsa_pss_codificar(m_hash: bytes, em_bits: int,
                       tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017, 9.1.1) a partir do digest da mensagem.

    M' = 0x00*8 || mHash || salt;  H = Hash(M');
    DB = PS || 0x01 || salt;  maskedDB = DB xor MGF1(H);
    zera os 8*emLen - emBits bits mais à esquerda;  EM = maskedDB || H || 0xbc.
    """
    raise NotImplementedError("TODO Pessoa C")


def emsa_pss_verificar(m_hash: bytes, em: bytes, em_bits: int,
                       tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bool:
    """EMSA-PSS-VERIFY (RFC 8017, 9.1.2): True se consistente, False caso contrário."""
    raise NotImplementedError("TODO Pessoa C")


def assinar_digest(chave: ChavePrivada, m_hash: bytes,
                   tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bytes:
    """RSASSA-PSS-SIGN: emBits = modBits - 1; retorna assinatura com k bytes."""
    raise NotImplementedError("TODO Pessoa C")


def verificar_digest(chave: ChavePublica, m_hash: bytes, assinatura: bytes,
                     tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bool:
    """RSASSA-PSS-VERIFY: nunca lança exceção por assinatura inválida; retorna False."""
    raise NotImplementedError("TODO Pessoa C")
