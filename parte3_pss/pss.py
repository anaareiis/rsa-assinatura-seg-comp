"""RSASSA-PSS (RFC 8017, Seções 8.1 e 9.1) com SHA3-256 e MGF1-SHA3-256.

A assinatura NÃO é "cifrar o hash": o digest passa pela codificação
probabilística EMSA-PSS (salt aleatório + MGF1) antes da primitiva RSASP1.
"""

import hmac
import secrets

from comum.conversoes import i2osp, os2ip, xor_bytes
from comum.erros import ErroRSA, ErroParametro
from comum.hash_sha3 import H_LEN, sha3_256
from parte1_chaves.chaves import ChavePrivada, ChavePublica
from parte1_chaves.rsa_primitivas import rsasp1, rsavp1
from parte2_oaep.mgf1 import mgf1

TAMANHO_SALT_PADRAO = 32  # sLen = hLen


def emsa_pss_codificar(m_hash: bytes, em_bits: int,
                       tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017, 9.1.1) a partir do digest da mensagem.

    M' = 0x00*8 || mHash || salt;  H = Hash(M');
    DB = PS || 0x01 || salt;  maskedDB = DB xor MGF1(H);
    zera os 8*emLen - emBits bits mais à esquerda;  EM = maskedDB || H || 0xbc.
    """
    _validar_parametros(m_hash, em_bits, tamanho_salt)
    em_len = (em_bits + 7) // 8
    if em_len < H_LEN + tamanho_salt + 2:
        raise ErroParametro("tamanho do módulo insuficiente para RSA-PSS")

    salt = secrets.token_bytes(tamanho_salt)
    h = sha3_256(b"\x00" * 8 + m_hash + salt)

    tamanho_ps = em_len - H_LEN - tamanho_salt - 2
    db = b"\x00" * tamanho_ps + b"\x01" + salt
    masked_db = bytearray(xor_bytes(db, mgf1(h, em_len - H_LEN - 1)))

    # RFC 8017, 9.1.1, passo 11: o representante codificado deve ter no
    # máximo emBits bits, mesmo quando emLen ocupa um octeto a mais.
    bits_nao_usados = 8 * em_len - em_bits
    if bits_nao_usados:
        masked_db[0] &= 0xFF >> bits_nao_usados

    return bytes(masked_db) + h + b"\xbc"


def emsa_pss_verificar(m_hash: bytes, em: bytes, em_bits: int,
                       tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bool:
    """EMSA-PSS-VERIFY (RFC 8017, 9.1.2): True se consistente, False caso contrário."""
    try:
        _validar_parametros(m_hash, em_bits, tamanho_salt)
    except (ErroParametro, TypeError):
        return False

    em_len = (em_bits + 7) // 8
    if em_len < H_LEN + tamanho_salt + 2 or len(em) != em_len:
        return False
    if em[-1] != 0xBC:
        return False

    tamanho_masked_db = em_len - H_LEN - 1
    masked_db = em[:tamanho_masked_db]
    h = em[tamanho_masked_db:tamanho_masked_db + H_LEN]

    bits_nao_usados = 8 * em_len - em_bits
    if bits_nao_usados and masked_db[0] & (0xFF << (8 - bits_nao_usados)):
        return False

    db = bytearray(xor_bytes(masked_db, mgf1(h, tamanho_masked_db)))
    if bits_nao_usados:
        db[0] &= 0xFF >> bits_nao_usados

    tamanho_ps = em_len - H_LEN - tamanho_salt - 2
    if any(db[:tamanho_ps]) or db[tamanho_ps] != 0x01:
        return False

    salt = bytes(db[-tamanho_salt:]) if tamanho_salt else b""
    h_esperado = sha3_256(b"\x00" * 8 + m_hash + salt)
    return hmac.compare_digest(h, h_esperado)


def assinar_digest(chave: ChavePrivada, m_hash: bytes,
                   tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bytes:
    """RSASSA-PSS-SIGN: emBits = modBits - 1; retorna assinatura com k bytes."""
    em_bits = chave.n.bit_length() - 1
    em = emsa_pss_codificar(m_hash, em_bits, tamanho_salt)
    assinatura = rsasp1(chave, os2ip(em))
    return i2osp(assinatura, chave.k)


def verificar_digest(chave: ChavePublica, m_hash: bytes, assinatura: bytes,
                     tamanho_salt: int = TAMANHO_SALT_PADRAO) -> bool:
    """RSASSA-PSS-VERIFY: nunca lança exceção por assinatura inválida; retorna False."""
    try:
        if len(assinatura) != chave.k:
            return False

        representante_assinatura = os2ip(assinatura)
        if representante_assinatura >= chave.n:
            return False

        em_bits = chave.n.bit_length() - 1
        em_len = (em_bits + 7) // 8
        representante_mensagem = rsavp1(chave, representante_assinatura)
        em = i2osp(representante_mensagem, em_len)
        return emsa_pss_verificar(m_hash, em, em_bits, tamanho_salt)
    except (ErroRSA, TypeError, ValueError, OverflowError):
        return False


def _validar_parametros(m_hash: bytes, em_bits: int, tamanho_salt: int) -> None:
    """Valida os parâmetros fixos usados pelo perfil PSS do projeto."""
    if not isinstance(m_hash, bytes) or len(m_hash) != H_LEN:
        raise ErroParametro(f"digest deve ter exatamente {H_LEN} bytes")
    if not isinstance(em_bits, int) or em_bits <= 0:
        raise ErroParametro("emBits deve ser positivo")
    if not isinstance(tamanho_salt, int) or tamanho_salt < 0:
        raise ErroParametro("tamanho do salt deve ser não negativo")
