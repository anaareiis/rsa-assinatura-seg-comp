"""RSAES-OAEP (RFC 8017, Seção 7.1) com SHA3-256 e MGF1-SHA3-256.

Tamanho máximo da mensagem: k - 2*H_LEN - 2 bytes (190 bytes para RSA-2048).
"""

import hmac
import secrets

from comum.conversoes import i2osp, os2ip, xor_bytes
from comum.erros import ErroDecifracao, ErroParametro
from comum.hash_sha3 import H_LEN, sha3_256
from parte1_chaves.chaves import ChavePrivada, ChavePublica
from parte1_chaves.rsa_primitivas import rsadp, rsaep
from parte2_oaep.mgf1 import mgf1

# Mensagem única para toda falha de decifração: mensagens diferentes para
# cada verificação criariam um oráculo de padding (ataque de Manger, 2001).
_FALHA = "falha na decifração"


def tamanho_maximo_mensagem(k: int) -> int:
    """Maior mensagem cifrável com um módulo de k bytes: k - 2*hLen - 2."""
    return k - 2 * H_LEN - 2


def oaep_codificar(mensagem: bytes, k: int, rotulo: bytes = b"") -> bytes:
    """EME-OAEP encoding: EM = 0x00 || maskedSeed || maskedDB (k bytes).

    DB = lHash || PS || 0x01 || M; seed aleatória de H_LEN bytes (secrets).
    """
    if len(mensagem) > tamanho_maximo_mensagem(k):
        raise ErroParametro(
            f"mensagem longa demais: máximo de {max(tamanho_maximo_mensagem(k), 0)} bytes"
        )

    l_hash = sha3_256(rotulo)
    ps = b"\x00" * (k - len(mensagem) - 2 * H_LEN - 2)
    db = l_hash + ps + b"\x01" + mensagem  # k - hLen - 1 bytes

    seed = secrets.token_bytes(H_LEN)
    masked_db = xor_bytes(db, mgf1(seed, k - H_LEN - 1))
    masked_seed = xor_bytes(seed, mgf1(masked_db, H_LEN))
    return b"\x00" + masked_seed + masked_db


def oaep_decodificar(em: bytes, k: int, rotulo: bytes = b"") -> bytes:
    """EME-OAEP decoding. Lança ErroDecifracao com mensagem ÚNICA para
    qualquer falha (Y != 0, lHash diferente, separador 0x01 ausente),
    sem revelar qual verificação falhou.
    """
    if len(em) != k or k < 2 * H_LEN + 2:
        raise ErroDecifracao(_FALHA)

    y, masked_seed, masked_db = em[0], em[1:1 + H_LEN], em[1 + H_LEN:]
    seed = xor_bytes(masked_seed, mgf1(masked_db, H_LEN))
    db = xor_bytes(masked_db, mgf1(seed, k - H_LEN - 1))
    l_hash_recebido, resto = db[:H_LEN], db[H_LEN:]

    # Percorre o resto inteiro, sem sair do laço cedo, para achar o 0x01
    # que separa PS da mensagem; qualquer byte diferente de 0x00 antes
    # dele torna o padding inválido.
    indice_separador = -1
    padding_invalido = 0
    for i, byte in enumerate(resto):
        ainda_no_ps = indice_separador < 0
        if ainda_no_ps and byte == 0x01:
            indice_separador = i
        elif ainda_no_ps and byte != 0x00:
            padding_invalido = 1

    # As três verificações são combinadas e testadas uma única vez.
    l_hash_ok = hmac.compare_digest(l_hash_recebido, sha3_256(rotulo))
    if y != 0 or not l_hash_ok or padding_invalido or indice_separador < 0:
        raise ErroDecifracao(_FALHA)
    return resto[indice_separador + 1:]


def cifrar_oaep(chave: ChavePublica, mensagem: bytes, rotulo: bytes = b"") -> bytes:
    """RSAES-OAEP-ENCRYPT: retorna o ciphertext com k bytes."""
    em = oaep_codificar(mensagem, chave.k, rotulo)
    c = rsaep(chave, os2ip(em))
    return i2osp(c, chave.k)


def decifrar_oaep(chave: ChavePrivada, cifra: bytes, rotulo: bytes = b"") -> bytes:
    """RSAES-OAEP-DECRYPT: valida len(cifra) == k e c < n; ErroDecifracao em falha."""
    if len(cifra) != chave.k:
        raise ErroDecifracao(_FALHA)
    c = os2ip(cifra)
    if c >= chave.n:
        raise ErroDecifracao(_FALHA)
    em = i2osp(rsadp(chave, c), chave.k)
    return oaep_decodificar(em, chave.k, rotulo)
