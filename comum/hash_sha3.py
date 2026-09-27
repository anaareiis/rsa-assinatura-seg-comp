"""SHA3-256 (FIPS 202) via hashlib — uso de biblioteca permitido pelo roteiro."""

import hashlib

H_LEN = 32  # tamanho do digest em bytes
_BLOCO_LEITURA = 64 * 1024


def sha3_256(dados: bytes) -> bytes:
    return hashlib.sha3_256(dados).digest()


def digest_arquivo(caminho: str) -> bytes:
    """Calcula o SHA3-256 de um arquivo lendo-o em blocos."""
    h = hashlib.sha3_256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(_BLOCO_LEITURA), b""):
            h.update(bloco)
    return h.digest()
