"""Assinatura de arquivos: SHA3-256 do arquivo -> RSA-PSS -> Base64."""

import base64

from comum.hash_sha3 import digest_arquivo
from parte1_chaves.chaves import ChavePrivada
from parte3_pss.pss import TAMANHO_SALT_PADRAO, assinar_digest


def assinar_arquivo(chave: ChavePrivada, caminho: str,
                    tamanho_salt: int = TAMANHO_SALT_PADRAO) -> str:
    """Retorna a assinatura RSA-PSS do arquivo codificada em Base64."""
    assinatura = assinar_digest(chave, digest_arquivo(caminho), tamanho_salt)
    return base64.b64encode(assinatura).decode("ascii")
