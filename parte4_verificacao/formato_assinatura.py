"""Estrutura do arquivo de assinatura (.sig) — formato definido pelo grupo.

    -----BEGIN RSA-SEGCOMP SIGNATURE-----
    {"formato": "rsa-segcomp-assinatura-v1",
     "algoritmo": "RSASSA-PSS", "hash": "SHA3-256", "mgf": "MGF1-SHA3-256",
     "tamanho_salt": 32, "arquivo": "documento.txt",
     "assinatura": "<Base64>"}
    -----END RSA-SEGCOMP SIGNATURE-----

O parsing deve rejeitar (ErroFormato) delimitadores ausentes, JSON inválido,
campos ausentes/extras, algoritmo/hash/mgf diferentes dos suportados e
Base64 inválido (usar base64.b64decode(..., validate=True)).
"""

from dataclasses import dataclass

FORMATO = "rsa-segcomp-assinatura-v1"


@dataclass(frozen=True)
class EstruturaAssinada:
    arquivo: str
    assinatura: bytes          # bytes já decodificados do Base64
    tamanho_salt: int = 32
    algoritmo: str = "RSASSA-PSS"
    hash: str = "SHA3-256"
    mgf: str = "MGF1-SHA3-256"


def serializar_assinatura(estrutura: EstruturaAssinada) -> str:
    raise NotImplementedError("TODO Pessoa D")


def parse_assinatura(texto: str) -> EstruturaAssinada:
    raise NotImplementedError("TODO Pessoa D")
