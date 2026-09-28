"""Estrutura do arquivo de assinatura (.sig) — formato definido pelo grupo.

    -----BEGIN RSA-SEGCOMP SIGNATURE-----
    {"formato": "rsa-segcomp-assinatura-v1",
     "algoritmo": "RSASSA-PSS", "hash": "SHA3-256", "mgf": "MGF1-SHA3-256",
     "tamanho_salt": 32, "arquivo": "documento.txt",
     "assinatura": "<Base64>"}
    -----END RSA-SEGCOMP SIGNATURE-----

O parsing rejeita (ErroFormato) delimitadores ausentes, JSON inválido,
campos ausentes/extras, algoritmo/hash/mgf diferentes dos suportados e
Base64 inválido (usar base64.b64decode(..., validate=True)).
"""

import json
import base64
from dataclasses import dataclass
from comum.erros import ErroFormato

FORMATO = "rsa-segcomp-assinatura-v1"
_CABECALHO = "-----BEGIN RSA-SEGCOMP SIGNATURE-----"
_RODAPE = "-----END RSA-SEGCOMP SIGNATURE-----"


@dataclass(frozen=True)
class EstruturaAssinada:
    arquivo: str
    assinatura: bytes          # bytes já decodificados do Base64
    tamanho_salt: int = 32
    algoritmo: str = "RSASSA-PSS"
    hash: str = "SHA3-256"
    mgf: str = "MGF1-SHA3-256"


def serializar_assinatura(estrutura: EstruturaAssinada) -> str:
    """Transforma a estrutura na string formatada com cabeçalho e JSON."""
    assinatura_b64 = base64.b64encode(estrutura.assinatura).decode("ascii")
    
    corpo = {
        "formato": FORMATO,
        "algoritmo": estrutura.algoritmo,
        "hash": estrutura.hash,
        "mgf": estrutura.mgf,
        "tamanho_salt": estrutura.tamanho_salt,
        "arquivo": estrutura.arquivo,
        "assinatura": assinatura_b64
    }
    
    # O empacotamento mantém a quebra de linha após o cabeçalho e antes do rodapé
    return f"{_CABECALHO}\n{json.dumps(corpo)}\n{_RODAPE}\n"


def parse_assinatura(texto: str) -> EstruturaAssinada:
    """Extrai os dados da string; rejeita alterações com ErroFormato."""
    linhas = texto.strip().splitlines()
    
    # Valida delimitadores ausentes ou incorretos
    if len(linhas) < 3 or linhas[0].strip() != _CABECALHO or linhas[-1].strip() != _RODAPE:
        raise ErroFormato("Delimitadores ausentes ou incorretos.")

    # Valida JSON
    try:
        corpo = json.loads("\n".join(linhas[1:-1]))
    except json.JSONDecodeError as erro:
        raise ErroFormato("JSON inválido.") from erro

    if not isinstance(corpo, dict):
        raise ErroFormato("O corpo da assinatura deve ser um objeto JSON.")

    # Valida presença e correspondência de campos contra downgrade/confusão de algoritmo
    if corpo.get("formato") != FORMATO:
        raise ErroFormato("Formato incompatível ou ausente.")
    if corpo.get("algoritmo") != "RSASSA-PSS":
        raise ErroFormato("Algoritmo não suportado (exigido: RSASSA-PSS).")
    if corpo.get("hash") != "SHA3-256":
        raise ErroFormato("Hash não suportado (exigido: SHA3-256).")
    if corpo.get("mgf") != "MGF1-SHA3-256":
        raise ErroFormato("MGF não suportado (exigido: MGF1-SHA3-256).")

    # Extrai arquivo, salt e checa presença
    try:
        arquivo = str(corpo["arquivo"])
        tamanho_salt = int(corpo["tamanho_salt"])
        assinatura_texto = str(corpo["assinatura"])
    except (KeyError, ValueError) as erro:
        raise ErroFormato("Campos 'arquivo', 'tamanho_salt' ou 'assinatura' ausentes ou malformados.") from erro

    # Rejeita Base64 inválido com validate=True
    try:
        assinatura_bytes = base64.b64decode(assinatura_texto, validate=True)
    except Exception as erro:
        raise ErroFormato("Base64 da assinatura inválido.") from erro

    return EstruturaAssinada(
        arquivo=arquivo,
        assinatura=assinatura_bytes,
        tamanho_salt=tamanho_salt
    )