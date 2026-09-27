"""Importação/exportação das chaves no formato definido pelo grupo.

Formato (documentado em parte1_chaves/README.md): JSON UTF-8 com inteiros
em hexadecimal, delimitado por cabeçalho/rodapé no estilo PEM, ex.:

    -----BEGIN RSA-SEGCOMP PUBLIC KEY-----
    {"formato": "rsa-segcomp-v1", "tipo": "publica", "bits": 2048,
     "n": "c3a1...", "e": "10001"}
    -----END RSA-SEGCOMP PUBLIC KEY-----

A importação deve validar todos os campos e lançar ErroFormato em caso de
arquivo malformado ou parâmetros inconsistentes (ex.: p*q != n).
"""

import json
import re

from comum.erros import ErroFormato
from parte1_chaves.aritmetica_modular import mmc
from parte1_chaves.chaves import ChavePrivada, ChavePublica

FORMATO = "rsa-segcomp-v1"

_CABECALHO_PUBLICA = "-----BEGIN RSA-SEGCOMP PUBLIC KEY-----"
_RODAPE_PUBLICA = "-----END RSA-SEGCOMP PUBLIC KEY-----"
_CABECALHO_PRIVADA = "-----BEGIN RSA-SEGCOMP PRIVATE KEY-----"
_RODAPE_PRIVADA = "-----END RSA-SEGCOMP PRIVATE KEY-----"

_CAMPOS_PUBLICA = ("n", "e")
_CAMPOS_PRIVADA = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")

_PADRAO_HEX = re.compile(r"^[0-9a-f]+$")


def serializar_chave_publica(chave: ChavePublica) -> str:
    corpo = {
        "formato": FORMATO,
        "tipo": "publica",
        "bits": chave.n.bit_length(),
        "n": _para_hex(chave.n),
        "e": _para_hex(chave.e),
    }
    return _empacotar(_CABECALHO_PUBLICA, corpo, _RODAPE_PUBLICA)


def serializar_chave_privada(chave: ChavePrivada) -> str:
    corpo = {
        "formato": FORMATO,
        "tipo": "privada",
        "bits": chave.n.bit_length(),
        "n": _para_hex(chave.n),
        "e": _para_hex(chave.e),
        "d": _para_hex(chave.d),
        "p": _para_hex(chave.p),
        "q": _para_hex(chave.q),
        "dp": _para_hex(chave.dp),
        "dq": _para_hex(chave.dq),
        "qinv": _para_hex(chave.qinv),
    }
    return _empacotar(_CABECALHO_PRIVADA, corpo, _RODAPE_PRIVADA)


def carregar_chave_publica(texto: str) -> ChavePublica:
    corpo = _desempacotar(texto, _CABECALHO_PUBLICA, _RODAPE_PUBLICA, "publica", _CAMPOS_PUBLICA)
    return ChavePublica(n=_de_hex(corpo, "n"), e=_de_hex(corpo, "e"))


def carregar_chave_privada(texto: str) -> ChavePrivada:
    corpo = _desempacotar(texto, _CABECALHO_PRIVADA, _RODAPE_PRIVADA, "privada", _CAMPOS_PRIVADA)
    valores = {campo: _de_hex(corpo, campo) for campo in _CAMPOS_PRIVADA}
    _validar_consistencia_privada(valores)
    return ChavePrivada(
        n=valores["n"], e=valores["e"], d=valores["d"],
        p=valores["p"], q=valores["q"],
        dp=valores["dp"], dq=valores["dq"], qinv=valores["qinv"],
    )


def exportar_chave(chave, caminho: str) -> None:
    """Grava a chave (pública ou privada) em arquivo."""
    if isinstance(chave, ChavePrivada):
        texto = serializar_chave_privada(chave)
    else:
        texto = serializar_chave_publica(chave)
    with open(caminho, "w", encoding="utf-8") as arquivo:
        arquivo.write(texto)


def importar_chave_publica(caminho: str) -> ChavePublica:
    with open(caminho, encoding="utf-8") as arquivo:
        return carregar_chave_publica(arquivo.read())


def importar_chave_privada(caminho: str) -> ChavePrivada:
    with open(caminho, encoding="utf-8") as arquivo:
        return carregar_chave_privada(arquivo.read())


def _para_hex(valor: int) -> str:
    return format(valor, "x")


def _de_hex(corpo: dict, campo: str) -> int:
    return int(corpo[campo], 16)


def _empacotar(cabecalho: str, corpo: dict, rodape: str) -> str:
    return f"{cabecalho}\n{json.dumps(corpo)}\n{rodape}\n"


def _desempacotar(texto: str, cabecalho: str, rodape: str,
                   tipo_esperado: str, campos_esperados: tuple) -> dict:
    """Valida delimitadores, JSON, campo 'formato'/'tipo' e presença/forma
    hexadecimal de cada campo esperado. Lança ErroFormato em qualquer falha.
    """
    linhas = texto.strip().splitlines()
    if len(linhas) < 3 or linhas[0].strip() != cabecalho or linhas[-1].strip() != rodape:
        raise ErroFormato("delimitadores ausentes ou incorretos")

    try:
        corpo = json.loads("\n".join(linhas[1:-1]))
    except json.JSONDecodeError as erro:
        raise ErroFormato("corpo da chave não é um JSON válido") from erro

    if not isinstance(corpo, dict):
        raise ErroFormato("corpo da chave deve ser um objeto JSON")
    if corpo.get("formato") != FORMATO:
        raise ErroFormato(f"campo 'formato' ausente ou diferente de {FORMATO!r}")
    if corpo.get("tipo") != tipo_esperado:
        raise ErroFormato(f"campo 'tipo' deveria ser {tipo_esperado!r}")
    if not isinstance(corpo.get("bits"), int) or corpo["bits"] <= 0:
        raise ErroFormato("campo 'bits' ausente ou inválido")

    for campo in campos_esperados:
        valor = corpo.get(campo)
        if not isinstance(valor, str) or not _PADRAO_HEX.match(valor):
            raise ErroFormato(f"campo {campo!r} ausente ou não é hexadecimal válido")

    return corpo


def _validar_consistencia_privada(valores: dict) -> None:
    """Verifica p*q == n e e*d ≡ 1 (mod lambda(n)) antes de aceitar a chave."""
    if valores["p"] * valores["q"] != valores["n"]:
        raise ErroFormato("inconsistência na chave: p * q != n")

    lambda_n = mmc(valores["p"] - 1, valores["q"] - 1)
    if (valores["e"] * valores["d"]) % lambda_n != 1:
        raise ErroFormato("inconsistência na chave: e * d não é congruente a 1 mod lambda(n)")
