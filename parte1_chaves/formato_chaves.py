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

from parte1_chaves.chaves import ChavePrivada, ChavePublica


def serializar_chave_publica(chave: ChavePublica) -> str:
    raise NotImplementedError("TODO Pessoa A")


def serializar_chave_privada(chave: ChavePrivada) -> str:
    raise NotImplementedError("TODO Pessoa A")


def carregar_chave_publica(texto: str) -> ChavePublica:
    raise NotImplementedError("TODO Pessoa A")


def carregar_chave_privada(texto: str) -> ChavePrivada:
    raise NotImplementedError("TODO Pessoa A")


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
