"""RSAES-OAEP (RFC 8017, Seção 7.1) com SHA3-256 e MGF1-SHA3-256.

Tamanho máximo da mensagem: k - 2*H_LEN - 2 bytes (190 bytes para RSA-2048).
"""

from parte1_chaves.chaves import ChavePrivada, ChavePublica


def oaep_codificar(mensagem: bytes, k: int, rotulo: bytes = b"") -> bytes:
    """EME-OAEP encoding: EM = 0x00 || maskedSeed || maskedDB (k bytes).

    DB = lHash || PS || 0x01 || M; seed aleatória de H_LEN bytes (secrets).
    """
    raise NotImplementedError("TODO Pessoa B")


def oaep_decodificar(em: bytes, k: int, rotulo: bytes = b"") -> bytes:
    """EME-OAEP decoding. Lança ErroDecifracao com mensagem ÚNICA para
    qualquer falha (Y != 0, lHash diferente, separador 0x01 ausente),
    sem revelar qual verificação falhou.
    """
    raise NotImplementedError("TODO Pessoa B")


def cifrar_oaep(chave: ChavePublica, mensagem: bytes, rotulo: bytes = b"") -> bytes:
    """RSAES-OAEP-ENCRYPT: retorna o ciphertext com k bytes."""
    raise NotImplementedError("TODO Pessoa B")


def decifrar_oaep(chave: ChavePrivada, cifra: bytes, rotulo: bytes = b"") -> bytes:
    """RSAES-OAEP-DECRYPT: valida len(cifra) == k e c < n; ErroDecifracao em falha."""
    raise NotImplementedError("TODO Pessoa B")
