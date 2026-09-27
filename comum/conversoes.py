"""Primitivas de conversão da RFC 8017, Seção 4 (I2OSP e OS2IP)."""

from comum.erros import ErroParametro


def i2osp(x: int, tamanho: int) -> bytes:
    """Converte um inteiro não negativo em uma string de `tamanho` octetos (big-endian)."""
    if x < 0 or x >= 256 ** tamanho:
        raise ErroParametro("inteiro grande demais")
    return x.to_bytes(tamanho, "big")


def os2ip(octetos: bytes) -> int:
    """Converte uma string de octetos (big-endian) em inteiro não negativo."""
    return int.from_bytes(octetos, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte de duas sequências de mesmo tamanho."""
    if len(a) != len(b):
        raise ValueError("sequências de tamanhos diferentes")
    return bytes(x ^ y for x, y in zip(a, b))
