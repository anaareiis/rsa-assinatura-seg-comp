"""Exceções compartilhadas entre as partes.

As mensagens são propositalmente genéricas: na decifração OAEP, por exemplo,
não se deve revelar *qual* verificação do padding falhou (ataque de Manger).
"""


class ErroRSA(Exception):
    """Classe base de todos os erros do projeto."""


class ErroParametro(ErroRSA):
    """Entrada inválida (tamanho de chave, mensagem longa demais etc.)."""


class ErroDecifracao(ErroRSA):
    """Falha ao decifrar: padding inválido ou ciphertext adulterado."""


class ErroFormato(ErroRSA):
    """Arquivo de chave ou de assinatura malformado."""
