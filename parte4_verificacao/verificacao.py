"""Verificação de arquivos assinados com RSA-PSS e chave pública."""

from dataclasses import dataclass

from parte1_chaves.chaves import ChavePublica


@dataclass(frozen=True)
class ResultadoVerificacao:
    valido: bool
    mensagem: str  # ex.: "ASSINATURA VÁLIDA: arquivo íntegro" / "ASSINATURA INVÁLIDA"


def verificar_arquivo(chave: ChavePublica, caminho_arquivo: str,
                      texto_assinatura: str) -> ResultadoVerificacao:
    """Faz o parsing da estrutura assinada, recalcula o SHA3-256 do arquivo
    e verifica com RSASSA-PSS-VERIFY.

    Nunca propaga exceção por entrada adulterada: formato inválido, tamanho
    de assinatura errado ou falha criptográfica viram ResultadoVerificacao
    com valido=False e mensagem clara.
    """
    raise NotImplementedError("TODO Pessoa D")
