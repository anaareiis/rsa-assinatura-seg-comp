"""Verificação de arquivos assinados com RSA-PSS e chave pública."""

from dataclasses import dataclass
from comum.erros import ErroFormato
from comum.hash_sha3 import digest_arquivo
from parte1_chaves.chaves import ChavePublica
from parte3_pss.pss import verificar_digest
from parte4_verificacao.formato_assinatura import parse_assinatura


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
    mensagem_sucesso = "ASSINATURA VÁLIDA: o arquivo é íntegro e foi assinado pela chave informada."
    mensagem_falha = "ASSINATURA INVÁLIDA: o arquivo foi alterado, a assinatura foi adulterada ou a chave não corresponde."

    try:
        # 1. Parsing da estrutura assinada e validação de formato
        estrutura = parse_assinatura(texto_assinatura)

        # 2. Recalcula o SHA3-256 do arquivo
        m_hash = digest_arquivo(caminho_arquivo)

        # 3. Executa a verificação (RSASSA-PSS-VERIFY) 
        # (retorna bool sem lançar exceção, conforme implementado no pss_2.py)
        assinatura_ok = verificar_digest(
            chave,
            m_hash,
            estrutura.assinatura,
            estrutura.tamanho_salt
        )

        if assinatura_ok:
            return ResultadoVerificacao(valido=True, mensagem=mensagem_sucesso)
        else:
            return ResultadoVerificacao(valido=False, mensagem=mensagem_falha)

    except (ErroFormato, FileNotFoundError, OSError):
        # Qualquer falha de leitura, arquivo não encontrado,
        # formato do .sig destruído/modificado, deve retornar erro amigável.
        return ResultadoVerificacao(valido=False, mensagem=mensagem_falha)