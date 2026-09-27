"""Teste probabilístico de primalidade de Miller-Rabin e geração de primos.

Referências: FIPS 186-5, Apêndice B.3; NIST SP 800-56B Rev. 2.
Aleatoriedade: usar o módulo `secrets` (CSPRNG), nunca `random`.
"""

import secrets

from parte1_chaves.aritmetica_modular import exp_modular

_LIMITE_CRIVO = 1000  # FIPS 186-5 Apêndice B.3: divisão por tentativa opcional com
# limite L entre 10^3 e 10^5 antes do teste probabilístico; usamos o piso do
# intervalo (10^3), que já descarta a maioria dos compostos sem exp_modular.


def _crivo_eratostenes(limite: int) -> tuple[int, ...]:
    """Primos menores que `limite`, usados para descarte rápido de candidatos."""
    eh_primo = [True] * limite
    eh_primo[0:2] = [False, False]
    for numero in range(2, int(limite ** 0.5) + 1):
        if eh_primo[numero]:
            for multiplo in range(numero * numero, limite, numero):
                eh_primo[multiplo] = False
    return tuple(numero for numero, primo in enumerate(eh_primo) if primo)


_PRIMOS_PEQUENOS = _crivo_eratostenes(_LIMITE_CRIVO)

# FIPS 186-5, Apêndice B.3, Tabela B.1 ("Minimum number of rounds of M-R
# testing when generating primes for use in RSA Digital Signatures"),
# coluna "Error probability = 2^-100": rodadas mínimas de Miller-Rabin por
# tamanho (em bits) do primo p/q, para os três tamanhos de módulo RSA que a
# tabela cobre (nlen = 2048, 3072 e 4096 bits). Ver docstring de
# `rodadas_recomendadas` para a justificativa e o intervalo de validade.
_RODADAS_TABELA_B1_ERRO_2_100 = {
    1024: 4,  # nlen = 2048
    1536: 3,  # nlen = 3072
    2048: 2,  # nlen = 4096
}
_ERRO_ALVO_LOG2_PADRAO = 100  # FIPS 186-5 Apêndice C.2: "acceptable for many applications"


def rodadas_recomendadas(bits: int, erro_alvo_log2: int = _ERRO_ALVO_LOG2_PADRAO) -> int:
    """Rodadas mínimas de Miller-Rabin para gerar um primo de `bits` bits
    com probabilidade de erro <= 2^-erro_alvo_log2.

    Duas fontes, ambas da FIPS 186-5:

    1. Para os tamanhos de primo que a Tabela B.1 (Apêndice B.3) cobre
       (1024/1536/2048 bits, usados nos módulos RSA de 2048/3072/4096 bits)
       com o alvo padrão 2^-100, usa o valor tabelado. Esses valores vêm da
       análise de caso médio de Damgård, Landrock e Pomerance (1993): sobre
       candidatos ímpares aleatórios de `bits` bits que já sobreviveram a
       `t` rodadas, a fração que ainda é composta cai muito mais rápido que
       4^-t — por isso bastam só 2 a 4 rodadas em vez de dezenas.
    2. Para qualquer outro tamanho (ou outro erro-alvo), usa o teorema
       clássico de Miller-Rabin (Rabin, 1980; Monier, 1980): um COMPOSTO
       FIXO sobrevive a t rodadas com probabilidade <= 4^-t, para qualquer n
       e qualquer t — sem depender de n ter sido escolhido ao acaso. Isso
       sempre vale, então t = ceil(erro_alvo_log2 / 2) rodadas bastam.

    A divisão por tentativa feita em `eh_provavel_primo` antes do
    Miller-Rabin só remove compostos (nunca remove primos), então ela só
    pode diminuir a probabilidade real de erro abaixo da tabelada — os
    valores continuam sendo um limite superior seguro mesmo com esse filtro.
    """
    if erro_alvo_log2 == _ERRO_ALVO_LOG2_PADRAO and bits in _RODADAS_TABELA_B1_ERRO_2_100:
        return _RODADAS_TABELA_B1_ERRO_2_100[bits]
    return -(-erro_alvo_log2 // 2)  # ceil(erro_alvo_log2 / 2), sem depender de float


def eh_provavel_primo(n: int, rodadas: int = 40) -> bool:
    """Retorna True se `n` passa em `rodadas` iterações de Miller-Rabin.

    Probabilidade de erro <= 4^-rodadas. Trata n < 2, pequenos primos e
    fatores pequenos por divisão direta antes do laço principal, o que
    evita exponenciações modulares caras para a maioria dos compostos.
    """
    if n < 2:
        return False
    for primo in _PRIMOS_PEQUENOS:
        if n == primo:
            return True
        if n % primo == 0:
            return False

    d, r = _decompor_em_impar_e_potencia_de_dois(n - 1)
    for _ in range(rodadas):
        testemunha = secrets.randbelow(n - 3) + 2  # testemunha em [2, n-2]
        if not _testemunha_atesta_primalidade(n, d, r, testemunha):
            return False
    return True


def _decompor_em_impar_e_potencia_de_dois(m: int) -> tuple[int, int]:
    """Escreve m = d * 2^r com d ímpar."""
    r = 0
    d = m
    while d % 2 == 0:
        d //= 2
        r += 1
    return d, r


def _testemunha_atesta_primalidade(n: int, d: int, r: int, testemunha: int) -> bool:
    """True se `testemunha` não prova que `n` é composto (uma rodada de Miller-Rabin)."""
    x = exp_modular(testemunha, d, n)
    if x == 1 or x == n - 1:
        return True

    for _ in range(r - 1):
        x = exp_modular(x, 2, n)
        if x == n - 1:
            return True
    return False


def gerar_primo_provavel(bits: int) -> int:
    """Gera um primo provável com exatamente `bits` bits.

    Força o bit mais significativo e o segundo antes de testar, o que
    garante p >= 1.5 * 2^(bits-1) — mais forte que o piso exigido pela FIPS
    186-5 Apêndice A.1.1 critério 2(b)/(c), p >= sqrt(2) * 2^(bits-1)
    (~1.414 * 2^(bits-1)) — e o bit menos significativo (ímpar).

    Usa `rodadas_recomendadas(bits)` em vez de um número fixo de rodadas:
    o cenário aqui é exatamente o da FIPS 186-5 Apêndice C.2 ("Generating
    Primes for RSA Signatures"), então aproveitamos a tabela otimizada por
    tamanho em vez do limite de pior caso genérico usado por
    `eh_provavel_primo` como padrão.
    """
    if bits < 2:
        raise ValueError("bits deve ser >= 2")

    rodadas = rodadas_recomendadas(bits)
    bit_mais_significativo = 1 << (bits - 1)
    segundo_bit = 1 << (bits - 2)
    while True:
        candidato = secrets.randbits(bits) | bit_mais_significativo | segundo_bit | 1
        if eh_provavel_primo(candidato, rodadas):
            return candidato
