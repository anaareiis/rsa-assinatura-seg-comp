# Parte I — Geração e gerenciamento de chaves RSA

## Responsável

- **Pessoa A** — Gabriel de Sousa (211056000)

## Implementação

| Arquivo | Conteúdo |
|---|---|
| `aritmetica_modular.py` | MDC estendido, inverso modular e exponenciação modular (square-and-multiply) |
| `miller_rabin.py` | Teste de Miller-Rabin e geração de primos prováveis com `secrets` |
| `chaves.py` | `ChavePublica`, `ChavePrivada` e `gerar_par_chaves(bits>=2048)` |
| `rsa_primitivas.py` | RSAEP, RSADP (com CRT), RSASP1, RSAVP1 — RFC 8017 §5 |
| `formato_chaves.py` | Importação/exportação no formato abaixo |

Não usar `pow(a, -1, m)`, `sympy`, `Crypto`, `cryptography`, OpenSSL ou
qualquer biblioteca que gere chaves ou teste primalidade.

## Parâmetros

- Módulo `n = p·q` com **2048 bits** (padrão); `p` e `q` com 1024 bits cada.
- `e = 65537` (F4, satisfaz 2¹⁶ < e < 2²⁵⁶ da FIPS 186-5 A.1.1 critério 1(b));
  `d = e⁻¹ mod λ(n)`, com `λ(n) = mmc(p−1, q−1)`.
- Parâmetros CRT: `dP = d mod (p−1)`, `dQ = d mod (q−1)`, `qInv = q⁻¹ mod p`.
- Miller-Rabin com número de rodadas escolhido por tamanho do primo, ver
  seção própria abaixo (não é mais um número fixo).
- `|p − q| > 2^(bits/2 − 100)` (FIPS 186-5 A.1.1, critério 2(d)) e bit mais
  significativo + segundo bit forçados em 1, garantindo `p, q ≥ 1.5·2^(bits/2−1)`
  (mais forte que o piso `√2·2^(bits/2−1)` exigido pelo critério 2(b)/(c)).
- Divisão por tentativa (trial division) com primos < 1000 antes do
  Miller-Rabin, dentro do intervalo `10³–10⁵` recomendado pela FIPS 186-5,
  Apêndice B.3 (nota sobre "trial division limit L").

## Política de rodadas do Miller-Rabin

`eh_provavel_primo(n, rodadas=40)` mantém **40 rodadas como padrão genérico**
(erro ≤ 4⁻⁴⁰ = 2⁻⁸⁰), para quando a função é chamada isoladamente sobre um
número qualquer, de proveniência ou tamanho desconhecidos — é o teste de
"é primo?" de propósito geral do módulo, e não deve presumir nada sobre `n`.

`gerar_primo_provavel(bits)`, porém, sabe exatamente o que está gerando: um
primo de `bits` bits para virar fator de um módulo RSA — o cenário descrito
na FIPS 186-5, Apêndice C.2 ("Generating Primes for RSA Signatures"). Para
esse caso ela chama `rodadas_recomendadas(bits)`, que decide o número de
rodadas assim:

1. **Tamanhos padronizados (1024, 1536 ou 2048 bits), erro-alvo 2⁻¹⁰⁰**
   → usa a **Tabela B.1** da FIPS 186-5 (Apêndice B.3) diretamente:

   | bits de p/q | nlen (módulo) | rodadas (Tabela B.1, coluna 2⁻¹⁰⁰) |
   |---|---|---|
   | 1024 | 2048 | 4 |
   | 1536 | 3072 | 3 |
   | 2048 | 4096 | 2 |

   Esses números parecem baixos demais à primeira vista, mas não são um
   limite de pior caso — vêm da análise de **caso médio** de Damgård,
   Landrock e Pomerance, *"Average case error estimates for the strong
   probable prime test"*, Math. Comp. 61(203), 1993: sobre candidatos
   ímpares de `k` bits escolhidos **ao acaso** (não por um adversário) que
   já sobreviveram a `t` rodadas com bases aleatórias, a fração que ainda é
   composta cai muito mais rápido que o limite genérico `4⁻ᵗ`, porque
   compostos que enganam várias bases de Miller-Rabin ao mesmo tempo são
   raríssimos entre números aleatórios. É exatamente esse resultado que a
   FIPS 186-5 tabula para os três tamanhos de módulo RSA padrão.

2. **Qualquer outro tamanho** (por exemplo os 512 bits usados em
   `test_primo_gerado_tem_tamanho_exato`) → cai no **teorema clássico de
   Miller-Rabin** (Rabin, 1980; Monier, 1980): para um composto **fixo**
   `n`, cada rodada com base aleatória o declara "provavelmente primo" com
   probabilidade ≤ 1/4, e as rodadas são independentes, logo `t` rodadas
   dão probabilidade ≤ `4⁻ᵗ` — **sem qualquer hipótese sobre `n` ter sido
   sorteado ao acaso**, o que faz esse limite valer sempre, para qualquer
   tamanho de bits. Daí `t = ⌈erro_alvo_log2 / 2⌉`; com o alvo padrão 2⁻¹⁰⁰,
   são 50 rodadas.

O alvo padrão `2⁻¹⁰⁰` (em vez de `2⁻⁸⁰`) é o mesmo que a FIPS 186-5 usa em
toda a Tabela B.1 e justifica no Apêndice C.2 como "aceitável para a
maioria das aplicações" — adotamos o mesmo valor para poder citar a tabela
sem reescalar nada.

A divisão por tentativa que `eh_provavel_primo` já faz antes do Miller-Rabin
só descarta números com fator pequeno — ela nunca descarta um primo. Isso
significa que ela só pode reduzir a fração de compostos que chegam à etapa
probabilística, então os limites acima (tabelados ou pelo teorema clássico)
continuam válidos como cota superior mesmo com esse filtro na frente.

Consequência prática: `gerar_par_chaves(2048)` gera primos de 1024 bits
usando só **4** rodadas de Miller-Rabin (não 40), o que é matematicamente
suficiente pela Tabela B.1 e visivelmente mais rápido — mas exige saber
explicar, na arguição, a diferença entre o limite de pior caso `4⁻ᵗ`
(sempre válido, usado como *fallback*) e o limite de caso médio da tabela
(mais forte, válido só quando o candidato é mesmo sorteado ao acaso, como
é o nosso caso).

## Formato das chaves (`rsa-segcomp-v1`)

JSON UTF-8 entre delimitadores no estilo PEM; inteiros em hexadecimal
minúsculo sem prefixo `0x`.

```text
-----BEGIN RSA-SEGCOMP PUBLIC KEY-----
{"formato": "rsa-segcomp-v1", "tipo": "publica", "bits": 2048, "n": "...", "e": "10001"}
-----END RSA-SEGCOMP PUBLIC KEY-----
```

```text
-----BEGIN RSA-SEGCOMP PRIVATE KEY-----
{"formato": "rsa-segcomp-v1", "tipo": "privada", "bits": 2048,
 "n": "...", "e": "...", "d": "...", "p": "...", "q": "...",
 "dp": "...", "dq": "...", "qinv": "..."}
-----END RSA-SEGCOMP PRIVATE KEY-----
```

Na importação, validar: delimitadores, campo `formato`, presença e tipo
hexadecimal de todos os campos, `p·q = n` e `e·d ≡ 1 (mod λ(n))` para a
chave privada. Qualquer falha lança `ErroFormato`.

## Testes

```bash
python3 -m unittest parte1_chaves.testes.test_parte1 -v
```
