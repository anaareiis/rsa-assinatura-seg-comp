# Sistema de Assinatura Digital e Verificação Segura de Arquivos

Trabalho de Implementação 2 da disciplina CIC0201 - Segurança Computacional,
ministrada pela Profa. Priscila Solis na Universidade de Brasília.
Entrega: **29/09/2026**.

Implementação própria, em Python, de RSA com geração de chaves por
Miller-Rabin, cifragem **RSA-OAEP** e assinatura **RSA-PSS**, ambas com
SHA3-256 e MGF1, seguindo a RFC 8017 (PKCS #1 v2.2). O RSA é usado de duas
formas distintas: para **cifrar** mensagens curtas (OAEP, chave pública
cifra e chave privada decifra) e para **assinar** arquivos (PSS, chave
privada assina e chave pública verifica).

## Equipe e divisão do trabalho

- **Pessoa A - Gabriel de Sousa (211056000):** Parte I — aritmética modular,
  Miller-Rabin, geração do par de chaves, primitivas RSA e formato das chaves.
- **Pessoa B - Ana Luísa Reis Nascente (211045688):** Parte II — MGF1 e
  RSA-OAEP (codificação, decodificação e detecção de adulteração).
- **Pessoa C - Marina Pimentel Moreno (222014071):** Parte III — EMSA-PSS,
  RSASSA-PSS e assinatura de arquivos em Base64.
- **Pessoa D - Pedro de Paula Campos (231036050):** Partes IV e V — formato
  e parsing da estrutura assinada, verificação, testes de adulteração e
  análise de segurança.

Relatório: Gabriel e Pedro. Slides: Ana. Revisão final: todo o grupo.

## Entregáveis

| Item | Onde está |
|---|---|
| Código-fonte | `comum/`, `parte1_chaves/` a `parte4_verificacao/` e `rsa_cli.py` |
| Casos de teste | `parteN_*/testes/`: 52 testes com `unittest` |
| Demonstração | `exemplos/demo.sh` |
| Análise de segurança (Parte V) | `parte5_analise/README.md` e Seção II-E do relatório |
| Relatório (IEEE, 5 páginas) | `relatorio/relatorio.pdf` |
| Slides | `slide/Apresentacao_RSA_UNB.pdf` |

## Estrutura do projeto

```text
rsa-assinatura-seg-comp/
|-- comum/                # I2OSP/OS2IP, XOR, SHA3-256 e exceções
|-- parte1_chaves/        # aritmética modular, Miller-Rabin, chaves e primitivas RSA
|-- parte2_oaep/          # MGF1 e RSA-OAEP
|-- parte3_pss/           # RSA-PSS e assinatura de arquivos em Base64
|-- parte4_verificacao/   # formato .sig, verificação e testes de adulteração
|-- parte5_analise/       # análise de segurança
|-- exemplos/             # documento de exemplo e demo.sh
|-- relatorio/            # relatório em LaTeX, figuras e script das figuras de testes
|-- slide/                # apresentação em Beamer e PDF compilado
|-- rsa_cli.py            # CLI integrada
|-- requirements.txt      # bibliotecas opcionais, só para os testes de interoperabilidade
`-- README.md
```

Cada parte tem um `README.md` próprio com a implementação, os parâmetros e
as seções da RFC 8017 e da FIPS 186-5 correspondentes.

## Requisitos

- Python **3.9 ou superior**. A implementação usa só a biblioteca padrão.
- Opcional, só para os testes de interoperabilidade:
  `pip install -r requirements.txt` (`cryptography` e `pycryptodome`).
- Opcional, para recompilar o relatório e os slides: LaTeX com `latexmk`.

## Execução

Todos os comandos são executados a partir da raiz do projeto.

```bash
# Parte I: gera chaves/privada.pem e chaves/publica.pem (RSA-2048)
python3 rsa_cli.py gerar-chaves --saida chaves

# Parte II: cifra uma mensagem de até 190 bytes (saída em Base64) e decifra
python3 rsa_cli.py cifrar   --chave chaves/publica.pem "mensagem curta"
python3 rsa_cli.py decifrar --chave chaves/privada.pem "<ciphertext em Base64>"

# Parte III: assina um arquivo e grava exemplos/documento.txt.sig
python3 rsa_cli.py assinar --chave chaves/privada.pem exemplos/documento.txt

# Parte IV: verifica o arquivo com a assinatura e a chave pública
python3 rsa_cli.py verificar --chave chaves/publica.pem exemplos/documento.txt exemplos/documento.txt.sig
```

O comando `verificar` imprime uma destas duas mensagens:

```text
ASSINATURA VÁLIDA: o arquivo é íntegro e foi assinado pela chave informada.
ASSINATURA INVÁLIDA: o arquivo foi alterado, a assinatura foi adulterada ou a chave não corresponde.
```

Códigos de saída: `0` sucesso ou assinatura válida, `2` assinatura
inválida, `1` erro de entrada (arquivo inexistente, chave malformada,
ciphertext inválido etc.). Erros sempre aparecem como mensagem curta,
sem stack trace.

### Demonstração completa

```bash
bash exemplos/demo.sh
```

Gera um par de chaves, cifra e decifra com OAEP (incluindo um ciphertext
adulterado), assina `exemplos/documento.txt` com PSS e executa os três
testes de adulteração do roteiro: (a) um byte do arquivo, (b) um byte da
assinatura e (c) outra chave pública. Os arquivos gerados ficam em
`exemplos/saida/`, que não é versionada.

## Testes

```bash
python3 -m unittest discover -p "test_*.py" -v
```

| Parte | Testes | O que cobrem |
|---|---|---|
| I | 11 | aritmética modular, primos e números de Carmichael, parâmetros da chave, formato das chaves |
| II | 20 + 3 | MGF1, OAEP com e sem RSA, limite de 190 bytes, adulteração, erro único; interoperabilidade com `pycryptodome` |
| III | 10 | EMSA-PSS, assinatura probabilística, "não é cifrar o hash", Base64 |
| IV | 5 + 3 | adulteração (a), (b), (c) e `.sig` malformado; interoperabilidade com `cryptography` |

Com as bibliotecas opcionais instaladas, são **52 testes, todos aprovados**.
Se uma delas faltar, os 3 testes de interoperabilidade que dependem dela
são pulados automaticamente e os demais continuam rodando. As bibliotecas servem **somente para
conferir** a saída da nossa implementação, nos dois sentidos (restrição 3
do roteiro). O OAEP é conferido com a `pycryptodome` porque a
`cryptography` não aceita SHA3-256 no OAEP.

## Formatos de arquivo

Os formatos foram definidos pelo grupo e usam JSON entre delimitadores no
estilo PEM:

- **Chaves** (`rsa-segcomp-v1`): inteiros em hexadecimal; a chave privada
  inclui os parâmetros CRT. Ver `parte1_chaves/README.md`.
- **Assinatura** (`rsa-segcomp-assinatura-v1`): algoritmo, hash, MGF,
  tamanho do salt, nome do arquivo e assinatura em Base64. Ver
  `parte4_verificacao/README.md`.

A importação valida todos os campos e rejeita arquivos malformados com
`ErroFormato`.

## Restrições respeitadas

- A implementação usa apenas `hashlib` (SHA3-256), `secrets`, `base64` e
  `json` da biblioteca padrão.
- Geração de chaves, Miller-Rabin, aritmética modular, operações RSA, OAEP,
  MGF1 e PSS são implementações próprias; não se usa `pow(a, -1, m)`,
  OpenSSL nem bibliotecas equivalentes.
- A assinatura não é "cifragem do hash": o digest passa pela codificação
  probabilística EMSA-PSS antes da primitiva RSA.
- Entradas inválidas e falhas de verificação geram mensagens controladas.
  A decifragem OAEP dá o mesmo erro para qualquer falha, para não virar um
  oráculo de padding.

## Relatório e slides

O relatório segue o formato IEEE de conferência exigido em
`formatorelatorios.pdf`. O PDF compilado já está versionado.

```bash
cd relatorio && latexmk -pdf relatorio.tex
cd slide/apresentacao_rsa && latexmk -pdf apresentacao_rsa.tex
```

As figuras de testes do relatório são geradas a partir da suíte real:

```bash
python3 relatorio/scripts/gerar_figuras_testes.py
```

## Fluxo de trabalho com git

Uma branch por parte (`feat/part1-rsa-keygen`, `feat/part2-oaep`,
`feat/part3-rsa-pss`, `part4-verificacao`), além de `relatorio` e
`slides`, cada uma integrada à `main` por pull request depois que os
testes passaram.

## Referências

- NIST FIPS 202 — SHA-3 Standard.
- NIST SP 800-56B Rev. 2 — criptografia baseada em fatoração inteira.
- NIST FIPS 186-5 — Digital Signature Standard.
- RFC 8017 — PKCS #1: RSA Cryptography Specifications v2.2.
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA).
