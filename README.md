# Sistema de Assinatura Digital e Verificação Segura de Arquivos

Trabalho de Implementação 2 da disciplina CIC0201 - Segurança Computacional,
ministrada pela Profa. Priscila Solis na Universidade de Brasília.
Entrega: **29/09/2026**.

Implementação própria, em Python, de RSA com geração de chaves por
Miller-Rabin, cifragem **RSA-OAEP** e assinatura **RSA-PSS**, ambas com
SHA3-256 e MGF1, seguindo a RFC 8017 (PKCS #1 v2.2).

## Equipe e divisão do trabalho

- **Pessoa A - Gabriel de Sousa (211056000):** Parte I — aritmética modular,
  Miller-Rabin, geração do par de chaves, primitivas RSA e formato das chaves.
- **Pessoa B - Ana Luísa Reis Nascente (211045688):** Parte II — MGF1 e
  RSA-OAEP (codificação, decodificação e detecção de adulteração).
- **Pessoa C - Marina Pimentel Moreno (222014071):** Parte III — EMSA-PSS,
  RSASSA-PSS e assinatura de arquivos em Base64.
- **Pessoa D - Pedro de Paula Campos (231036050):** Parte IV e V — formato
  e parsing da estrutura assinada, verificação, testes de adulteração e de
  interoperabilidade, CLI integrada, análise de segurança, relatório e slides.

## Estado da implementação

- [x] Estrutura do projeto, interfaces e testes-contrato
- [x] Utilitários comuns: I2OSP/OS2IP, XOR, SHA3-256 (`comum/`)
- [x] CLI integrada (`rsa_cli.py`) e roteiro de demonstração
- [ ] Parte I — chaves RSA e Miller-Rabin
- [ ] Parte II — RSA-OAEP e MGF1
- [ ] Parte III — RSA-PSS
- [ ] Parte IV — parsing e verificação
- [ ] Parte V — análise de segurança (rascunho em `parte5_analise/`)
- [ ] Relatório e slides

## Estrutura do projeto

```text
rsa-assinatura-seg-comp/
|-- comum/                # I2OSP/OS2IP, SHA3-256, exceções
|-- parte1_chaves/        # Miller-Rabin, geração e formato das chaves, primitivas RSA
|-- parte2_oaep/          # MGF1 e RSA-OAEP
|-- parte3_pss/           # RSA-PSS e assinatura de arquivos em Base64
|-- parte4_verificacao/   # parsing da assinatura, verificação, testes de adulteração
|-- parte5_analise/       # análise de segurança (texto)
|-- exemplos/             # documento de exemplo e demo.sh da apresentação
|-- relatorio/            # relatório técnico em LaTeX (IEEE)
|-- slide/                # apresentação em Beamer
|-- rsa_cli.py            # CLI integrada
`-- README.md
```

Cada parte tem um `README.md` com o que implementar, parâmetros e
referências da RFC 8017.

## Execução

Requer Python 3.9+ e nenhuma dependência para a implementação.

```bash
python3 rsa_cli.py gerar-chaves --saida chaves
python3 rsa_cli.py cifrar    --chave chaves/publica.pem "mensagem curta"
python3 rsa_cli.py decifrar  --chave chaves/privada.pem "<ciphertext Base64>"
python3 rsa_cli.py assinar   --chave chaves/privada.pem exemplos/documento.txt
python3 rsa_cli.py verificar --chave chaves/publica.pem exemplos/documento.txt exemplos/documento.txt.sig
```

Demonstração completa (chaves, OAEP, PSS e os três testes de adulteração):

```bash
bash exemplos/demo.sh
```

## Testes

```bash
python3 -m unittest discover -p "test_*.py" -v
```

O teste de interoperabilidade (`parte4_verificacao/testes/test_interoperabilidade.py`)
usa a biblioteca `cryptography` **somente para conferir** nossas saídas
(restrição 3 do roteiro) e é pulado se ela não estiver instalada:
`pip install -r requirements.txt`.

## Restrições respeitadas

- Bibliotecas usadas na implementação: apenas `hashlib` (SHA3-256), `secrets`,
  `base64` e `json` da biblioteca padrão.
- Geração de chaves, Miller-Rabin, aritmética modular, operações RSA, OAEP,
  MGF1 e PSS são implementações próprias.
- Entradas inválidas e falhas de verificação geram mensagens de erro
  controladas, sem stack trace e sem vazar detalhes do padding.

## Fluxo de trabalho com git

Como no Trabalho 1: uma branch por parte (`parte1-chaves`, `parte2-oaep`,
`parte3-pss`, `parte4-verificacao`), commits no padrão `feat:`, `test:`,
`docs:` e merge na `main` quando os testes da parte passarem.

## Relatório

Formato IEEE de conferência, até 8 páginas (ver `formatorelatorios.pdf`):

```bash
cd relatorio
latexmk -pdf relatorio.tex
```

## Referências

- NIST FIPS 202 — SHA-3 Standard.
- NIST SP 800-56B Rev. 2 — criptografia baseada em fatoração inteira.
- NIST FIPS 186-5 — Digital Signature Standard.
- RFC 8017 — PKCS #1: RSA Cryptography Specifications v2.2.
