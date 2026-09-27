# Parte IV — Verificação e testes de integridade

## Responsável

- **Pessoa D** — Pedro de Paula Campos (231036050), também responsável pela
  integração (CLI), análise de segurança, relatório e slides.

## O que implementar

| Arquivo | Conteúdo |
|---|---|
| `formato_assinatura.py` | Serialização e parsing da estrutura assinada (`.sig`) |
| `verificacao.py` | Parsing + SHA3-256 + RSASSA-PSS-VERIFY → resultado claro |
| `testes/test_adulteracao.py` | Casos (a) byte do arquivo, (b) byte da assinatura, (c) chave pública |
| `testes/test_interoperabilidade.py` | Conferência opcional com a biblioteca `cryptography` |

## Formato da estrutura assinada (`rsa-segcomp-assinatura-v1`)

```text
-----BEGIN RSA-SEGCOMP SIGNATURE-----
{"formato": "rsa-segcomp-assinatura-v1", "algoritmo": "RSASSA-PSS",
 "hash": "SHA3-256", "mgf": "MGF1-SHA3-256", "tamanho_salt": 32,
 "arquivo": "documento.txt", "assinatura": "<Base64 de k bytes>"}
-----END RSA-SEGCOMP SIGNATURE-----
```

Os metadados de algoritmo são conferidos contra valores fixos: o
verificador **não** aceita que o arquivo escolha outro hash ou salt
(evita ataques de downgrade/confusão de algoritmo).

## Saída esperada

```text
$ python3 rsa_cli.py verificar --chave pub.pem documento.txt documento.txt.sig
ASSINATURA VÁLIDA: o arquivo é íntegro e foi assinado pela chave informada.

$ python3 rsa_cli.py verificar --chave pub.pem documento_alterado.txt documento.txt.sig
ASSINATURA INVÁLIDA: o arquivo foi alterado, a assinatura foi adulterada ou a chave não corresponde.
```

## Testes

```bash
python3 -m unittest parte4_verificacao.testes.test_adulteracao -v
python3 -m unittest parte4_verificacao.testes.test_interoperabilidade -v
```
