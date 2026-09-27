# Parte I — Geração e gerenciamento de chaves RSA

## Responsável

- **Pessoa A** — Gabriel de Sousa (211056000)

## O que implementar

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
- `e = 65537`; `d = e⁻¹ mod λ(n)`, com `λ(n) = mmc(p−1, q−1)`.
- Parâmetros CRT: `dP = d mod (p−1)`, `dQ = d mod (q−1)`, `qInv = q⁻¹ mod p`.
- Miller-Rabin com 40 rodadas (erro ≤ 2⁻⁸⁰).

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
