# Parte III — Assinatura digital RSA-PSS

## Responsável

- **Pessoa C** — Marina Pimentel Moreno (222014071)

## O que implementar

| Arquivo | Conteúdo |
|---|---|
| `pss.py` | EMSA-PSS encode/verify (RFC 8017, §9.1) e RSASSA-PSS sign/verify (§8.1) |
| `assinatura.py` | SHA3-256 do arquivo → PSS → Base64 (já integrado; depende de `pss.py`) |

Reutilizar `parte2_oaep.mgf1.mgf1`, `comum.conversoes` e as primitivas
`rsasp1`/`rsavp1` da Parte I.

## Parâmetros

- Hash: SHA3-256; MGF: MGF1-SHA3-256; salt de 32 bytes (`sLen = hLen`) via `secrets`.
- `emBits = modBits − 1` (2047 para RSA-2048), `emLen = 256`, trailer `0xbc`.

## Por que não é "cifragem do hash"

A abordagem simplificada `s = H(m)^d mod n` é determinística e herda a
maleabilidade do RSA textbook. O PSS mistura um salt aleatório, espalha
o resultado por todo o módulo com MGF1 e tem prova de segurança no modelo
de oráculo aleatório (Bellare–Rogaway, 1996). Há um teste
(`test_nao_e_cifragem_do_hash`) que garante isso.

## Testes

```bash
python3 -m unittest parte3_pss.testes.test_parte3 -v
```
