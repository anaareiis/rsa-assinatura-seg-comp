# Parte II — Cifragem e decifragem RSA-OAEP

## Responsável

- **Pessoa B** — Ana Luísa Reis Nascente (211045688)

## Implementação

| Arquivo | Conteúdo |
|---|---|
| `mgf1.py` | MGF1 com SHA3-256 (RFC 8017, B.2.1) — também usada pela Parte III |
| `oaep.py` | Codificação/decodificação EME-OAEP e RSAES-OAEP encrypt/decrypt (RFC 8017, §7.1) |

Usa `comum.conversoes` (I2OSP/OS2IP, XOR), `comum.hash_sha3` e as
primitivas `rsaep`/`rsadp` da Parte I.

## Parâmetros

- Hash: SHA3-256 (`hLen = 32`); MGF: MGF1-SHA3-256; rótulo `L` padrão vazio.
- RSA-2048 → `k = 256` bytes → mensagem de até `k − 2·hLen − 2 = 190` bytes.
- Seed aleatória gerada com `secrets.token_bytes(hLen)`.

## Tratamento de erros

A decifragem lança **uma única** `ErroDecifracao("falha na decifração")`
para qualquer problema (tamanho do ciphertext, `c ≥ n`, byte inicial ≠ 0,
`lHash'` diferente, separador `0x01` ausente). Mensagens distintas
permitiriam um oráculo de padding (ataque de Manger, 2001).

Pelo mesmo motivo, `oaep_decodificar` percorre todo o bloco de padding
sem sair do laço ao encontrar o separador, compara o `lHash` com
`hmac.compare_digest` e testa todas as condições de uma vez só.

## Testes

```bash
python3 -m unittest parte2_oaep.testes.test_parte2 -v
python3 -m unittest parte2_oaep.testes.test_interoperabilidade_oaep -v
```

| Grupo | O que verifica |
|---|---|
| `TesteMGF1` | contador de 4 bytes, prefixo, limites de tamanho |
| `TesteCodificacaoOAEP` | EME-OAEP sem RSA: ida e volta, 190 bytes máx., qualquer byte alterado, rótulo, mensagem de erro única |
| `TesteOAEP` | RSAES-OAEP com chave de 2048 bits: ida e volta, cifragem probabilística, ciphertext adulterado, `c ≥ n`, chave errada |
| `TesteInteroperabilidadeOAEP` | cifra da pycryptodome decifrada por nós e vice-versa, inclusive com rótulo |
