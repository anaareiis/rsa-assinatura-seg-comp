# Parte V — Análise de segurança

Análise de segurança pedida na Parte V do roteiro. A versão final está na
Seção II-E do relatório (`relatorio/relatorio.pdf`) e nos slides da Parte V.

Responsável: **Pessoa D** — Pedro de Paula Campos (231036050).

## 1. Por que RSA sem padding seguro (textbook RSA) não deve ser usado

- **Determinístico:** a mesma mensagem gera sempre o mesmo ciphertext, o que
  permite ataques de dicionário e impede segurança semântica (IND-CPA).
- **Maleável/homomórfico:** `E(m1)·E(m2) = E(m1·m2) mod n`; um atacante
  altera o ciphertext de forma previsível. Na assinatura, permite
  falsificação existencial (`s1·s2` assina `m1·m2`) e ataques de mensagem
  escolhida (blinding).
- **Mensagens pequenas:** com `e = 3` e `m^e < n`, basta tirar a raiz cúbica
  inteira; ataque de Håstad em broadcast para vários destinatários.
- **"Cifrar o hash"** também é insuficiente: ainda determinístico e sem prova
  de segurança; esquemas ad hoc sofreram ataques como o de Bleichenbacher
  (2006) contra verificações de padding frouxas.

## 2. Papel do OAEP na cifragem

- Adiciona **aleatoriedade** (seed) → cifragem probabilística.
- Estrutura de rede de Feistel de duas rodadas com MGF1 → "tudo ou nada":
  alterar qualquer bit do ciphertext destrói a estrutura, e a decodificação
  detecta (`lHash`, byte `0x01`).
- Segurança IND-CCA2 no modelo de oráculo aleatório (Bellare–Rogaway 1994;
  Fujisaki et al. 2001).
- Cuidado de implementação: erro único na decodificação (Manger, 2001).

## 3. Papel do PSS na assinatura

- Salt aleatório → assinatura probabilística; o mesmo documento gera
  assinaturas diferentes, todas válidas.
- MGF1 espalha o hash por todo o módulo; o trailer `0xbc` e o bit mais alto
  zerado impedem representantes fora de faixa.
- Prova de segurança **tight** (redução ao problema RSA) no modelo de
  oráculo aleatório, ao contrário do PKCS#1 v1.5.

## 4. RSA-PSS × Ed25519

| Aspecto | RSA-PSS (2048) | Ed25519 |
|---|---|---|
| Problema difícil | Fatoração / problema RSA | Log discreto em curva elíptica (Curve25519) |
| Segurança aproximada | ~112 bits | ~128 bits |
| Chave pública | 256 bytes | 32 bytes |
| Assinatura | 256 bytes | 64 bytes |
| Aleatoriedade na assinatura | Salt aleatório (depende de bom RNG) | Nonce determinístico derivado da chave e da mensagem |
| Velocidade | Verificação rápida, assinatura lenta | Assinatura e verificação rápidas |
| Complexidade de implementação | Padding, CRT, geração de primos | Aritmética de curva fixa, menos parâmetros |
| Padronização | RFC 8017, FIPS 186-5 | RFC 8032, FIPS 186-5 |

Ambos são quebrados por computadores quânticos (algoritmo de Shor);
alternativas pós-quânticas: ML-DSA (FIPS 204) e SLH-DSA (FIPS 205).
