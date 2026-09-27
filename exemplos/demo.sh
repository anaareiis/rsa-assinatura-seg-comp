#!/usr/bin/env bash
# Demonstração completa para a apresentação: gera chaves, cifra/decifra com
# OAEP, assina com PSS e mostra os três testes de adulteração da Parte IV.
# Uso (a partir da raiz do projeto): bash exemplos/demo.sh
set -u
cd "$(dirname "$0")/.."
SAIDA=exemplos/saida
rm -rf "$SAIDA" && mkdir -p "$SAIDA"
CLI="python3 rsa_cli.py"

echo "== 1. Geração de chaves RSA-2048 (Miller-Rabin) =="
$CLI gerar-chaves --saida "$SAIDA/chaves"

echo; echo "== 2. RSA-OAEP =="
CIFRA=$($CLI cifrar --chave "$SAIDA/chaves/publica.pem" "senha: correct horse battery staple")
echo "Ciphertext (Base64): ${CIFRA:0:60}..."
$CLI decifrar --chave "$SAIDA/chaves/privada.pem" "$CIFRA"
echo "Ciphertext adulterado:"
ADULT=$(python3 -c "import base64,sys; c=bytearray(base64.b64decode(sys.argv[1])); c[100]^=1; print(base64.b64encode(c).decode())" "$CIFRA")
$CLI decifrar --chave "$SAIDA/chaves/privada.pem" "$ADULT"

echo; echo "== 3. Assinatura RSA-PSS =="
cp exemplos/documento.txt "$SAIDA/documento.txt"
$CLI assinar --chave "$SAIDA/chaves/privada.pem" "$SAIDA/documento.txt"
cat "$SAIDA/documento.txt.sig"

echo; echo "== 4. Verificação =="
echo "-- original:"
$CLI verificar --chave "$SAIDA/chaves/publica.pem" "$SAIDA/documento.txt" "$SAIDA/documento.txt.sig"

echo "-- (a) um byte do arquivo alterado (1.000 -> 9.000):"
sed 's/1\.000/9.000/' "$SAIDA/documento.txt" > "$SAIDA/documento_a.txt"
$CLI verificar --chave "$SAIDA/chaves/publica.pem" "$SAIDA/documento_a.txt" "$SAIDA/documento.txt.sig"

echo "-- (b) um byte da assinatura alterado:"
python3 - "$SAIDA" <<'PY'
import base64, json, sys
d = sys.argv[1]
linhas = open(f"{d}/documento.txt.sig", encoding="utf-8").read().splitlines()
corpo = json.loads("".join(linhas[1:-1]))
s = bytearray(base64.b64decode(corpo["assinatura"])); s[10] ^= 1
corpo["assinatura"] = base64.b64encode(s).decode()
open(f"{d}/documento_b.sig", "w", encoding="utf-8").write("\n".join([linhas[0], json.dumps(corpo), linhas[-1]]))
PY
$CLI verificar --chave "$SAIDA/chaves/publica.pem" "$SAIDA/documento.txt" "$SAIDA/documento_b.sig"

echo "-- (c) outra chave pública:"
$CLI gerar-chaves --saida "$SAIDA/outra" > /dev/null
$CLI verificar --chave "$SAIDA/outra/publica.pem" "$SAIDA/documento.txt" "$SAIDA/documento.txt.sig"
