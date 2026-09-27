"""Interface de linha de comando integrada do sistema de assinatura digital.

Exemplos:
    python3 rsa_cli.py gerar-chaves --saida chaves/ --bits 2048
    python3 rsa_cli.py cifrar   --chave chaves/publica.pem "mensagem curta" > cifra.b64
    python3 rsa_cli.py decifrar --chave chaves/privada.pem "$(cat cifra.b64)"
    python3 rsa_cli.py assinar  --chave chaves/privada.pem documento.txt
    python3 rsa_cli.py verificar --chave chaves/publica.pem documento.txt documento.txt.sig
"""

import argparse
import base64
import binascii
import os
import sys

from comum.erros import ErroRSA
from parte1_chaves.chaves import gerar_par_chaves
from parte1_chaves.formato_chaves import exportar_chave, importar_chave_privada, importar_chave_publica
from parte2_oaep.oaep import cifrar_oaep, decifrar_oaep
from parte3_pss.assinatura import assinar_arquivo
from parte4_verificacao.formato_assinatura import EstruturaAssinada, serializar_assinatura
from parte4_verificacao.verificacao import verificar_arquivo


def cmd_gerar_chaves(args) -> int:
    os.makedirs(args.saida, exist_ok=True)
    privada = gerar_par_chaves(args.bits)
    exportar_chave(privada, os.path.join(args.saida, "privada.pem"))
    exportar_chave(privada.publica(), os.path.join(args.saida, "publica.pem"))
    print(f"Par de chaves RSA-{args.bits} gravado em {args.saida}/")
    return 0


def cmd_cifrar(args) -> int:
    cifra = cifrar_oaep(importar_chave_publica(args.chave), args.mensagem.encode("utf-8"))
    print(base64.b64encode(cifra).decode("ascii"))
    return 0


def cmd_decifrar(args) -> int:
    try:
        cifra = base64.b64decode(args.cifra, validate=True)
    except binascii.Error:
        print("Erro: ciphertext não está em Base64 válido.", file=sys.stderr)
        return 1
    print(decifrar_oaep(importar_chave_privada(args.chave), cifra).decode("utf-8", errors="replace"))
    return 0


def cmd_assinar(args) -> int:
    b64 = assinar_arquivo(importar_chave_privada(args.chave), args.arquivo)
    estrutura = EstruturaAssinada(os.path.basename(args.arquivo), base64.b64decode(b64))
    destino = args.saida or args.arquivo + ".sig"
    with open(destino, "w", encoding="utf-8") as f:
        f.write(serializar_assinatura(estrutura))
    print(f"Assinatura gravada em {destino}")
    return 0


def cmd_verificar(args) -> int:
    with open(args.assinatura, encoding="utf-8") as f:
        resultado = verificar_arquivo(importar_chave_publica(args.chave), args.arquivo, f.read())
    print(resultado.mensagem)
    return 0 if resultado.valido else 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="RSA-OAEP / RSA-PSS com SHA3-256 — CIC0201 Trabalho 2")
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("gerar-chaves", help="gera um par de chaves RSA")
    p.add_argument("--saida", default="chaves")
    p.add_argument("--bits", type=int, default=2048)
    p.set_defaults(func=cmd_gerar_chaves)

    p = sub.add_parser("cifrar", help="cifra uma mensagem curta com RSA-OAEP (saída em Base64)")
    p.add_argument("--chave", required=True, help="chave pública")
    p.add_argument("mensagem")
    p.set_defaults(func=cmd_cifrar)

    p = sub.add_parser("decifrar", help="decifra um ciphertext RSA-OAEP em Base64")
    p.add_argument("--chave", required=True, help="chave privada")
    p.add_argument("cifra")
    p.set_defaults(func=cmd_decifrar)

    p = sub.add_parser("assinar", help="assina um arquivo com RSA-PSS")
    p.add_argument("--chave", required=True, help="chave privada")
    p.add_argument("--saida", help="arquivo .sig (padrão: <arquivo>.sig)")
    p.add_argument("arquivo")
    p.set_defaults(func=cmd_assinar)

    p = sub.add_parser("verificar", help="verifica a assinatura RSA-PSS de um arquivo")
    p.add_argument("--chave", required=True, help="chave pública")
    p.add_argument("arquivo")
    p.add_argument("assinatura")
    p.set_defaults(func=cmd_verificar)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ErroRSA, ValueError, OSError) as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
