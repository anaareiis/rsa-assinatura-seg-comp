"""Gera as figuras da suíte de testes usadas no relatório.

- figs/resultado_testes.pdf: testes aprovados por parte, separando os de
  interoperabilidade (bibliotecas usadas só para conferência).
- figs/05_testes.png: saída real de `python3 -m unittest discover -v`.

Uso (a partir da raiz do projeto, com cryptography e pycryptodome instaladas):
    python3 relatorio/scripts/gerar_figuras_testes.py
"""

import io
import os
import sys
import unittest

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIGS = os.path.join(RAIZ, "relatorio", "figs")

PARTES = [
    ("parte1_chaves", "Parte I\n(chaves)"),
    ("parte2_oaep", "Parte II\n(OAEP)"),
    ("parte3_pss", "Parte III\n(PSS)"),
    ("parte4_verificacao", "Parte IV\n(verificação)"),
]
VERDE, AZUL, CINZA = "#2e9e44", "#3b6fb6", "#c9ced6"


def rodar_suite():
    """Executa a suíte como `unittest discover -v`, mas sem docstrings,
    para que cada teste ocupe exatamente uma linha na saída."""
    os.chdir(RAIZ)
    sys.path.insert(0, RAIZ)
    suite = unittest.defaultTestLoader.discover(RAIZ, pattern="test_*.py")
    fluxo = io.StringIO()
    resultado = unittest.TextTestRunner(stream=fluxo, verbosity=2, descriptions=False).run(suite)
    return fluxo.getvalue(), 0 if resultado.wasSuccessful() else 1


def contar_por_parte(saida: str):
    contagem = {pacote: {"funcional": 0, "interop": 0, "pulado": 0} for pacote, _ in PARTES}
    for linha in saida.splitlines():
        if " ... " not in linha or "(" not in linha:
            continue
        caminho = linha.split("(", 1)[1].split(")", 1)[0]
        pacote = caminho.split(".")[0]
        if pacote not in contagem:
            continue
        if "skipped" in linha:
            contagem[pacote]["pulado"] += 1
        elif "interoperabilidade" in caminho:
            contagem[pacote]["interop"] += 1
        else:
            contagem[pacote]["funcional"] += 1
    return contagem


def figura_resultado(contagem):
    rotulos = [rotulo for _, rotulo in PARTES]
    funcionais = [contagem[p]["funcional"] for p, _ in PARTES]
    interop = [contagem[p]["interop"] for p, _ in PARTES]
    pulados = [contagem[p]["pulado"] for p, _ in PARTES]

    fig, ax = plt.subplots(figsize=(6, 3.4))
    ax.bar(rotulos, funcionais, color=VERDE, label="funcional (passou)")
    ax.bar(rotulos, interop, bottom=funcionais, color=AZUL, label="interoperabilidade (passou)")
    base = [f + i for f, i in zip(funcionais, interop)]
    if any(pulados):
        ax.bar(rotulos, pulados, bottom=base, color=CINZA, label="pulado")
    for x, total in enumerate(b + p for b, p in zip(base, pulados)):
        ax.text(x, total + 0.4, str(total), ha="center", va="bottom", fontsize=10)

    ax.set_ylabel("nº de testes")
    ax.set_ylim(0, max(base) + 7)
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="#e6e6e6")
    ax.set_axisbelow(True)
    ax.legend(loc="upper center", ncol=2, frameon=False, fontsize=8.5, bbox_to_anchor=(0.5, 1.13))
    fig.tight_layout()
    fig.savefig(os.path.join(FIGS, "resultado_testes.pdf"))
    plt.close(fig)


def figura_terminal(saida: str, primeiras: int = 11, ultimas: int = 5):
    linhas_teste = [l for l in saida.splitlines() if " ... " in l]
    rodape = [l for l in saida.splitlines() if l.startswith(("Ran ", "OK", "FAILED")) or set(l) == {"-"}]
    omitidos = len(linhas_teste) - primeiras - ultimas
    texto = ['$ python3 -m unittest discover -p "test_*.py" -v']
    texto += linhas_teste[:primeiras]
    texto.append(f"[... {omitidos} testes intermediários omitidos por espaço — ver Figura 6 ...]")
    texto += linhas_teste[-ultimas:]
    texto += [""] + rodape

    # Quebra linhas longas como um terminal de 112 colunas
    quebradas = []
    for linha in texto:
        while len(linha) > 112:
            quebradas.append(linha[:112])
            linha = linha[112:]
        quebradas.append(linha)

    altura = 0.8 + 0.215 * len(quebradas)
    fig = plt.figure(figsize=(11, altura), dpi=100)
    fig.patch.set_facecolor("#1e1f2e")
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_axis_off()
    ax.set_xlim(0, 1)
    ax.set_ylim(0, altura)
    ax.add_patch(plt.Rectangle((0, altura - 0.35), 1, 0.35, color="#2b2c3f"))
    for i, cor in enumerate(["#ff5f57", "#febc2e", "#28c840"]):
        ax.plot(0.018 + i * 0.018, altura - 0.175, "o", color=cor, markersize=8)
    ax.text(0.075, altura - 0.175, "terminal — suíte automatizada de testes (unittest)",
            color="#b8bbd0", fontsize=9, va="center", family="monospace")

    y = altura - 0.6
    for linha in quebradas:
        cor = "#e6e6e6" if linha.startswith(("$", "[", "Ran", "---")) else "#7fd6a0"
        ax.text(0.02, y, linha, color=cor, fontsize=9.2, family="monospace", va="top")
        y -= 0.215
    fig.savefig(os.path.join(FIGS, "05_testes.png"), facecolor=fig.get_facecolor())
    plt.close(fig)


def main():
    saida, codigo = rodar_suite()
    if codigo != 0:
        sys.exit("A suíte de testes falhou; figuras não geradas.\n" + saida[-2000:])
    contagem = contar_por_parte(saida)
    figura_resultado(contagem)
    figura_terminal(saida)
    for pacote, rotulo in PARTES:
        print(rotulo.replace("\n", " "), contagem[pacote])


if __name__ == "__main__":
    main()
