"""Testes de integridade exigidos na Parte IV:
(a) um byte do arquivo; (b) um byte da assinatura; (c) a chave pública."""

import base64
import os
import tempfile
import unittest

from comum.erros import ErroFormato
from parte1_chaves.chaves import ChavePublica, gerar_par_chaves
from parte3_pss.assinatura import assinar_arquivo
from parte4_verificacao.formato_assinatura import (
    EstruturaAssinada, parse_assinatura, serializar_assinatura,
)
from parte4_verificacao.verificacao import verificar_arquivo


class TesteAdulteracao(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = gerar_par_chaves(2048)
        cls.pub = cls.priv.publica()
        cls.dir = tempfile.TemporaryDirectory()
        cls.caminho = os.path.join(cls.dir.name, "documento.txt")
        with open(cls.caminho, "wb") as f:
            f.write(b"Contrato: pagar R$ 100,00 a Fulano.\n" * 50)
        assinatura = base64.b64decode(assinar_arquivo(cls.priv, cls.caminho))
        cls.sig = serializar_assinatura(EstruturaAssinada("documento.txt", assinatura))

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _copia_adulterada(self, posicao: int) -> str:
        with open(self.caminho, "rb") as f:
            dados = bytearray(f.read())
        dados[posicao] ^= 0x01
        caminho = os.path.join(self.dir.name, f"adulterado_{posicao}.txt")
        with open(caminho, "wb") as f:
            f.write(dados)
        return caminho

    def test_original_valido(self):
        self.assertTrue(verificar_arquivo(self.pub, self.caminho, self.sig).valido)

    def test_a_um_byte_do_arquivo(self):
        for pos in (0, 17, -1):
            self.assertFalse(verificar_arquivo(self.pub, self._copia_adulterada(pos), self.sig).valido)

    def test_b_um_byte_da_assinatura(self):
        estrutura = parse_assinatura(self.sig)
        for pos in (0, 128, 255):
            s = bytearray(estrutura.assinatura)
            s[pos] ^= 0x01
            sig = serializar_assinatura(EstruturaAssinada("documento.txt", bytes(s)))
            self.assertFalse(verificar_arquivo(self.pub, self.caminho, sig).valido)

    def test_c_chave_publica_alterada(self):
        n_alterado = self.pub.n ^ (1 << 100)
        self.assertFalse(verificar_arquivo(ChavePublica(n_alterado, self.pub.e), self.caminho, self.sig).valido)
        self.assertFalse(verificar_arquivo(ChavePublica(self.pub.n, 3), self.caminho, self.sig).valido)
        outra = gerar_par_chaves(2048).publica()
        self.assertFalse(verificar_arquivo(outra, self.caminho, self.sig).valido)

    def test_estrutura_malformada(self):
        with self.assertRaises(ErroFormato):
            parse_assinatura("lixo")
        # verificar_arquivo não deve lançar exceção, apenas reportar inválido
        self.assertFalse(verificar_arquivo(self.pub, self.caminho, "lixo").valido)


if __name__ == "__main__":
    unittest.main()
