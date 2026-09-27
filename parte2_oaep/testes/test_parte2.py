import unittest

from comum.erros import ErroDecifracao, ErroParametro
from comum.hash_sha3 import H_LEN, sha3_256
from parte1_chaves.chaves import gerar_par_chaves
from parte2_oaep.mgf1 import mgf1
from parte2_oaep.oaep import cifrar_oaep, decifrar_oaep


class TesteMGF1(unittest.TestCase):
    def test_primeiro_bloco(self):
        semente = b"semente"
        self.assertEqual(mgf1(semente, H_LEN), sha3_256(semente + b"\x00\x00\x00\x00"))

    def test_tamanho_e_prefixo(self):
        longa = mgf1(b"abc", 100)
        self.assertEqual(len(longa), 100)
        self.assertEqual(mgf1(b"abc", 40), longa[:40])

    def test_segundo_bloco_usa_contador_1(self):
        semente = b"semente"
        self.assertEqual(mgf1(semente, 2 * H_LEN)[H_LEN:], sha3_256(semente + b"\x00\x00\x00\x01"))

    def test_tamanho_zero_e_negativo(self):
        self.assertEqual(mgf1(b"abc", 0), b"")
        with self.assertRaises(ErroParametro):
            mgf1(b"abc", -1)


class TesteOAEP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = gerar_par_chaves(2048)
        cls.pub = cls.priv.publica()
        cls.max_msg = cls.pub.k - 2 * H_LEN - 2

    def test_ida_e_volta(self):
        for msg in [b"", b"mensagem curta", bytes(range(256))[: self.max_msg]]:
            self.assertEqual(decifrar_oaep(self.priv, cifrar_oaep(self.pub, msg)), msg)

    def test_probabilistico(self):
        self.assertNotEqual(cifrar_oaep(self.pub, b"x"), cifrar_oaep(self.pub, b"x"))

    def test_mensagem_longa_demais(self):
        with self.assertRaises(ErroParametro):
            cifrar_oaep(self.pub, b"a" * (self.max_msg + 1))

    def test_ciphertext_adulterado(self):
        cifra = bytearray(cifrar_oaep(self.pub, b"segredo"))
        cifra[len(cifra) // 2] ^= 0x01
        with self.assertRaises(ErroDecifracao):
            decifrar_oaep(self.priv, bytes(cifra))

    def test_rotulo_diferente(self):
        cifra = cifrar_oaep(self.pub, b"segredo", rotulo=b"A")
        with self.assertRaises(ErroDecifracao):
            decifrar_oaep(self.priv, cifra, rotulo=b"B")

    def test_tamanho_invalido(self):
        with self.assertRaises(ErroDecifracao):
            decifrar_oaep(self.priv, b"\x01\x02\x03")


if __name__ == "__main__":
    unittest.main()
