import unittest

from comum.erros import ErroDecifracao, ErroParametro
from comum.hash_sha3 import H_LEN, sha3_256
from parte1_chaves.chaves import gerar_par_chaves
from parte2_oaep.mgf1 import mgf1
from parte2_oaep.oaep import (
    cifrar_oaep, decifrar_oaep, oaep_codificar, oaep_decodificar, tamanho_maximo_mensagem,
)

K = 256  # RSA-2048


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


class TesteCodificacaoOAEP(unittest.TestCase):
    """EME-OAEP isolado, sem a operação RSA."""

    def test_tamanho_maximo_rsa_2048(self):
        self.assertEqual(tamanho_maximo_mensagem(K), 190)

    def test_ida_e_volta(self):
        for msg in [b"", b"mensagem curta", b"\x00\x01\x00", b"a" * 190]:
            em = oaep_codificar(msg, K)
            self.assertEqual(len(em), K)
            self.assertEqual(em[0], 0x00)
            self.assertEqual(oaep_decodificar(em, K), msg)

    def test_codificacao_probabilistica(self):
        self.assertNotEqual(oaep_codificar(b"x", K), oaep_codificar(b"x", K))

    def test_mensagem_longa_demais(self):
        with self.assertRaises(ErroParametro):
            oaep_codificar(b"a" * 191, K)

    def test_qualquer_byte_alterado_e_detectado(self):
        em = oaep_codificar(b"segredo", K)
        for pos in (0, 1, 32, 33, 64, 65, 200, K - 1):
            adulterado = bytearray(em)
            adulterado[pos] ^= 0x01
            with self.assertRaises(ErroDecifracao, msg=f"posição {pos}"):
                oaep_decodificar(bytes(adulterado), K)

    def test_rotulo(self):
        em = oaep_codificar(b"segredo", K, rotulo=b"contexto")
        self.assertEqual(oaep_decodificar(em, K, rotulo=b"contexto"), b"segredo")
        with self.assertRaises(ErroDecifracao):
            oaep_decodificar(em, K, rotulo=b"outro")

    def test_tamanho_errado(self):
        with self.assertRaises(ErroDecifracao):
            oaep_decodificar(oaep_codificar(b"x", K)[1:], K)

    def test_mesma_mensagem_de_erro(self):
        """Falhas diferentes não podem ser distinguíveis pela mensagem."""
        em = bytearray(oaep_codificar(b"segredo", K))
        y_errado = bytearray(em)
        y_errado[0] = 0x01
        mensagens = set()
        for entrada, rotulo in [(bytes(y_errado), b""), (bytes(em), b"outro"), (b"\x00" * K, b"")]:
            with self.assertRaises(ErroDecifracao) as ctx:
                oaep_decodificar(entrada, K, rotulo)
            mensagens.add(str(ctx.exception))
        self.assertEqual(len(mensagens), 1)


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
