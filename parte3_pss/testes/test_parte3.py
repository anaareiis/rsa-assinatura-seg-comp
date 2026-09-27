import os
import tempfile
import unittest

from comum.hash_sha3 import sha3_256
from parte1_chaves.chaves import gerar_par_chaves
from parte3_pss.assinatura import assinar_arquivo
from parte3_pss.pss import assinar_digest, emsa_pss_codificar, emsa_pss_verificar, verificar_digest


class TesteEMSAPSS(unittest.TestCase):
    def test_codificacao_termina_em_bc(self):
        em = emsa_pss_codificar(sha3_256(b"msg"), 2047)
        self.assertEqual(len(em), 256)
        self.assertEqual(em[-1], 0xBC)
        self.assertEqual(em[0] & 0x80, 0)  # bit mais alto zerado

    def test_codifica_e_verifica(self):
        h = sha3_256(b"msg")
        em = emsa_pss_codificar(h, 2047)
        self.assertTrue(emsa_pss_verificar(h, em, 2047))
        self.assertFalse(emsa_pss_verificar(sha3_256(b"outra"), em, 2047))


class TesteRSAPSS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = gerar_par_chaves(2048)
        cls.pub = cls.priv.publica()

    def test_assina_e_verifica(self):
        h = sha3_256(b"documento")
        s = assinar_digest(self.priv, h)
        self.assertEqual(len(s), self.pub.k)
        self.assertTrue(verificar_digest(self.pub, h, s))

    def test_probabilistica(self):
        h = sha3_256(b"documento")
        self.assertNotEqual(assinar_digest(self.priv, h), assinar_digest(self.priv, h))

    def test_nao_e_cifragem_do_hash(self):
        """A assinatura não pode ser simplesmente H(m)^d mod n."""
        h = sha3_256(b"documento")
        s = int.from_bytes(assinar_digest(self.priv, h), "big")
        self.assertNotEqual(pow(s, self.pub.e, self.pub.n), int.from_bytes(h, "big"))

    def test_assinatura_arquivo_base64(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"conteudo do arquivo")
        try:
            b64 = assinar_arquivo(self.priv, f.name)
            import base64
            self.assertEqual(len(base64.b64decode(b64, validate=True)), self.pub.k)
        finally:
            os.remove(f.name)


if __name__ == "__main__":
    unittest.main()
