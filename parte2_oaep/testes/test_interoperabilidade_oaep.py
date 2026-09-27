"""Teste ADICIONAL de interoperabilidade do OAEP (restrição 3 do roteiro).

Usa a pycryptodome somente para conferir a saída da nossa implementação.
A biblioteca `cryptography` não aceita OAEP com SHA3-256 (nem na 50.x),
por isso este teste usa a pycryptodome. É pulado se ela não estiver instalada.
"""

import unittest

try:
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA3_256
    from Crypto.PublicKey import RSA
    TEM_PYCRYPTODOME = True
except ImportError:  # pragma: no cover
    TEM_PYCRYPTODOME = False

from parte1_chaves.chaves import gerar_par_chaves
from parte2_oaep.oaep import cifrar_oaep, decifrar_oaep

MENSAGENS = [b"", b"segredo", bytes(range(190))]


@unittest.skipUnless(TEM_PYCRYPTODOME, "biblioteca pycryptodome não instalada")
class TesteInteroperabilidadeOAEP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nossa = gerar_par_chaves(2048)
        c = cls.nossa
        cls.lib = RSA.construct((c.n, c.e, c.d, c.p, c.q))

    def _oaep_lib(self, rotulo: bytes = b""):
        return PKCS1_OAEP.new(self.lib, hashAlgo=SHA3_256, label=rotulo)

    def test_nos_para_biblioteca(self):
        for msg in MENSAGENS:
            self.assertEqual(self._oaep_lib().decrypt(cifrar_oaep(self.nossa.publica(), msg)), msg)

    def test_biblioteca_para_nos(self):
        for msg in MENSAGENS:
            self.assertEqual(decifrar_oaep(self.nossa, self._oaep_lib().encrypt(msg)), msg)

    def test_rotulo(self):
        cifra = self._oaep_lib(b"rotulo").encrypt(b"x")
        self.assertEqual(decifrar_oaep(self.nossa, cifra, rotulo=b"rotulo"), b"x")


if __name__ == "__main__":
    unittest.main()
