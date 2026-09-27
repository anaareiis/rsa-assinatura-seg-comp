"""Teste ADICIONAL de interoperabilidade (restrição 3 do roteiro).

A biblioteca `cryptography` é usada somente para conferir a saída da nossa
implementação — nunca para produzi-la. O teste é pulado se ela não existir.
"""

import unittest

try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    TEM_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    TEM_CRYPTOGRAPHY = False

from comum.hash_sha3 import H_LEN, sha3_256
from parte1_chaves.chaves import gerar_par_chaves
from parte2_oaep.oaep import cifrar_oaep, decifrar_oaep
from parte3_pss.pss import assinar_digest


@unittest.skipUnless(TEM_CRYPTOGRAPHY, "biblioteca cryptography não instalada")
class TesteInteroperabilidade(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nossa = gerar_par_chaves(2048)
        c = cls.nossa
        publica = rsa.RSAPublicNumbers(c.e, c.n)
        cls.lib_priv = rsa.RSAPrivateNumbers(c.p, c.q, c.d, c.dp, c.dq, c.qinv, publica).private_key()
        cls.lib_pub = cls.lib_priv.public_key()

    def test_pss_verificado_pela_biblioteca(self):
        mensagem = b"documento assinado pelo grupo"
        assinatura = assinar_digest(self.nossa, sha3_256(mensagem))
        self.lib_pub.verify(  # lança InvalidSignature se incompatível
            assinatura, mensagem,
            padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=H_LEN),
            hashes.SHA3_256(),
        )

    def _oaep_lib(self):
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA3_256()), algorithm=hashes.SHA3_256(), label=None)

    def test_oaep_biblioteca_para_nos(self):
        try:
            cifra = self.lib_pub.encrypt(b"segredo", self._oaep_lib())
        except UnsupportedAlgorithm:
            self.skipTest("versão da cryptography não suporta OAEP com SHA3-256")
        self.assertEqual(decifrar_oaep(self.nossa, cifra), b"segredo")

    def test_oaep_nos_para_biblioteca(self):
        cifra = cifrar_oaep(self.nossa.publica(), b"segredo")
        try:
            decifrado = self.lib_priv.decrypt(cifra, self._oaep_lib())
        except UnsupportedAlgorithm:
            self.skipTest("versão da cryptography não suporta OAEP com SHA3-256")
        self.assertEqual(decifrado, b"segredo")


if __name__ == "__main__":
    unittest.main()
