"""Teste ADICIONAL de interoperabilidade (restrição 3 do roteiro).

A biblioteca `cryptography` é usada somente para conferir a saída da nossa
implementação — nunca para produzi-la. O teste é pulado se ela não existir.
O OAEP é conferido em parte2_oaep/testes/test_interoperabilidade_oaep.py.
"""

import os
import tempfile
import unittest

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    TEM_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    TEM_CRYPTOGRAPHY = False

from comum.hash_sha3 import H_LEN, sha3_256
from parte1_chaves.chaves import gerar_par_chaves
from parte3_pss.pss import assinar_digest, verificar_digest
from parte4_verificacao.formato_assinatura import EstruturaAssinada, serializar_assinatura
from parte4_verificacao.verificacao import verificar_arquivo


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

    def _pss_lib(self):
        return padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=H_LEN)

    def test_pss_da_biblioteca_verificado_por_nos(self):
        mensagem = b"documento assinado pela biblioteca"
        assinatura = self.lib_priv.sign(mensagem, self._pss_lib(), hashes.SHA3_256())
        self.assertTrue(verificar_digest(self.nossa.publica(), sha3_256(mensagem), assinatura))
        self.assertFalse(verificar_digest(self.nossa.publica(), sha3_256(b"outro"), assinatura))

    def test_arquivo_assinado_pela_biblioteca_passa_em_verificar_arquivo(self):
        conteudo = b"Contrato assinado com a biblioteca cryptography.\n" * 20
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "documento.txt")
            with open(caminho, "wb") as arquivo:
                arquivo.write(conteudo)
            assinatura = self.lib_priv.sign(conteudo, self._pss_lib(), hashes.SHA3_256())
            sig = serializar_assinatura(EstruturaAssinada("documento.txt", assinatura))
            self.assertTrue(verificar_arquivo(self.nossa.publica(), caminho, sig).valido)


if __name__ == "__main__":
    unittest.main()
