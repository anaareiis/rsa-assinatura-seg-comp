import unittest

from comum.erros import ErroFormato
from parte1_chaves.aritmetica_modular import exp_modular, inverso_modular, mdc_estendido
from parte1_chaves.chaves import gerar_par_chaves
from parte1_chaves.formato_chaves import (
    carregar_chave_privada, carregar_chave_publica,
    serializar_chave_privada, serializar_chave_publica,
)
from parte1_chaves.miller_rabin import eh_provavel_primo, gerar_primo_provavel
from parte1_chaves.rsa_primitivas import rsadp, rsaep

PRIMOS = [2, 3, 5, 7, 97, 7919, 2**61 - 1, 2**127 - 1]
COMPOSTOS = [0, 1, 4, 9, 561, 1105, 1729, 2**61 + 1, (2**61 - 1) * (2**31 - 1)]  # inclui números de Carmichael


class TesteAritmetica(unittest.TestCase):
    def test_mdc_estendido(self):
        g, x, y = mdc_estendido(240, 46)
        self.assertEqual(g, 2)
        self.assertEqual(240 * x + 46 * y, 2)

    def test_inverso_modular(self):
        self.assertEqual(inverso_modular(3, 11) * 3 % 11, 1)
        with self.assertRaises(ValueError):
            inverso_modular(6, 9)

    def test_exp_modular(self):
        for base, exp, mod in [(4, 13, 497), (2, 10**6, 10**9 + 7), (7, 0, 13)]:
            self.assertEqual(exp_modular(base, exp, mod), pow(base, exp, mod))


class TesteMillerRabin(unittest.TestCase):
    def test_primos_conhecidos(self):
        for p in PRIMOS:
            self.assertTrue(eh_provavel_primo(p), p)

    def test_compostos_e_carmichael(self):
        for c in COMPOSTOS:
            self.assertFalse(eh_provavel_primo(c), c)

    def test_primo_gerado_tem_tamanho_exato(self):
        p = gerar_primo_provavel(512)
        self.assertEqual(p.bit_length(), 512)
        self.assertTrue(eh_provavel_primo(p))


class TesteChaves(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chave = gerar_par_chaves(2048)

    def test_parametros(self):
        c = self.chave
        self.assertGreaterEqual(c.n.bit_length(), 2048)
        self.assertEqual(c.p * c.q, c.n)
        self.assertNotEqual(c.p, c.q)
        self.assertEqual(c.dp, c.d % (c.p - 1))
        self.assertEqual(c.dq, c.d % (c.q - 1))
        self.assertEqual(c.qinv * c.q % c.p, 1)

    def test_rejeita_modulo_pequeno(self):
        with self.assertRaises(ValueError):
            gerar_par_chaves(1024)

    def test_primitivas_ida_e_volta(self):
        m = 0x1234567890ABCDEF
        c = rsaep(self.chave.publica(), m)
        self.assertEqual(rsadp(self.chave, c), m)

    def test_exportacao_importacao(self):
        pub = self.chave.publica()
        self.assertEqual(carregar_chave_publica(serializar_chave_publica(pub)), pub)
        self.assertEqual(carregar_chave_privada(serializar_chave_privada(self.chave)), self.chave)

    def test_importacao_malformada(self):
        with self.assertRaises(ErroFormato):
            carregar_chave_publica("isto não é uma chave")


if __name__ == "__main__":
    unittest.main()
