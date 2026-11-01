import threading
import unittest

from lab.servidor_vulneravel import criar_servidor
from sql_injection_scan import encontrar_erros, escanear, main, montar_urls_de_teste


class TestFuncoes(unittest.TestCase):
    def test_testa_um_parametro_por_vez_e_mantem_os_demais(self):
        urls = montar_urls_de_teste("http://a.test/p?x=1&y=2")
        self.assertEqual(urls, [("x", "http://a.test/p?x=1%27&y=2"), ("y", "http://a.test/p?x=1&y=2%27")])

    def test_identifica_o_banco_pela_mensagem(self):
        self.assertEqual({b for b, _ in encontrar_erros("Unclosed quotation mark after")}, {"SQL Server"})

    def test_pagina_comum_nao_gera_erro(self):
        self.assertEqual(encontrar_erros("<h1>Bem-vindo</h1>"), set())

    def test_url_sem_parametro_e_recusada(self):
        with self.assertRaises(SystemExit):
            main(["http://127.0.0.1/"])

    def test_alvo_externo_exige_autorizacao(self):
        with self.assertRaises(SystemExit):
            main(["http://exemplo.test/p?id=1"])


class TestLaboratorio(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servidor = criar_servidor(0)
        cls.base = f"http://127.0.0.1:{cls.servidor.server_address[1]}"
        threading.Thread(target=cls.servidor.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.servidor.shutdown()
        cls.servidor.server_close()

    def test_detecta_rota_vulneravel(self):
        resultado = escanear(f"{self.base}/produto?id=1")
        self.assertTrue(resultado[0]["vulneravel"])
        self.assertEqual(resultado[0]["bancos"], ["SQLite"])

    def test_rota_parametrizada_nao_e_acusada(self):
        self.assertFalse(escanear(f"{self.base}/seguro?id=1")[0]["vulneravel"])

    def test_codigo_de_saida(self):
        self.assertEqual(main([f"{self.base}/produto?id=1"]), 1)
        self.assertEqual(main([f"{self.base}/seguro?id=1"]), 0)


if __name__ == "__main__":
    unittest.main()
