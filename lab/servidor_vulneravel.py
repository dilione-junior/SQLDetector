# Laboratório local INTENCIONALMENTE vulnerável. Não reutilize este código em aplicações reais.
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PORTA_PADRAO = 8000


def criar_banco():
    banco = sqlite3.connect(":memory:", check_same_thread=False)
    banco.execute("CREATE TABLE produtos (id TEXT, nome TEXT)")
    banco.execute("INSERT INTO produtos VALUES ('1', 'Caderno'), ('2', 'Caneta')")
    return banco


BANCO = criar_banco()


class Manipulador(BaseHTTPRequestHandler):
    def do_GET(self):
        partes = urlsplit(self.path)
        identificador = parse_qs(partes.query).get("id", ["1"])[0]
        if partes.path == "/seguro":
            # Correção: consulta parametrizada, em que a entrada nunca vira parte do SQL
            consulta, argumentos = "SELECT nome FROM produtos WHERE id = ?", (identificador,)
        else:
            # Falha: a entrada do usuário é concatenada diretamente na consulta
            consulta, argumentos = f"SELECT nome FROM produtos WHERE id = '{identificador}'", ()
        try:
            linhas = BANCO.execute(consulta, argumentos).fetchall()
            corpo, status = f"Produtos: {[linha[0] for linha in linhas]}", 200
        except sqlite3.Error as erro:
            # Falha: o erro do banco é exibido ao visitante
            corpo, status = f"sqlite3.OperationalError: {erro}", 500
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(corpo.encode("utf-8"))

    def log_message(self, *args):
        pass


def criar_servidor(porta=PORTA_PADRAO):
    # Escuta apenas na própria máquina, para que o laboratório não fique exposto na rede
    return ThreadingHTTPServer(("127.0.0.1", porta), Manipulador)


if __name__ == "__main__":
    print(f"Laboratório em http://127.0.0.1:{PORTA_PADRAO} (Ctrl+C para encerrar)")
    try:
        criar_servidor().serve_forever()
    except KeyboardInterrupt:
        pass
