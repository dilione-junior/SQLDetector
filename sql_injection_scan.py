import requests
import re

# URL de teste (exemplo com parâmetro fictício)
url = 'https://exemplo.exemplo/exemplo.html?mensagem=1'

# Expressão regular para capturar o parâmetro
padrao = re.search(r"([\w/\-_.]+[\?&]{1}[\w_]+=)([\w_]+)", url)

# Monta a URL com tentativa de injeção
injecao = padrao.groups()[0] + "\\'"

print("Testando:", injecao)

header = {
    'user-agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/51.0.2704.103 Safari/537.36'
    )
}

# Envia a requisição
req = requests.get(injecao, headers=header)
html = req.text

# Verifica se há sinais de falha SQL
if "mysql_fetch_array()" in html:
    print("Vulnerável!")
else:
    print("Não vulnerável.")