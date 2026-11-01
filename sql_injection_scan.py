# Scanner de SQL Injection baseado em erro, para uso em ambientes autorizados
import argparse
import json
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

# Caractere que quebra a sintaxe de uma consulta montada por concatenação de strings
PAYLOAD = "'"

# Trechos de mensagens de erro típicas de cada banco de dados
ASSINATURAS = {
    "MySQL": ["you have an error in your sql syntax", "mysql_fetch_array()", "warning: mysql"],
    "PostgreSQL": ["pg_query()", "unterminated quoted string", "syntax error at or near"],
    "SQL Server": ["unclosed quotation mark", "microsoft ole db provider for sql server"],
    "Oracle": ["ora-00933", "ora-01756"],
    "SQLite": ["sqlite3.operationalerror", "unrecognized token", "sqlite error"],
}

CABECALHOS = {"User-Agent": "SQLDetector/2.0 (teste de seguranca autorizado)"}
ALVOS_LOCAIS = {"localhost", "127.0.0.1", "::1"}


def montar_urls_de_teste(url):
    """Retorna (parâmetro, url) com o payload em um parâmetro por vez, mantendo os demais."""
    partes = urlsplit(url)
    parametros = parse_qsl(partes.query, keep_blank_values=True)
    urls = []
    for indice, (nome, valor) in enumerate(parametros):
        alterados = list(parametros)
        alterados[indice] = (nome, valor + PAYLOAD)
        urls.append((nome, urlunsplit(partes._replace(query=urlencode(alterados)))))
    return urls


def encontrar_erros(html):
    """Retorna o conjunto de (banco, assinatura) presentes na resposta."""
    texto = html.lower()
    return {
        (banco, assinatura)
        for banco, assinaturas in ASSINATURAS.items()
        for assinatura in assinaturas
        if assinatura in texto
    }


def escanear(url, timeout=10, sessao=requests):
    """Compara cada resposta injetada com a original para não acusar erros que já existiam."""
    base = encontrar_erros(sessao.get(url, headers=CABECALHOS, timeout=timeout).text)
    resultados = []
    for parametro, url_teste in montar_urls_de_teste(url):
        erros = encontrar_erros(sessao.get(url_teste, headers=CABECALHOS, timeout=timeout).text) - base
        resultados.append({
            "parametro": parametro,
            "url_testada": url_teste,
            "vulneravel": bool(erros),
            "bancos": sorted({banco for banco, _ in erros}),
            "evidencias": sorted(assinatura for _, assinatura in erros),
        })
    return resultados


def criar_parser():
    parser = argparse.ArgumentParser(description="Detecta SQL Injection baseado em erro nos parâmetros de uma URL.")
    parser.add_argument("url", help="URL com parâmetros, ex.: http://127.0.0.1:8000/produto?id=1")
    parser.add_argument("--timeout", type=float, default=10, help="tempo limite em segundos (padrão: 10)")
    parser.add_argument("--json", action="store_true", help="exibe o resultado em JSON")
    parser.add_argument("--autorizado", action="store_true",
                        help="confirma que você tem permissão para testar um alvo que não é local")
    return parser


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    parser = criar_parser()
    args = parser.parse_args(argv)
    partes = urlsplit(args.url)

    if partes.scheme not in ("http", "https") or not partes.hostname:
        parser.error("informe uma URL completa, começando com http:// ou https://")
    if not partes.query:
        parser.error("a URL precisa ter ao menos um parâmetro, ex.: ?id=1")
    if partes.hostname not in ALVOS_LOCAIS and not args.autorizado:
        parser.error("alvo externo: use --autorizado somente se tiver permissão para testá-lo")

    try:
        resultados = escanear(args.url, args.timeout)
    except requests.RequestException as erro:
        print(f"Erro ao acessar o alvo: {erro}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(resultados, ensure_ascii=False, indent=2))
    else:
        for item in resultados:
            if item["vulneravel"]:
                print(f"[VULNERÁVEL] parâmetro '{item['parametro']}' - banco provável: {', '.join(item['bancos'])}")
                print(f"             evidência: {'; '.join(item['evidencias'])}")
            else:
                print(f"[sem indício] parâmetro '{item['parametro']}'")
    return 1 if any(item["vulneravel"] for item in resultados) else 0


if __name__ == "__main__":
    sys.exit(main())
