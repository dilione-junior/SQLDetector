# SQLDetector

Scanner em Python que detecta indícios de **SQL Injection baseado em erro** nos parâmetros de uma URL. Inclui um laboratório local vulnerável para testar com segurança e ver a correção da falha.

> **Uso autorizado:** teste apenas sistemas seus ou com permissão por escrito. Alvos fora da sua máquina exigem a opção `--autorizado`.

## Como funciona

1. Acessa a URL original e guarda as mensagens de erro que já existem na página.
2. Adiciona uma aspa simples (`'`) a um parâmetro por vez, sem alterar os demais.
3. Procura na resposta mensagens de erro de MySQL, PostgreSQL, SQL Server, Oracle e SQLite.
4. Aponta o parâmetro somente se surgir um erro que não existia na resposta original.

O scanner apenas provoca e identifica o erro. Ele não extrai dados nem altera o banco.

## Passo a passo

### 1. Instalar

```bash
git clone https://github.com/dilione-junior/SQLDetector.git
cd SQLDetector
python -m pip install -r requirements.txt
```

### 2. Subir o laboratório

Em um terminal, execute o comando abaixo e deixe-o aberto. O servidor escuta apenas em `127.0.0.1`:

```bash
python lab/servidor_vulneravel.py
```

### 3. Testar a rota vulnerável

Em outro terminal:

```bash
python sql_injection_scan.py "http://127.0.0.1:8000/produto?id=1"
```

```text
[VULNERÁVEL] parâmetro 'id' - banco provável: SQLite
             evidência: sqlite3.operationalerror; unrecognized token
```

### 4. Testar a rota corrigida

```bash
python sql_injection_scan.py "http://127.0.0.1:8000/seguro?id=1"
```

```text
[sem indício] parâmetro 'id'
```

### 5. Gerar saída em JSON

```bash
python sql_injection_scan.py "http://127.0.0.1:8000/produto?id=1" --json
```

### 6. Testar um alvo autorizado

```bash
python sql_injection_scan.py "https://homologacao.exemplo.com/produto?id=1" --autorizado
```

## Opções e códigos de saída

| Opção | Descrição |
|---|---|
| `--timeout N` | Tempo limite de cada requisição, em segundos (padrão: 10) |
| `--json` | Exibe o resultado em JSON |
| `--autorizado` | Confirma a permissão para testar um alvo que não é local |

| Código | Significado |
|---|---|
| 0 | Nenhum indício encontrado |
| 1 | Indício de SQL Injection encontrado |
| 2 | Erro de conexão ou uso incorreto |

## Como corrigir a falha

A diferença entre as duas rotas de [`lab/servidor_vulneravel.py`](lab/servidor_vulneravel.py) é a forma de montar a consulta:

```python
# Vulnerável: a entrada do usuário vira parte do SQL
f"SELECT nome FROM produtos WHERE id = '{identificador}'"

# Seguro: a entrada é enviada separadamente, como dado
banco.execute("SELECT nome FROM produtos WHERE id = ?", (identificador,))
```

Além disso, não exiba erros do banco ao visitante e use um usuário de banco com o mínimo de privilégios. Veja o [guia da OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).

## Limitações

- Testa apenas parâmetros da URL em requisições GET; não cobre formulários POST, cookies ou cabeçalhos.
- Detecta apenas falhas que exibem erro. **"Sem indício" não significa "seguro"**: variantes cegas (blind) não são identificadas.
- Um indício precisa de validação manual, pois a página pode conter um texto parecido com a mensagem de erro.

## Testes

```bash
python -m unittest -v
```
