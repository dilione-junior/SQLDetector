**Projeto: Scanner de SQL Injection com Python**

Desenvolvi um scanner automatizado para detectar possíveis falhas de SQL Injection em aplicações web. O projeto simula a manipulação de parâmetros de URL com caracteres especiais e monitora a resposta do servidor à procura de mensagens de erro típicas de banco de dados, como mysql_fetch_array().
O script foi desenvolvido com Python e utiliza bibliotecas como requests para envio das requisições e re para manipulação de expressões regulares. Essa automação ajuda a identificar, de forma simples e rápida, possíveis brechas em aplicações mal protegidas, sendo útil na fase de reconhecimento de um teste de invasão (pentest).
Funcionalidades:

•	Manipulação automática de URLs com parâmetros
•	Injeção de carga maliciosa (') para testes
•	Análise de resposta do servidor em busca de mensagens de erro SQL
•	Simulação de navegação real com cabeçalhos personalizados
