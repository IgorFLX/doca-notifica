# Chamada de Doca

App simples para chamar motoristas para a doca (A ou B), com aviso sonoro
e vibracao na tela do motorista.

- `/` — painel do operador (fila, chamar motorista, QR code).
- `/motorista` — pagina que o motorista abre no celular para entrar na fila
  e aguardar a chamada.

## Rodar localmente

```bash
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

## Deploy no Render (gratuito)

1. Suba este codigo para um repositorio no GitHub.
2. Em https://dashboard.render.com, clique em **New > Blueprint** e
   conecte o repositorio. O Render le o `render.yaml` automaticamente
   e configura o servico (build + start).
3. Aguarde o deploy. O Render gera uma URL publica com HTTPS, por
   exemplo `https://doca-notifica.onrender.com`.
4. Acesse `https://<sua-url>.onrender.com/` (painel) e
   `https://<sua-url>.onrender.com/motorista` (motorista) de qualquer
   rede — nao precisa mais estar na mesma Wi-Fi.

### Limitacoes do plano gratuito

- O servico "dorme" apos ~15 minutos sem uso e demora alguns segundos
  para acordar na proxima requisicao.
- O disco nao e persistente: a fila de motoristas (armazenada em
  SQLite) e perdida a cada reinicio ou novo deploy. Para uso real em
  producao, trocar o SQLite por um banco gerenciado (ex: Postgres,
  que o Render tambem oferece gratuitamente em plano separado).
