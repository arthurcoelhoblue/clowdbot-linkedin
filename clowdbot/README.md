# clowdbot

Aplicação Node.js (Express) pronta para deploy no Google Cloud Run, focada no fluxo OAuth 2.0 do LinkedIn.

## Como rodar localmente

```bash
npm install
npm start
```

A aplicação inicia na porta definida por `PORT` (padrão `8080`).

## Variáveis de ambiente

Defina as variáveis abaixo antes de iniciar:

```bash
export LINKEDIN_CLIENT_ID="..."
export LINKEDIN_CLIENT_SECRET="..."
export LINKEDIN_REDIRECT_URI="http://localhost:8080/oauth/linkedin/callback"
```

## Rotas disponíveis

- `GET /` → retorna `clowdbot ok`
- `GET /auth/linkedin` → inicia o OAuth 2.0 do LinkedIn
- `GET /oauth/linkedin/callback` → recebe o `code` e troca por `access_token`

## Deploy no Cloud Run (Deploy from source)

1. Faça push deste repositório para o GitHub.
2. No Google Cloud Console, acesse **Cloud Run** → **Create service**.
3. Em **Source**, escolha **Deploy from source** e conecte o repositório.
4. Selecione a branch e o diretório `clowdbot/` como raiz do serviço.
5. Configure as variáveis de ambiente (`LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET`, `LINKEDIN_REDIRECT_URI`).
6. Conclua o deploy.

## Redirect URI do LinkedIn

Use a URL pública do Cloud Run com o caminho:

```
https://SEU-SERVICO-REGIAO.a.run.app/oauth/linkedin/callback
```

Para testes locais, use:

```
http://localhost:8080/oauth/linkedin/callback
```
