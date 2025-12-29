# Bolão Mega-Sena

## Configuração SMTP

Variáveis de ambiente relevantes:

- `SMTP_HOST` (default: `127.0.0.1`)
- `SMTP_PORT` (default: `25`)
- `SMTP_SECURE` (default: `false`, força `false` quando `SMTP_PORT=25`)
- `SMTP_TLS_REJECT_UNAUTHORIZED` (default: `true`)
- `SMTP_IGNORE_TLS` (default: `false`)
- `SMTP_REQUIRE_TLS` (default: `false`)

Para ambientes internos com certificado self-signed:

```bash
SMTP_TLS_REJECT_UNAUTHORIZED=false
# SMTP_IGNORE_TLS=true
```

## Teste rápido de envio

Use o endpoint administrativo:

```bash
curl -X POST "http://localhost:3000/admin/email/test" \
  -u "${ADMIN_USER}:${ADMIN_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"to":"seu@email.com"}'
```
