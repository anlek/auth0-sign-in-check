# Cloudflare Workers

STOP. Your knowledge of Cloudflare Workers APIs and limits may be outdated. Always retrieve current documentation before any Workers, KV, R2, D1, Durable Objects, Queues, Vectorize, AI, or Agents SDK task.

## Docs

- https://developers.cloudflare.com/workers/
- MCP: `https://docs.mcp.cloudflare.com/mcp`

For all limits and quotas, retrieve from the product's `/platform/limits/` page. eg. `/workers/platform/limits`

## Project Context

This project is Sign-In Check: a stateless Cloudflare Worker that helps support staff confirm that a user still controls an Auth0 account. It is used when a user can sign in to Auth0 but no longer has access to the email address on the account.

The app proves account control, not real-world identity.

## Security Invariants

- Do not add storage unless explicitly required. The Worker should remain stateless.
- Do not store Auth0 IDs, tokens, confirmation codes, login events, or user records.
- Do not log Auth0 IDs, tokens, confirmation codes, request bodies, or callback query strings.
- Do not put real Auth0 values or secrets in `wrangler.jsonc`, `wrangler.example.jsonc`, `.dev.vars.example`, tests, or docs.
- Real local secrets belong only in `.dev.vars` or `.env`, which must stay ignored by git.
- Before committing or pushing, scan staged changes for secrets.

## Setup Notes

The required deployed secrets are:

- `AUTH0_DOMAIN`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`
- `HASH_SECRET`
- `COOKIE_SECRET`
- optional `CALLBACK_URL`

Use `npx wrangler secret put <NAME>` for deployed secrets. Use `.dev.vars` for local development only.

For each Auth0 application, configure:

- Allowed Callback URLs: `https://<host>/callback`
- Application Login URI: `https://<host>/login`
- Allowed Logout URLs: `https://<host>/`
- Allowed Web Origins: `https://<host>`
- Token Endpoint Authentication Method: `Client Secret Post`

## User-Facing Copy

Avoid exposing implementation details to users. For example, the sign-in link should say `Sign in`, not `Sign in with Auth0`.

Support-facing docs may mention Auth0 because support staff need the Auth0 ID / `sub`.

## Commands

| Command | Purpose |
|---------|---------|
| `npx wrangler dev` | Local development |
| `npx wrangler deploy` | Deploy to Cloudflare |
| `npx wrangler types` | Generate TypeScript types |

Run `wrangler types` after changing bindings in wrangler.jsonc.

## Node.js Compatibility

https://developers.cloudflare.com/workers/runtime-apis/nodejs/

## Errors

- **Error 1102** (CPU/Memory exceeded): Retrieve limits from `/workers/platform/limits/`
- **All errors**: https://developers.cloudflare.com/workers/observability/errors/

## Product Docs

Retrieve API references and limits from:
`/kv/` · `/r2/` · `/d1/` · `/durable-objects/` · `/queues/` · `/vectorize/` · `/workers-ai/` · `/agents/`

## Best Practices (conditional)

If the application uses Durable Objects or Workflows, refer to the relevant best practices:

- Durable Objects: https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/
- Workflows: https://developers.cloudflare.com/workflows/build/rules-of-workflows/
