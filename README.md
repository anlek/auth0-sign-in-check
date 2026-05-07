# Sign-In Check

Sign-In Check is a small Cloudflare Worker that helps support staff confirm that a person still controls an Auth0 account.

The project exists for cases where a user can still sign in to Auth0 but no longer has access to the email address on the account. Because we do not currently have a self-serve way for users to change their email address after signing in, support needs another way to confirm account control before helping with an email change. An email or phone call alone is not enough proof that the requester is the account owner. This app asks the user to complete a fresh Auth0 login and gives them a short confirmation code that support can verify against the Auth0 user ID.

This confirms control of the Auth0 login at a high level of confidence. It does not prove the user's real-world identity.

## How It Works

1. The user opens the Sign-In Check URL, for example `https://verify.example.com`.
2. They select **Sign in**.
3. The Worker redirects them to Auth0 and requires a fresh login.
4. Auth0 redirects back to the Worker after the login succeeds.
5. The Worker validates the Auth0 ID token and shows the user a short confirmation code.
6. Support enters the user's Auth0 ID and confirmation code at `/confirm`.
7. The Worker says whether the code matches that Auth0 ID.

The confirmation code is based on the Auth0 `sub` value and a 24-hour time bucket. Support can verify codes from the current and previous 24-hour bucket so there is some tolerance around timing.

## Project Shape

- `src/index.ts`: the Worker, Auth0 callback handling, support code generation, and minimal HTML pages.
- `test/index.test.ts`: unit tests for support code generation and route behaviour.
- `wrangler.example.jsonc`: example Cloudflare Worker configuration.
- `.dev.vars.example`: example local development secrets.

The Worker is stateless. It does not use KV, R2, D1, Durable Objects, Queues, or any database.

## Cloudflare Setup

Copy `wrangler.example.jsonc` to `wrangler.jsonc` for each Cloudflare account or deployment target:

```bash
cp wrangler.example.jsonc wrangler.jsonc
```

Update the client-specific values in `wrangler.jsonc`:

- `name`: the Worker name in that Cloudflare account.
- `routes[0].pattern`: the hostname that should serve this Worker, for example `verify.example.com`.
- `routes[0].custom_domain`: keep this as `true` when the Worker owns the full hostname.

Do not put Auth0 values, client secrets, HMAC secrets, or cookie secrets in `wrangler.jsonc`. Cloudflare treats secrets as encrypted Worker bindings, and this project declares the required secret names in the Wrangler config.

If you change Worker bindings or the Wrangler config shape, run:

```bash
npx wrangler types
```

## Required Cloudflare Secrets

Set these secrets for each Cloudflare account or environment:

```bash
npx wrangler secret put AUTH0_DOMAIN
npx wrangler secret put AUTH0_CLIENT_ID
npx wrangler secret put AUTH0_CLIENT_SECRET
```

Generate separate random values for the support-code HMAC secret and the OAuth state cookie secret:

```bash
node -e "console.log('HASH_SECRET example: ' + require('crypto').randomBytes(32).toString('base64url'))"
npx wrangler secret put HASH_SECRET

node -e "console.log('COOKIE_SECRET example: ' + require('crypto').randomBytes(32).toString('base64url'))"
npx wrangler secret put COOKIE_SECRET
```

Secret meanings:

- `AUTH0_DOMAIN`: Auth0 tenant domain, for example `example-region.auth0.com`.
- `AUTH0_CLIENT_ID`: Auth0 application client ID.
- `AUTH0_CLIENT_SECRET`: Auth0 application client secret.
- `HASH_SECRET`: secret key used to generate support confirmation codes.
- `COOKIE_SECRET`: secret key used to sign the temporary OAuth state cookie.
- `CALLBACK_URL`: optional override for the callback URL.

`CALLBACK_URL` is usually not needed. If it is not configured, the Worker derives it from the request origin, for example `https://verify.example.com/callback`. If a deployment needs an explicit callback URL, set it as a secret:

```bash
npx wrangler secret put CALLBACK_URL
```

## Auth0 Setup

Create or configure an Auth0 application for the deployed Sign-In Check hostname.

For a deployed domain like `https://verify.example.com`, configure:

- Allowed Callback URLs: `https://verify.example.com/callback`
- Application Login URI: `https://verify.example.com/login`
- Allowed Logout URLs: `https://verify.example.com/`
- Allowed Web Origins: `https://verify.example.com`
- Token Endpoint Authentication Method: `Client Secret Post`

The Worker requests the `openid` scope and validates the returned ID token. It also sends `max_age=0` so Auth0 requires a fresh login instead of silently reusing an old session.

## Local Development

Install dependencies:

```bash
npm install
```

Copy the local secret template:

```bash
cp .dev.vars.example .dev.vars
```

Fill in `.dev.vars` with local-only Auth0 values and random local secrets. `.dev.vars` is ignored by git and must not be committed.

Start the Worker locally:

```bash
npm run dev
```

The local Worker will usually run at `http://localhost:8787`. For an end-to-end local Auth0 test, add the matching local callback URL to the Auth0 application, for example `http://localhost:8787/callback`.

## Test And Deploy

Run tests and type checking before deploying:

```bash
npm test
npm run typecheck
```

Deploy with Wrangler:

```bash
npx wrangler deploy
```

## Support Workflow

Support needs two values:

- the user's Auth0 ID, also called the Auth0 `sub`;
- the confirmation code shown to the user after they sign in.

To verify a user:

1. Ask the user to open the Sign-In Check URL and sign in.
2. Ask them to read or send the confirmation code shown by the app.
3. Open `/confirm` on the same deployment.
4. Enter the Auth0 ID and the confirmation code.
5. Continue the support process only if the app returns **Confirmed**.

The confirmation page does not echo the Auth0 ID or submitted code back into the page.

## Security Notes

- The Worker stores no user records, login records, tokens, or confirmation codes.
- Auth0 tenant values and app secrets are Cloudflare secrets, not plaintext Wrangler config values.
- The temporary OAuth state cookie is signed, `HttpOnly`, `Secure`, `SameSite=Lax`, and expires after 10 minutes.
- ID tokens are verified against the Auth0 issuer, audience, nonce, and recent `auth_time`.
- Pages use `Cache-Control: no-store` and `X-Robots-Tag: noindex`.
- The Worker does not call `console.log`.
- Confirmation codes are generated with HMAC-SHA-256 over the Auth0 `sub` and a 24-hour time bucket.
- `/confirm` accepts the current and previous 24-hour buckets.

## References

- [Cloudflare Workers docs](https://developers.cloudflare.com/workers/)
- [Cloudflare Workers secrets](https://developers.cloudflare.com/workers/configuration/secrets/)
- [Cloudflare Workers custom domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/)
- [Cloudflare Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
