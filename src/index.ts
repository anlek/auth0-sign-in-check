import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface Env {
	AUTH0_DOMAIN: string;
	AUTH0_CLIENT_ID: string;
	AUTH0_CLIENT_SECRET: string;
	CALLBACK_URL?: string;
	HASH_SECRET: string;
	COOKIE_SECRET: string;
}

interface OAuthCookiePayload {
	state: string;
	nonce: string;
	iat: number;
}

const OAUTH_COOKIE_NAME = "__Host-auth0_login";
const STATE_MAX_AGE_SECONDS = 10 * 60;
const CODE_BUCKET_MS = 24 * 60 * 60 * 1000;
const AUTH_TIME_MAX_AGE_SECONDS = 10 * 60;
const AUTH0_SCOPE = "openid";
const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const jsonWebKeySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		try {
			return await handleRequest(request, env);
		} catch {
			return htmlResponse("Unable to complete verification", errorPage("Unable to complete verification."), 500);
		}
	},
} satisfies ExportedHandler<Env>;

export async function handleRequest(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);

	if (url.pathname === "/confirm") {
		if (request.method === "GET") {
			return htmlResponse("Confirm support code", confirmFormPage());
		}
		if (request.method === "POST") {
			return handleConfirm(request, env);
		}
		return textResponse("Method not allowed", 405, { Allow: "GET, POST" });
	}

	if (request.method !== "GET") {
		return textResponse("Method not allowed", 405, { Allow: "GET" });
	}

	switch (url.pathname) {
		case "/":
			return htmlResponse("Verify login", homePage());
		case "/login":
			return redirectToLogin(request, env);
		case "/callback":
			return handleCallback(request, env);
		default:
			return htmlResponse("Not found", errorPage("Not found."), 404);
	}
}

async function handleConfirm(request: Request, env: Env): Promise<Response> {
	const form = await request.formData();
	const auth0Id = getFormString(form, "auth0_id").trim();
	const submittedCode = normalizeConfirmationCode(getFormString(form, "confirmation_code"));

	if (!auth0Id || !submittedCode) {
		return htmlResponse("Confirmation denied", confirmResultPage(false));
	}

	const acceptedCodes = await getAcceptedSupportCodes(auth0Id, env.HASH_SECRET);
	const confirmed = acceptedCodes.some((acceptedCode) => constantTimeEqual(normalizeConfirmationCode(acceptedCode), submittedCode));

	return htmlResponse(confirmed ? "Confirmation accepted" : "Confirmation denied", confirmResultPage(confirmed));
}

async function redirectToLogin(request: Request, env: Env): Promise<Response> {
	const state = randomBase64Url(32);
	const nonce = randomBase64Url(32);
	const issuedAt = nowSeconds();
	const cookie = await signOAuthCookie({ state, nonce, iat: issuedAt }, env.COOKIE_SECRET);
	const callbackUrl = getCallbackUrl(request, env);

	const authorizeUrl = new URL(`https://${env.AUTH0_DOMAIN}/authorize`);
	authorizeUrl.searchParams.set("response_type", "code");
	authorizeUrl.searchParams.set("client_id", env.AUTH0_CLIENT_ID);
	authorizeUrl.searchParams.set("redirect_uri", callbackUrl);
	authorizeUrl.searchParams.set("scope", AUTH0_SCOPE);
	authorizeUrl.searchParams.set("state", state);
	authorizeUrl.searchParams.set("nonce", nonce);
	authorizeUrl.searchParams.set("max_age", "0");

	return new Response(null, {
		status: 302,
		headers: secureHeaders({
			Location: authorizeUrl.toString(),
			"Set-Cookie": serializeOAuthCookie(cookie),
		}),
	});
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
	const url = new URL(request.url);
	const clearCookie = clearOAuthCookieHeader();

	if (url.searchParams.has("error")) {
		return htmlResponse("Verification failed", errorPage("Login was not completed."), 400, {
			"Set-Cookie": clearCookie,
		});
	}

	const code = url.searchParams.get("code");
	const state = url.searchParams.get("state");
	if (!code || !state) {
		return htmlResponse("Verification failed", errorPage("Missing authorization response."), 400, {
			"Set-Cookie": clearCookie,
		});
	}

	const cookie = await readOAuthCookie(request, env.COOKIE_SECRET);
	if (!cookie || cookie.state !== state || nowSeconds() - cookie.iat > STATE_MAX_AGE_SECONDS) {
		return htmlResponse("Verification failed", errorPage("Login state expired or did not match."), 400, {
			"Set-Cookie": clearCookie,
		});
	}

	let sub: string | undefined;
	try {
		const idToken = await exchangeAuthorizationCode(code, getCallbackUrl(request, env), env);
		const payload = await verifyIdToken(idToken, env, cookie.nonce);
		sub = payload.sub;
	} catch {
		return htmlResponse("Verification failed", errorPage("Unable to verify login."), 400, {
			"Set-Cookie": clearCookie,
		});
	}

	if (!sub) {
		return htmlResponse("Verification failed", errorPage("Login token was missing a subject."), 400, {
			"Set-Cookie": clearCookie,
		});
	}
	const codeForUser = await createSupportCode(sub, env.HASH_SECRET);

	return htmlResponse("Verification code", codePage(codeForUser), 200, {
		"Set-Cookie": clearCookie,
	});
}

async function exchangeAuthorizationCode(code: string, callbackUrl: string, env: Env): Promise<string> {
	const tokenUrl = `https://${env.AUTH0_DOMAIN}/oauth/token`;
	const body = new URLSearchParams({
		grant_type: "authorization_code",
		client_id: env.AUTH0_CLIENT_ID,
		client_secret: env.AUTH0_CLIENT_SECRET,
		code,
		redirect_uri: callbackUrl,
	});

	const response = await fetch(tokenUrl, {
		method: "POST",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded",
			Accept: "application/json",
		},
		body,
	});

	if (!response.ok) {
		throw new Error("Auth0 token exchange failed");
	}

	const tokenResponse = await response.json<TokenResponse>();
	if (typeof tokenResponse.id_token !== "string") {
		throw new Error("Auth0 token response missing ID token");
	}

	return tokenResponse.id_token;
}

interface TokenResponse {
	id_token?: unknown;
}

async function verifyIdToken(idToken: string, env: Env, expectedNonce: string): Promise<JWTPayload> {
	const issuer = `https://${env.AUTH0_DOMAIN}/`;
	const jwks = getJwks(env.AUTH0_DOMAIN);
	const { payload } = await jwtVerify(idToken, jwks, {
		issuer,
		audience: env.AUTH0_CLIENT_ID,
		clockTolerance: "60s",
	});

	if (payload.nonce !== expectedNonce) {
		throw new Error("ID token nonce mismatch");
	}

	if (typeof payload.auth_time !== "number") {
		throw new Error("ID token missing auth_time");
	}

	const currentTime = nowSeconds();
	if (payload.auth_time > currentTime + 60 || currentTime - payload.auth_time > AUTH_TIME_MAX_AGE_SECONDS) {
		throw new Error("ID token auth_time outside allowed window");
	}

	return payload;
}

function getJwks(domain: string): ReturnType<typeof createRemoteJWKSet> {
	const existing = jsonWebKeySets.get(domain);
	if (existing) {
		return existing;
	}

	const jwks = createRemoteJWKSet(new URL(`https://${domain}/.well-known/jwks.json`));
	jsonWebKeySets.set(domain, jwks);
	return jwks;
}

function getCallbackUrl(request: Request, env: Env): string {
	if (env.CALLBACK_URL) {
		return env.CALLBACK_URL;
	}

	const url = new URL(request.url);
	url.pathname = "/callback";
	url.search = "";
	url.hash = "";
	return url.toString();
}

export async function createSupportCode(sub: string, secret: string, timeMs = Date.now()): Promise<string> {
	const bucket = Math.floor(timeMs / CODE_BUCKET_MS);
	const input = `${sub}.${bucket}`;
	const digest = await hmacSha256(secret, input);
	const rawCode = crockfordBase32(digest).slice(0, 8);

	return `${rawCode.slice(0, 4)}-${rawCode.slice(4)}`;
}

export async function getAcceptedSupportCodes(sub: string, secret: string, timeMs = Date.now()): Promise<[string, string]> {
	const currentBucketStart = Math.floor(timeMs / CODE_BUCKET_MS) * CODE_BUCKET_MS;
	const current = await createSupportCode(sub, secret, currentBucketStart);
	const previous = await createSupportCode(sub, secret, currentBucketStart - CODE_BUCKET_MS);

	return [current, previous];
}

async function signOAuthCookie(payload: OAuthCookiePayload, secret: string): Promise<string> {
	const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
	const signature = await hmacSha256(secret, encodedPayload);

	return `${encodedPayload}.${base64UrlEncode(signature)}`;
}

async function readOAuthCookie(request: Request, secret: string): Promise<OAuthCookiePayload | null> {
	const cookieValue = parseCookies(request.headers.get("Cookie")).get(OAUTH_COOKIE_NAME);
	if (!cookieValue) {
		return null;
	}

	const [encodedPayload, encodedSignature] = cookieValue.split(".");
	if (!encodedPayload || !encodedSignature) {
		return null;
	}

	const expectedSignature = base64UrlEncode(await hmacSha256(secret, encodedPayload));
	if (!constantTimeEqual(encodedSignature, expectedSignature)) {
		return null;
	}

	try {
		const payload = JSON.parse(decoder.decode(base64UrlDecode(encodedPayload))) as Partial<OAuthCookiePayload>;
		if (typeof payload.state !== "string" || typeof payload.nonce !== "string" || typeof payload.iat !== "number") {
			return null;
		}

		return { state: payload.state, nonce: payload.nonce, iat: payload.iat };
	} catch {
		return null;
	}
}

function parseCookies(header: string | null): Map<string, string> {
	const cookies = new Map<string, string>();
	if (!header) {
		return cookies;
	}

	for (const cookie of header.split(";")) {
		const separatorIndex = cookie.indexOf("=");
		if (separatorIndex === -1) {
			continue;
		}

		const name = cookie.slice(0, separatorIndex).trim();
		const value = cookie.slice(separatorIndex + 1).trim();
		if (name) {
			cookies.set(name, value);
		}
	}

	return cookies;
}

function serializeOAuthCookie(value: string): string {
	return `${OAUTH_COOKIE_NAME}=${value}; Max-Age=${STATE_MAX_AGE_SECONDS}; HttpOnly; Secure; SameSite=Lax; Path=/`;
}

function clearOAuthCookieHeader(): string {
	return `${OAUTH_COOKIE_NAME}=; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/`;
}

function htmlResponse(title: string, body: string, status = 200, extraHeaders: HeadersInit = {}): Response {
	return new Response(page(title, body), {
		status,
		headers: secureHeaders({
			"Content-Type": "text/html; charset=UTF-8",
			...extraHeaders,
		}),
	});
}

function textResponse(body: string, status: number, extraHeaders: HeadersInit = {}): Response {
	return new Response(body, {
		status,
		headers: secureHeaders({
			"Content-Type": "text/plain; charset=UTF-8",
			...extraHeaders,
		}),
	});
}

function secureHeaders(extraHeaders: HeadersInit = {}): Headers {
	const headers = new Headers(extraHeaders);
	headers.set("Cache-Control", "no-store");
	headers.set("X-Robots-Tag", "noindex");
	headers.set("Referrer-Policy", "no-referrer");
	headers.set("X-Content-Type-Options", "nosniff");
	headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
	headers.set(
		"Content-Security-Policy",
		"default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; style-src 'unsafe-inline'",
	);

	return headers;
}

function page(title: string, body: string): string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
:root {
  color-scheme: dark;
  --text: #fff;
  --muted: #f1f1f1;
  --surface: #111;
  --field-surface: #2f2f2f;
  --field-border: #9a9a9a;
  --field-border-active: #d4ecef;
  --focus: #f2a900;
  --button: #00616d;
  --button-hover: #00454e;
  --confirmed: #89d185;
  --denied: #ff8d8d;
  --font-heading: "Montserrat", Arial, Helvetica, sans-serif;
  --font-body: "Nunito Sans", Arial, Helvetica, sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--surface); color: var(--text); font-family: var(--font-body); }
main { width: min(100% - 32px, 480px); padding-block: 20px; }
h1 { font-family: var(--font-heading); font-size: clamp(1.6rem, 4vw, 2rem); line-height: 1.2; margin: 0 0 18px; }
p { line-height: 1.5; margin: 0 0 24px; }
a, button, .code { border-radius: 4px; }
a { color: var(--button); font-weight: 700; text-underline-offset: 0.18em; }
a:hover { color: var(--button-hover); }
form { display: grid; gap: 14px; }
.field { display: grid; gap: 5px; }
label { color: var(--muted); font-weight: 700; line-height: 1.35; }
input { width: 100%; min-height: 40px; border: 2px solid var(--field-border); border-radius: 4px; padding: 7px 10px; background: var(--field-surface); color: var(--text); font: inherit; }
input:focus { border-color: var(--field-border-active); outline: 3px solid var(--focus); outline-offset: 2px; }
button { justify-self: start; min-height: 40px; border: 2px solid var(--button); background: var(--button); color: #fff; padding: 8px 18px; font: inherit; font-weight: 700; cursor: pointer; }
button:hover { border-color: var(--button-hover); background: var(--button-hover); }
button:focus-visible, a:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.code { display: inline-block; border: 2px solid #d8d8d8; padding: 16px 20px; font-size: clamp(2rem, 8vw, 3.5rem); letter-spacing: 0; font-weight: 800; font-variant-numeric: tabular-nums; }
.result--confirmed { color: var(--confirmed); }
.result--denied { color: var(--denied); }
</style>
</head>
<body>
<main>${body}</main>
</body>
</html>`;
}

function homePage(): string {
	return `<h1>Verify login</h1><p>Sign in to generate a short support confirmation code.</p><a href="/login">Sign in</a>`;
}

function codePage(code: string): string {
	return `<h1>Confirmation code</h1><p class="code" aria-label="Confirmation code">${escapeHtml(code)}</p>`;
}

function confirmFormPage(): string {
	return `<h1>Confirm support code</h1><form method="post" action="/confirm"><div class="field"><label for="auth0_id">Auth0 ID</label><input id="auth0_id" name="auth0_id" autocomplete="off" spellcheck="false" required autofocus></div><div class="field"><label for="confirmation_code">Confirmation code</label><input id="confirmation_code" name="confirmation_code" inputmode="text" autocomplete="off" spellcheck="false" required></div><button type="submit">Submit</button></form>`;
}

function confirmResultPage(confirmed: boolean): string {
	const result = confirmed ? "Confirmed" : "Denied";
	const message = confirmed ? "The confirmation code matches this Auth0 ID." : "The confirmation code does not match this Auth0 ID.";
	const resultClass = confirmed ? "result--confirmed" : "result--denied";

	return `<h1 class="result ${resultClass}">${result}</h1><p>${message}</p><a href="/confirm">Check another code</a>`;
}

function errorPage(message: string): string {
	return `<h1>Verification failed</h1><p>${escapeHtml(message)}</p><a href="/login">Try again</a>`;
}

async function hmacSha256(secret: string, input: string): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(input));

	return new Uint8Array(signature);
}

function crockfordBase32(bytes: Uint8Array): string {
	let output = "";
	let value = 0;
	let bits = 0;

	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;

		while (bits >= 5) {
			output += CROCKFORD_ALPHABET[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}

	if (bits > 0) {
		output += CROCKFORD_ALPHABET[(value << (5 - bits)) & 31];
	}

	return output;
}

function randomBase64Url(byteLength: number): string {
	const bytes = new Uint8Array(byteLength);
	crypto.getRandomValues(bytes);
	return base64UrlEncode(bytes);
}

function base64UrlEncode(bytes: Uint8Array): string {
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}

	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlDecode(value: string): Uint8Array {
	const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
	const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);

	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}

	return bytes;
}

function constantTimeEqual(left: string, right: string): boolean {
	const leftBytes = encoder.encode(left);
	const rightBytes = encoder.encode(right);
	let difference = leftBytes.length ^ rightBytes.length;
	const length = Math.max(leftBytes.length, rightBytes.length);

	for (let index = 0; index < length; index += 1) {
		difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
	}

	return difference === 0;
}

function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}

function nowSeconds(): number {
	return Math.floor(Date.now() / 1000);
}

function getFormString(form: FormData, name: string): string {
	const value = form.get(name);
	return typeof value === "string" ? value : "";
}

function normalizeConfirmationCode(value: string): string {
	return value.toUpperCase().replaceAll(/[^0-9A-Z]/g, "");
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
