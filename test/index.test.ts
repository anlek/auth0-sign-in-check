import { afterEach, describe, expect, it, vi } from "vitest";

import worker, {
	createSupportCode,
	getAcceptedSupportCodes,
	type Env,
} from "../src/index";

const env: Env = {
	AUTH0_DOMAIN: "tenant.example.auth0.com",
	AUTH0_CLIENT_ID: "test-client-id",
	AUTH0_CLIENT_SECRET: "client-secret",
	CALLBACK_URL: "https://verify.example.com/callback",
	HASH_SECRET: "hash-secret",
	COOKIE_SECRET: "cookie-secret",
};

afterEach(() => {
	vi.restoreAllMocks();
});

describe("support confirmation codes", () => {
	it("creates an 8 character Crockford Base32 code grouped as ABCD-1234", async () => {
		const code = await createSupportCode("auth0|abc123", "hash-secret", Date.UTC(2026, 4, 6, 19, 54, 0));

		expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
	});

	it("accepts current and previous 24-hour buckets for support verification", async () => {
		const now = Date.UTC(2026, 4, 6, 19, 54, 0);

		const accepted = await getAcceptedSupportCodes("auth0|abc123", "hash-secret", now);
		const current = await createSupportCode("auth0|abc123", "hash-secret", now);
		const previous = await createSupportCode("auth0|abc123", "hash-secret", now - 24 * 60 * 60 * 1000);

		expect(accepted).toEqual([current, previous]);
	});
});

describe("routes", () => {
	it("adds strong no-store headers to the home page", async () => {
		const response = await worker.fetch(new Request("https://verify.example.com/"), env);

		expect(response.status).toBe(200);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(response.headers.get("X-Robots-Tag")).toBe("noindex");
		expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
	});

	it("redirects /login to Auth0 with max_age=0 and a signed HttpOnly state cookie", async () => {
		vi.spyOn(crypto, "getRandomValues").mockImplementation((array) => {
			const bytes = array as Uint8Array;
			bytes.fill(7);
			return array;
		});

		const response = await worker.fetch(new Request("https://verify.example.com/login"), env);
		const location = response.headers.get("Location");
		const cookie = response.headers.get("Set-Cookie");

		expect(response.status).toBe(302);
		expect(location).not.toBeNull();

		const redirect = new URL(location!);
		expect(redirect.origin).toBe("https://tenant.example.auth0.com");
		expect(redirect.pathname).toBe("/authorize");
		expect(redirect.searchParams.get("response_type")).toBe("code");
		expect(redirect.searchParams.get("client_id")).toBe(env.AUTH0_CLIENT_ID);
		expect(redirect.searchParams.get("redirect_uri")).toBe(env.CALLBACK_URL);
		expect(redirect.searchParams.get("scope")).toBe("openid");
		expect(redirect.searchParams.get("max_age")).toBe("0");
		expect(redirect.searchParams.get("state")).toBeTruthy();
		expect(redirect.searchParams.get("nonce")).toBeTruthy();

		expect(cookie).toContain("__Host-auth0_login=");
		expect(cookie).toContain("HttpOnly");
		expect(cookie).toContain("Secure");
		expect(cookie).toContain("SameSite=Lax");
		expect(cookie).toContain("Path=/");
	});

	it("derives the callback URL from the request origin when no override is configured", async () => {
		const portableEnv = { ...env, CALLBACK_URL: undefined };

		const response = await worker.fetch(new Request("https://client.example.com/login"), portableEnv);
		const redirect = new URL(response.headers.get("Location")!);

		expect(redirect.searchParams.get("redirect_uri")).toBe("https://client.example.com/callback");
	});

	it("clears the OAuth cookie if callback token exchange fails", async () => {
		vi.spyOn(crypto, "getRandomValues").mockImplementation((array) => {
			const bytes = array as Uint8Array;
			bytes.fill(9);
			return array;
		});
		vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("bad", { status: 500 }));

		const login = await worker.fetch(new Request("https://verify.example.com/login"), env);
		const state = new URL(login.headers.get("Location")!).searchParams.get("state");
		const cookie = login.headers.get("Set-Cookie")!.split(";")[0];

		const callback = await worker.fetch(
			new Request(`https://verify.example.com/callback?code=test-code&state=${state}`, {
				headers: { Cookie: cookie },
			}),
			env,
		);

		expect(callback.status).toBe(400);
		expect(callback.headers.get("Set-Cookie")).toContain("__Host-auth0_login=; Max-Age=0");
	});

	it("serves a no-store support confirmation form", async () => {
		const response = await worker.fetch(new Request("https://verify.example.com/confirm"), env);
		const html = await response.text();

		expect(response.status).toBe(200);
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(response.headers.get("Content-Security-Policy")).toContain("form-action 'self'");
		expect(html).toContain('name="auth0_id"');
		expect(html).toContain('name="auth0_id" autocomplete="off" spellcheck="false" required autofocus');
		expect(html).toContain('name="confirmation_code"');
	});

	it("confirms when submitted code matches the Auth0 ID current bucket", async () => {
		const now = Date.UTC(2026, 4, 6, 19, 54, 0);
		vi.setSystemTime(now);
		const code = await createSupportCode("auth0|abc123", env.HASH_SECRET, now);

		const response = await worker.fetch(
			new Request("https://verify.example.com/confirm", {
				method: "POST",
				body: new URLSearchParams({
					auth0_id: "auth0|abc123",
					confirmation_code: code.toLowerCase().replace("-", " "),
				}),
			}),
			env,
		);
		const html = await response.text();

		expect(response.status).toBe(200);
		expect(html).toContain('<h1 class="result result--confirmed">Confirmed</h1>');
		expect(html).not.toContain("auth0|abc123");
		expect(html).not.toContain(code);
	});

	it("confirms when submitted code matches the previous 24-hour bucket", async () => {
		const now = Date.UTC(2026, 4, 6, 19, 54, 0);
		vi.setSystemTime(now);
		const previous = await createSupportCode("auth0|abc123", env.HASH_SECRET, now - 24 * 60 * 60 * 1000);

		const response = await worker.fetch(
			new Request("https://verify.example.com/confirm", {
				method: "POST",
				body: new URLSearchParams({
					auth0_id: "auth0|abc123",
					confirmation_code: previous,
				}),
			}),
			env,
		);
		const html = await response.text();

		expect(response.status).toBe(200);
		expect(html).toContain("Confirmed");
	});

	it("denies when submitted code does not match the Auth0 ID", async () => {
		vi.setSystemTime(Date.UTC(2026, 4, 6, 19, 54, 0));

		const response = await worker.fetch(
			new Request("https://verify.example.com/confirm", {
				method: "POST",
				body: new URLSearchParams({
					auth0_id: "auth0|abc123",
					confirmation_code: "ABCD-1234",
				}),
			}),
			env,
		);
		const html = await response.text();

		expect(response.status).toBe(200);
		expect(html).toContain('<h1 class="result result--denied">Denied</h1>');
		expect(html).not.toContain("auth0|abc123");
	});
});
