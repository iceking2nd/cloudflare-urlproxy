import { env, SELF, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import worker from "../src/index";
import { setFtpConnectorForTesting } from "../src/ftp";
import { installFtpFakes } from "./ftp-helpers";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

const TOKEN = "unit-test-token";
const PROXY_ORIGIN = "https://proxy.example.com";

// wrangler types 会把 vars 值字面量化为 `""`, 测试注入任意运行时字符串时需要断言回 Env
// wrangler types literalizes vars values as `""`; tests inject arbitrary runtime strings, so cast back to Env
const TEST_ENV = { ...env, PROXY_TOKEN: TOKEN, ALLOWED_ORIGINS: "" } as unknown as Env;

// ---------------------------------------------------------------------------
// 出站 fetch mock: unit 风格测试与被测 worker 运行在同一 isolate,
// 直接替换 globalThis.fetch 即可拦截 worker 发出的子请求。
// outbound fetch mock: unit-style tests run in the same isolate as the worker under test,
// so replacing globalThis.fetch intercepts the subrequests the worker makes.
// ---------------------------------------------------------------------------
type BackendHandler = (req: Request) => Response;
let backendHandler: BackendHandler | null = null;
let outboundRequests: Request[] = [];
const realFetch = globalThis.fetch;

beforeEach(() => {
	backendHandler = null;
	outboundRequests = [];
	globalThis.fetch = ((input: unknown, init?: RequestInit) => {
		const req = input instanceof Request ? input : new Request(input as string, init);
		outboundRequests.push(req);
		const handler = backendHandler;
		if (!handler) throw new Error(`unexpected outbound fetch: ${req.method} ${req.url}`);
		return Promise.resolve(handler(req));
	}) as typeof fetch;
});

afterEach(() => {
	globalThis.fetch = realFetch;
	setFtpConnectorForTesting(null);
});

function lastOutbound(): Request {
	return outboundRequests[outboundRequests.length - 1];
}

async function callProxy(
	url: string,
	init?: RequestInit<IncomingRequestCfProperties<unknown>>,
	envOverride: Env = TEST_ENV,
): Promise<Response> {
	const request = new IncomingRequest(url, init);
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, envOverride, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

describe("urlproxy worker", () => {
	it("returns 204 for /favicon.ico without a token (integration)", async () => {
		const response = await SELF.fetch("https://proxy.example.com/favicon.ico");
		expect(response.status).toBe(204);
	});

	it("rejects every proxy request when PROXY_TOKEN is not configured (fail-closed)", async () => {
		const emptyEnv = { ...env, PROXY_TOKEN: "", ALLOWED_ORIGINS: "" } as unknown as Env;
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, undefined, emptyEnv);
		expect(response.status).toBe(503);
	});

	it("rejects requests without a token", async () => {
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`);
		expect(response.status).toBe(403);
	});

	it("rejects requests with a wrong token", async () => {
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
			headers: { "x-proxy-token": "wrong-token" },
		});
		expect(response.status).toBe(403);
	});

	// 多 token 配置带空格, 顺带覆盖 trim / the multi-token config carries a space, covering trim as well
	const MULTI_TOKEN_ENV = { ...env, PROXY_TOKEN: "token-alpha, token-beta", ALLOWED_ORIGINS: "" } as unknown as Env;

	it("accepts each of multiple comma-separated tokens via header", async () => {
		backendHandler = () => new Response("ok", { headers: { "content-type": "application/octet-stream" } });
		for (const token of ["token-alpha", "token-beta"]) {
			const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
				headers: { "x-proxy-token": token },
			}, MULTI_TOKEN_ENV);
			expect(response.status).toBe(200);
		}
	});

	it("accepts any configured token via query parameter and still strips it from the destination URL", async () => {
		backendHandler = () => new Response("ok", { headers: { "content-type": "application/octet-stream" } });
		const response = await callProxy(
			`${PROXY_ORIGIN}/https://api.example.com/v1/data?__proxy_token=token-beta`,
			undefined,
			MULTI_TOKEN_ENV,
		);
		expect(response.status).toBe(200);
		expect(lastOutbound().url).toBe("https://api.example.com/v1/data");
	});

	it("rejects a token that is not in the comma-separated list", async () => {
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
			headers: { "x-proxy-token": "token-gamma" },
		}, MULTI_TOKEN_ENV);
		expect(response.status).toBe(403);
	});

	it("does not accept the raw comma-joined config string as a single token", async () => {
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
			headers: { "x-proxy-token": "token-alpha, token-beta" },
		}, MULTI_TOKEN_ENV);
		expect(response.status).toBe(403);
	});

	it("does not let an empty segment of a multi-token config accept an empty token", async () => {
		const gapEnv = { ...env, PROXY_TOKEN: "token-alpha,,token-beta", ALLOWED_ORIGINS: "" } as unknown as Env;
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
			headers: { "x-proxy-token": "" },
		}, gapEnv);
		expect(response.status).toBe(403);
	});

	it("treats a whitespace-and-comma-only PROXY_TOKEN as unconfigured (fail-closed)", async () => {
		const blankEnv = { ...env, PROXY_TOKEN: " , , ", ALLOWED_ORIGINS: "" } as unknown as Env;
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, undefined, blankEnv);
		expect(response.status).toBe(503);
	});

	it("forwards to the destination with a valid header token, stripping cookies and the token itself", async () => {
		backendHandler = () => new Response("ok", { headers: { "content-type": "application/octet-stream" } });
		const response = await callProxy(`${PROXY_ORIGIN}/https://api.example.com/v1/data?x=1`, {
			headers: {
				"x-proxy-token": TOKEN,
				cookie: "session=leak-me",
				authorization: "Bearer dst-token",
			},
		});
		expect(response.status).toBe(200);
		expect(new TextDecoder().decode(await response.arrayBuffer())).toBe("ok");
		expect(outboundRequests).toHaveLength(1);
		const out = lastOutbound();
		expect(out.url).toBe("https://api.example.com/v1/data?x=1");
		expect(out.headers.get("host")).toBe("api.example.com");
		// 安全修复: 代理域 Cookie 与访问令牌不得转发给目标 / security fix: proxy-domain cookies and the access token must not be forwarded
		expect(out.headers.get("cookie")).toBeNull();
		expect(out.headers.get("x-proxy-token")).toBeNull();
		// Authorization 是客户端显式提供的凭证, 保留转发 / Authorization is provided explicitly by the client, keep forwarding it
		expect(out.headers.get("authorization")).toBe("Bearer dst-token");
	});

	it("accepts a token via query parameter and strips it from the destination URL", async () => {
		backendHandler = () => new Response("ok", { headers: { "content-type": "application/octet-stream" } });
		const response = await callProxy(`${PROXY_ORIGIN}/https://api.example.com/v1/data?x=1&__proxy_token=${TOKEN}`);
		expect(response.status).toBe(200);
		expect(lastOutbound().url).toBe("https://api.example.com/v1/data?x=1");
	});

	it("returns 400 when the destination is not an absolute http(s) URL", async () => {
		const response = await callProxy(`${PROXY_ORIGIN}/example.com/foo`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(400);
	});

	it("still returns 400 for unsupported schemes such as ssh://", async () => {
		const response = await callProxy(`${PROXY_ORIGIN}/ssh://example.com/x`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(400);
	});

	it("routes ftp:// destinations through the FTP client with proxy response headers", async () => {
		installFtpFakes(
			[
				"220 ready\r\n",
				"331 pass\r\n",
				"230 ok\r\n",
				"200 type\r\n",
				"250 CWD ok\r\n",
				"229 (|||9998|)\r\n",
				"150 opening\r\n",
				"226 done\r\n",
				"221 bye\r\n",
			],
			[["sub\r\n", "file.txt\r\n"]],
		);
		const response = await callProxy(`${PROXY_ORIGIN}/ftp://files.example.com/pub/`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(200);
		const html = await response.text();
		expect(html).toContain("Index of ftp://files.example.com/pub/");
		// FTP 响应同样经过代理响应头处理 (CSP / no-store) / FTP responses go through the same proxy header pipeline (CSP / no-store)
		expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
		expect(response.headers.get("cache-control")).toBe("no-store");
	});

	it("propagates a query-provided token into FTP directory page links", async () => {
		// 场景: 经 ?__proxy_token= 打开目录页后点击导航, 链接若不带 token 会 403; query token 必须传播进页内所有链接
		// scenario: after opening a directory page via ?__proxy_token=, clicking a link without the token 403s; the query token must propagate into every page link
		installFtpFakes(
			[
				"220 ready\r\n",
				"331 pass\r\n",
				"230 ok\r\n",
				"200 type\r\n",
				"250 CWD ok\r\n",
				"229 (|||9998|)\r\n",
				"150 opening\r\n",
				"226 done\r\n",
				"221 bye\r\n",
			],
			[["sub\r\n", "file.txt\r\n"]],
		);
		const response = await callProxy(`${PROXY_ORIGIN}/ftp://files.example.com/pub/?__proxy_token=${encodeURIComponent(TOKEN)}`);
		expect(response.status).toBe(200);
		const html = await response.text();
		expect(html).toContain(`ftp://files.example.com/pub/file.txt?__proxy_token=${encodeURIComponent(TOKEN)}`);
		// 父目录链接同样携带 / the parent link carries it too
		expect(html).toContain(`href="${PROXY_ORIGIN}/ftp://files.example.com/?__proxy_token=${encodeURIComponent(TOKEN)}`);
	});

	it("keeps FTP directory page links token-free when the token came from the header", async () => {
		// header token: 页面不落 token, 暴露面不扩大 / header token: the page carries no token, so the exposure surface does not grow
		installFtpFakes(
			[
				"220 ready\r\n",
				"331 pass\r\n",
				"230 ok\r\n",
				"200 type\r\n",
				"250 CWD ok\r\n",
				"229 (|||9998|)\r\n",
				"150 opening\r\n",
				"226 done\r\n",
				"221 bye\r\n",
			],
			[["sub\r\n"]],
		);
		const response = await callProxy(`${PROXY_ORIGIN}/ftp://files.example.com/pub/`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(200);
		expect(await response.text()).not.toContain("__proxy_token");
	});

	it("returns 400 for proxy loop destinations (destination host equals proxy host)", async () => {
		const response = await callProxy(`${PROXY_ORIGIN}/https://proxy.example.com/anything`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(400);
	});

	it("passes bodies through unmodified in /~~/ original mode and strips Set-Cookie", async () => {
		const body = '<a href="https://example.com/page">link</a>';
		backendHandler = () =>
			new Response(body, {
				headers: {
					"content-type": "text/html",
					"set-cookie": "session=evil; Path=/",
					"content-security-policy": "script-src 'self'",
				},
			});
		const response = await callProxy(`${PROXY_ORIGIN}/~~/https://example.com/page`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(200);
		// 原样直通, body 不被改写 / original passthrough, body untouched
		expect(await response.text()).toBe(body);
		// 安全修复: 不透传目标的 Set-Cookie, 避免多目标共享代理域 cookie jar / security fix: no Set-Cookie passthrough, so targets never share the proxy-domain cookie jar
		expect(response.headers.get("set-cookie")).toBeNull();
		// CSP 始终替换为受限版本 (frame-ancestors 是本代理 CSP 模板的特有指令) / the restrictive CSP is always applied (frame-ancestors is unique to this proxy's CSP template)
		expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
		expect(response.headers.get("cache-control")).toBe("no-store");
	});

	it("rewrites absolute, path-relative and protocol-relative URLs, stripping stale encoding headers", async () => {
		const body = 'src="https://cdn.example.com/a.js" href="/x" alt="//proto.example.com/y"';
		backendHandler = () =>
			new Response(body, {
				headers: {
					"content-type": "text/html",
					"content-encoding": "gzip",
					"content-length": "999",
				},
			});
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/page`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(200);
		expect(await response.text()).toBe(
			'src="https://proxy.example.com/https://cdn.example.com/a.js" ' +
				'href="https://proxy.example.com/https://example.com/x" ' +
				'alt="https://proxy.example.com/https://proto.example.com/y"',
		);
		// 过期的 content-encoding / content-length 不得残留在重写后的响应里 / stale content-encoding / content-length must not survive into the rewritten response
		expect(response.headers.get("content-encoding")).toBeNull();
		expect(response.headers.get("content-length")).toBeNull();
	});

	it("propagates a query-provided token into every rewritten HTML URL", async () => {
		// 场景: query token 打开的页面, 其内嵌子资源与链接经改写后必须继续携带 token, 否则点击/加载全部 403
		// scenario: a page opened with a query token must keep carrying it in rewritten subresource and link URLs, or every click/load 403s
		backendHandler = () =>
			new Response(
				'src="https://cdn.example.com/a.js" href="/x" data-u="//proto.example.com/y" href2="https://example.com/p?q=1" href3="https://example.com/anchor#top"',
				{ headers: { "content-type": "text/html" } },
			);
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/page?__proxy_token=${encodeURIComponent(TOKEN)}`);
		expect(response.status).toBe(200);
		const html = await response.text();
		const tk = encodeURIComponent(TOKEN);
		// 规则 1 (绝对 URL) / rule 1 (absolute URL)
		expect(html).toContain(`src="https://proxy.example.com/https://cdn.example.com/a.js?__proxy_token=${tk}"`);
		// 规则 2 (引号内绝对路径) / rule 2 (quoted absolute path)
		expect(html).toContain(`href="https://proxy.example.com/https://example.com/x?__proxy_token=${tk}"`);
		// 规则 3 (协议相对) / rule 3 (protocol-relative)
		expect(html).toContain(`data-u="https://proxy.example.com/https://proto.example.com/y?__proxy_token=${tk}"`);
		// 已有 query 用 & 合并 / merge with an existing query via &
		expect(html).toContain(`href2="https://proxy.example.com/https://example.com/p?q=1&__proxy_token=${tk}"`);
		// fragment 之前插入 (落入 fragment 的 token 会失效) / insert before the fragment (a token inside the fragment dies)
		expect(html).toContain(`href3="https://proxy.example.com/https://example.com/anchor?__proxy_token=${tk}#top"`);
	});

	it("keeps JSON bodies token-free even with a query-provided token", async () => {
		// 仅 html 注入: JSON/JS/纯文本的 URL 字段不携带 token, 防止凭证进入 API 数据流向下游
		// html-only injection: URL fields in JSON/JS/plain text stay token-free so credentials never flow into downstream API data
		backendHandler = () =>
			new Response('{"url":"https://example.com/x"}', { headers: { "content-type": "application/json" } });
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/api?__proxy_token=${encodeURIComponent(TOKEN)}`);
		expect(response.status).toBe(200);
		const body = await response.text();
		// URL 仍被改写 (现状行为), 但不带 token / the URL is still rewritten (existing behavior), without a token
		expect(body).toContain(`{"url":"https://proxy.example.com/https://example.com/x"}`);
		expect(body).not.toContain("__proxy_token");
	});

	it("keeps content-encoding for pass-through (non-text) responses", async () => {
		backendHandler = () =>
			new Response("binary", {
				headers: { "content-type": "application/octet-stream", "content-encoding": "gzip" },
			});
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/blob`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.headers.get("content-encoding")).toBe("gzip");
	});

	it("does not crash when the backend response has no content-type header", async () => {
		backendHandler = () => new Response("plain");
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/noct`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(200);
		expect(new TextDecoder().decode(await response.arrayBuffer())).toBe("plain");
	});

	it("sets CORS headers only for the proxy origin or the configured allowlist", async () => {
		backendHandler = () => new Response("ok", { headers: { "content-type": "application/octet-stream" } });
		const withOrigin = async (origin: string) =>
			callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
				headers: { "x-proxy-token": TOKEN, origin },
			});
		expect((await withOrigin(PROXY_ORIGIN)).headers.get("access-control-allow-origin")).toBe(PROXY_ORIGIN);
		expect((await withOrigin("https://evil.example.com")).headers.get("access-control-allow-origin")).toBeNull();
		const noOrigin = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(noOrigin.headers.get("access-control-allow-origin")).toBeNull();
	});

	it("always applies a restrictive CSP even when the destination has none", async () => {
		backendHandler = () => new Response("x", { headers: { "content-type": "text/html" } });
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/`, {
			headers: { "x-proxy-token": TOKEN },
		});
		const csp = response.headers.get("content-security-policy");
		expect(csp).toContain("frame-ancestors 'none'");
		expect(csp).toContain("script-src 'unsafe-inline'");
	});

	it("forwards the request method and body", async () => {
		backendHandler = () => new Response("created", { status: 201 });
		const response = await callProxy(`${PROXY_ORIGIN}/https://api.example.com/items`, {
			method: "POST",
			headers: { "x-proxy-token": TOKEN, "content-type": "application/json" },
			body: '{"a":1}',
		});
		expect(response.status).toBe(201);
		const out = lastOutbound();
		expect(out.method).toBe("POST");
		expect(await out.text()).toBe('{"a":1}');
	});

	it("returns 502 when the backend fetch fails", async () => {
		backendHandler = () => {
			throw new Error("connection refused");
		};
		const response = await callProxy(`${PROXY_ORIGIN}/https://example.com/x`, {
			headers: { "x-proxy-token": TOKEN },
		});
		expect(response.status).toBe(502);
	});
});
