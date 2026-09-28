/**
 * 最小 FTP 客户端: 基于 cloudflare:sockets 的 TCP 连接实现 FTP 被动模式传输,
 * 供 src/index.ts 对 ftp:// 目的地址分派使用。
 *
 * 能力范围 (有意取舍):
 *   - 仅明文 FTP, 不支持 FTPS (AUTH TLS 为后续增强)
 *   - 被动模式: 优先 EPSV, 失败回退 PASV (PASV 返回的 IP 一律忽略, 始终用控制连接的主机, 规避 NAT 场景)
 *   - 文件: RETR 二进制流式直通; 目录: NLST 生成 HTML 导航页
 *   - 凭据: 从 ftp://user:pass@host/ 内嵌获取, 默认匿名 (anonymous); 凭据一律不落日志
 *
 * Minimal FTP client: passive-mode transfers over cloudflare:sockets TCP connections,
 * dispatched from src/index.ts for ftp:// destinations.
 *
 * Capabilities (deliberate trade-offs):
 *   - plaintext FTP only, no FTPS (AUTH TLS is a future enhancement)
 *   - passive mode: EPSV first, PASV fallback (the IP returned by PASV is always ignored; always
 *     reconnect to the control-connection host, which sidesteps NAT setups)
 *   - files: streamed binary via RETR; directories: NLST rendered into an HTML navigation page
 *   - credentials: taken from ftp://user:pass@host/ when embedded, anonymous by default; never logged
 */

import { connect } from "cloudflare:sockets";

/** 与 cloudflare:sockets 的 Socket 结构兼容的最小接口, 便于测试注入 / Minimal interface structurally compatible with cloudflare:sockets' Socket, easy to fake in tests */
export interface FtpSocket {
	opened: Promise<unknown>;
	readable: ReadableStream<Uint8Array>;
	writable: WritableStream<Uint8Array>;
	close(): Promise<void> | void;
}

/** 连接器: 控制连接与数据连接的建立入口 / Connector: entry point for control and data connections */
export interface FtpConnector {
	connectControl(hostname: string, port: number): FtpSocket;
	connectData(hostname: string, port: number): FtpSocket;
}

const realConnector: FtpConnector = {
	// 仅明文 FTP; FTPS (AUTH TLS + startTls) 为后续增强 / plaintext FTP only; FTPS (AUTH TLS + startTls) is a future enhancement
	connectControl: (hostname, port) => connect({ hostname, port }),
	connectData: (hostname, port) => connect({ hostname, port }),
};

let activeConnector: FtpConnector = realConnector;

/** 测试注入口: 传入假 connector 替换真实 TCP 连接, 传 null 恢复 / Test hook: pass a fake connector to replace real TCP; pass null to restore */
export function setFtpConnectorForTesting(connector: FtpConnector | null): void {
	activeConnector = connector ?? realConnector;
}

/** FTP 会话错误; httpStatus 为映射给客户端的响应状态码 / FTP session error; httpStatus is the status code mapped for the client */
class FtpError extends Error {
	constructor(
		readonly httpStatus: number,
		message: string,
		readonly ftpCode?: number,
	) {
		super(message);
		this.name = "FtpError";
	}
}

interface FtpResponse {
	code: number;
	text: string;
}

interface FtpSession {
	hostname: string;
	socket: FtpSocket;
	lineReader: FtpLineReader;
	writer: WritableStreamDefaultWriter<Uint8Array>;
	command(cmd: string): Promise<FtpResponse>;
	close(): void;
}

// ---------------------------------------------------------------------------
// 纯函数: 协议解析与 URL 处理 / Pure functions: protocol parsing and URL handling
// ---------------------------------------------------------------------------

/** 解析 FTP 响应行: "230 text" 为末行, "230-text" 为续行, 非法返回 null / Parse an FTP response line: "230 text" is final, "230-text" continues, null when invalid */
export function parseFtpResponseLine(line: string): { code: number; isFinal: boolean } | null {
	const m = /^(\d{3})([- ]?)/.exec(line);
	if (!m) return null;
	return { code: Number(m[1]), isFinal: m[2] !== "-" };
}

/** 从 EPSV 响应中解析数据端口: "229 ... (|||2121|)" -> 2121 / Parse the data port from an EPSV response: "229 ... (|||2121|)" -> 2121 */
export function parseEpsvPort(text: string): number | null {
	const m = /\(\|\|\|(\d+)\|\)/.exec(text);
	if (!m) return null;
	return Number(m[1]);
}

/** 从 PASV 响应中解析数据端口: "227 ... (h,h,h,h,p1,p2)" -> p1*256+p2; 忽略返回的 IP / Parse the data port from a PASV response: "227 ... (h,h,h,h,p1,p2)" -> p1*256+p2; the returned IP is ignored */
export function parsePasvPort(text: string): number | null {
	const m = /\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)/.exec(text);
	if (!m) return null;
	return Number(m[5]) * 256 + Number(m[6]);
}

/** 取 FTP 登录凭据: URL 内嵌 (百分号解码), 缺省为匿名 / Get FTP credentials: URL-embedded (percent-decoded), anonymous by default */
export function ftpCredentials(dstUrl: URL): { user: string; password: string } {
	if (dstUrl.username) {
		return {
			user: decodeURIComponent(dstUrl.username),
			password: dstUrl.password ? decodeURIComponent(dstUrl.password) : "",
		};
	}
	return { user: "anonymous", password: "anonymous@" };
}

/** 剥离 CR/LF, 防止 URL 中的换行注入额外 FTP 命令 / Strip CR/LF so newlines in URLs cannot inject extra FTP commands */
export function sanitizeFtpArg(arg: string): string {
	return arg.replace(/[\r\n]/g, "");
}

/** 日志用: 隐藏 URL 中的密码 / For logs: hide the password inside a URL */
export function redactUrlCredentials(url: URL): string {
	if (!url.username && !url.password) return url.href;
	return `${url.protocol}//${url.username}${url.password ? ":***" : ""}@${url.host}${url.pathname}${url.search}${url.hash}`;
}

const CONTENT_TYPES: Record<string, string> = {
	txt: "text/plain",
	text: "text/plain",
	md: "text/markdown",
	html: "text/html",
	htm: "text/html",
	css: "text/css",
	csv: "text/csv",
	json: "application/json",
	xml: "application/xml",
	js: "text/javascript",
	png: "image/png",
	jpg: "image/jpeg",
	jpeg: "image/jpeg",
	gif: "image/gif",
	svg: "image/svg+xml",
	webp: "image/webp",
	ico: "image/x-icon",
	pdf: "application/pdf",
	zip: "application/zip",
	gz: "application/gzip",
	tar: "application/x-tar",
	mp3: "audio/mpeg",
	ogg: "audio/ogg",
	wav: "audio/wav",
	mp4: "video/mp4",
	webm: "video/webm",
};

/** 按扩展名猜测 content-type, 未识别返回 application/octet-stream / Guess content-type by extension; application/octet-stream when unknown */
export function guessContentType(path: string): string {
	const m = /\.([a-z0-9]+)$/i.exec(path);
	if (!m) return "application/octet-stream";
	return CONTENT_TYPES[m[1].toLowerCase()] ?? "application/octet-stream";
}

function escapeHtml(s: string): string {
	return s.replace(/[&<>"']/g, (c) => {
		switch (c) {
			case "&":
				return "&amp;";
			case "<":
				return "&lt;";
			case ">":
				return "&gt;";
			case '"':
				return "&quot;";
			default:
				return "&#39;";
		}
	});
}

function joinFtpPath(path: string, name: string): string {
	const base = path.endsWith("/") ? path : `${path}/`;
	return base + name;
}

function parentOf(path: string): string {
	const trimmed = path.endsWith("/") ? path.slice(0, -1) : path;
	const idx = trimmed.lastIndexOf("/");
	return idx <= 0 ? "/" : `${trimmed.slice(0, idx)}/`;
}

/**
 * 生成目录导航页: 名字做 HTML 转义, 链接经代理并保留 URL 中已有的编码凭据。
 * tokenQuerySuffix 由 index.ts 在 token 来自 ?__proxy_token= 时构造 (值已 encodeURIComponent), 追加到每个链接
 * 尾部, 让点击导航继续带上 token; header 用户的页面不落 token。
 *
 * Render the directory navigation page: names are HTML-escaped, links go through the proxy and keep the
 * URL's encoded credentials. tokenQuerySuffix is built by index.ts when the token came via ?__proxy_token=
 * (value already encodeURIComponent'd) and is appended to every link so clicked navigations keep carrying
 * the token; header users' pages carry no token.
 */
export function renderDirectoryListing(dstUrl: URL, proxyBase: string, names: string[], tokenQuerySuffix = ""): string {
	const func = "src.ftp.renderDirectoryListing";
	console.debug("rendering directory listing", { func, count: names.length });
	// 链接保留编码凭据以便带凭据继续浏览 (用户自己 URL 中提供的值, 转义防注入)
	// links keep the encoded credentials so credentialed browsing continues (values the user put in their own URL; escaped against injection)
	const credentials = dstUrl.username ? `${dstUrl.username}:${dstUrl.password}@` : "";
	const listingUrl = `ftp://${dstUrl.host}${dstUrl.pathname}`;
	const links: string[] = [];
	if (dstUrl.pathname !== "/" && dstUrl.pathname !== "") {
		const parentHref = `${proxyBase}ftp://${credentials}${dstUrl.host}${parentOf(dstUrl.pathname)}${tokenQuerySuffix}`;
		links.push(`<li><a href="${escapeHtml(parentHref)}">..</a></li>`);
	}
	for (const name of names) {
		if (name === "") continue;
		const href = `${proxyBase}ftp://${credentials}${dstUrl.host}${joinFtpPath(dstUrl.pathname, encodeURIComponent(name))}${tokenQuerySuffix}`;
		links.push(`<li><a href="${escapeHtml(href)}">${escapeHtml(name)}</a></li>`);
	}
	return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Index of ${escapeHtml(listingUrl)}</title></head>
<body>
<h1>Index of ${escapeHtml(listingUrl)}</h1>
<ul>
${links.join("\n")}
</ul>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// 会话实现 / Session implementation
// ---------------------------------------------------------------------------

/** 聚合响应的累计长度上限 (字符数, 含 CRLF), 拦截异常服务器的无限读取 / total-size cap on an aggregated response (chars, CRLF included); stops unbounded reads from a misbehaving server */
const MAX_RESPONSE_CHARS = 64 * 1024;
/** 单行长度上限 (字符数): 无换行的超长流不得无限撑大行缓冲 / per-line cap (chars): an unterminated oversized stream must not balloon the line buffer */
const MAX_LINE_CHARS = 8 * 1024;

/** 流式按行读取: 处理 chunk 半行/多行边界与多字节 UTF-8 边界 / Streaming line reader: handles chunk boundaries (partial/multiple lines) and multi-byte UTF-8 boundaries */
class FtpLineReader {
	private buffer = "";
	private done = false;
	private readonly decoder = new TextDecoder();
	private readonly reader: ReadableStreamDefaultReader<Uint8Array>;

	constructor(stream: ReadableStream<Uint8Array>) {
		this.reader = stream.getReader();
	}

	async readLine(): Promise<string> {
		for (;;) {
			const idx = this.buffer.indexOf("\n");
			if (idx >= 0) {
				const line = this.buffer.slice(0, idx);
				this.buffer = this.buffer.slice(idx + 1);
				return line.replace(/\r$/, "");
			}
			if (this.done) return this.buffer.length > 0 ? this.buffer : "";
			const { value, done } = await this.reader.read();
			if (done) {
				this.done = true;
				continue;
			}
			this.buffer += this.decoder.decode(value, { stream: true });
			// 换行迟迟不出现而行已超限: 拒绝而不是继续累积 / the line is past the cap with no newline in sight: reject instead of buffering on
			if (this.buffer.length > MAX_LINE_CHARS) throw new FtpError(502, "FTP response line too long");
		}
	}
}

/** 读取完整 FTP 响应 (聚合 "xxx-" 续行直到 "xxx " 末行) / Read a complete FTP response (aggregate "xxx-" continuation lines up to the "xxx " final line) */
async function readFtpResponse(lineReader: FtpLineReader): Promise<FtpResponse> {
	const first = await lineReader.readLine();
	const parsed = parseFtpResponseLine(first);
	if (!parsed) {
		throw new FtpError(502, `invalid FTP response: ${JSON.stringify(first)}`);
	}
	if (parsed.isFinal) return { code: parsed.code, text: first };
	const lines = [first];
	let totalChars = first.length + 2;
	for (;;) {
		const line = await lineReader.readLine();
		if (line === "") throw new FtpError(502, "FTP connection closed mid-response");
		totalChars += line.length + 2;
		// 聚合长度上限防御: 行数无限制 (真实横幅可带几十行 ASCII art), 但累计超限仍未终结即拒绝
		// total-size guard: no line-count limit (real banners carry dozens of ASCII-art lines), but an unterminated response past the cap is rejected
		if (totalChars > MAX_RESPONSE_CHARS) throw new FtpError(502, "FTP response too long");
		lines.push(line);
		const p = parseFtpResponseLine(line);
		if (p && p.isFinal && p.code === parsed.code) return { code: parsed.code, text: lines.join("\n") };
	}
}

function ftpCommand(session: FtpSession, cmd: string): Promise<FtpResponse> {
	const encoder = new TextEncoder();
	return session.writer.write(encoder.encode(`${cmd}\r\n`)).then(() => readFtpResponse(session.lineReader));
}

/** 建立控制连接并完成登录与二进制模式设置 / Open the control connection, log in, and switch to binary mode */
async function openControlSession(hostname: string, port: number, creds: { user: string; password: string }): Promise<FtpSession> {
	const func = "src.ftp.openControlSession";
	console.debug("opening FTP control connection", { func, hostname, port });
	const socket = activeConnector.connectControl(hostname, port);
	try {
		await socket.opened;
	} catch (e) {
		console.warn("FTP control connection failed", { func, hostname, port, error: String(e) });
		socket.close();
		throw new FtpError(502, "failed to connect to FTP server");
	}
	const lineReader = new FtpLineReader(socket.readable);
	const writer = socket.writable.getWriter();
	const session: FtpSession = {
		hostname,
		socket,
		lineReader,
		writer,
		command: (cmd: string) => ftpCommand(session, cmd),
		close: () => {
			try {
				writer.releaseLock();
			} catch {
				// 锁已释放, 忽略 / lock already released, ignore
			}
			socket.close();
		},
	};
	try {
		const welcome = await readFtpResponse(lineReader);
		if (welcome.code !== 220) throw new FtpError(502, `unexpected FTP greeting (code ${welcome.code})`, welcome.code);
		const userResp = await session.command(`USER ${sanitizeFtpArg(creds.user)}`);
		if (userResp.code === 331) {
			const passResp = await session.command(`PASS ${sanitizeFtpArg(creds.password)}`);
			if (passResp.code !== 230) throw new FtpError(403, "FTP login failed", passResp.code);
		} else if (userResp.code !== 230) {
			throw new FtpError(403, "FTP login failed", userResp.code);
		}
		const typeResp = await session.command("TYPE I");
		if (typeResp.code >= 400) throw new FtpError(502, "FTP server rejected binary mode", typeResp.code);
	} catch (e) {
		session.close();
		throw e;
	}
	console.debug("FTP session established", { func, hostname });
	return session;
}

/** 协商被动数据端口并建立数据连接 (EPSV 优先, PASV 回退) / Negotiate the passive data port and open the data connection (EPSV first, PASV fallback) */
async function openPassiveData(session: FtpSession): Promise<FtpSocket> {
	const func = "src.ftp.openPassiveData";
	let resp = await session.command("EPSV");
	let port = resp.code === 229 ? parseEpsvPort(resp.text) : null;
	if (port === null) {
		resp = await session.command("PASV");
		port = resp.code === 227 ? parsePasvPort(resp.text) : null;
	}
	if (port === null) throw new FtpError(502, "failed to enter passive mode", resp.code);
	console.debug("passive data port negotiated", { func, port });
	const dataSocket = activeConnector.connectData(session.hostname, port);
	try {
		await dataSocket.opened;
	} catch (e) {
		console.warn("FTP data connection failed", { func, port, error: String(e) });
		dataSocket.close();
		throw new FtpError(502, "failed to open FTP data connection");
	}
	return dataSocket;
}

/** RETR 成功后的后台收尾 (waitUntil 中执行): 等 226, QUIT, 关闭控制连接 / Background finalization after a successful RETR (runs in waitUntil): await 226, QUIT, close the control connection */
async function finalizeTransfer(session: FtpSession): Promise<void> {
	const func = "src.ftp.finalizeTransfer";
	try {
		const done = await readFtpResponse(session.lineReader);
		console.debug("transfer finalized", { func, code: done.code });
	} catch (e) {
		// 客户端中断等场景下可能读不到 226, 容忍并继续收尾 / the 226 may never arrive when the client aborts; tolerate and finalize anyway
		console.debug("no final transfer response", { func, error: String(e) });
	}
	try {
		const bye = await session.command("QUIT");
		console.debug("session closed", { func, code: bye.code });
	} catch (e) {
		console.debug("QUIT failed", { func, error: String(e) });
	}
	session.close();
}

/** 获取目录列表并生成 HTML 导航页 (同步收尾, 不依赖 waitUntil) / Fetch the directory listing and render the HTML navigation page (finalizes synchronously, no waitUntil needed) */
async function listDirectory(session: FtpSession, dstUrl: URL, proxyBase: string, tokenQuerySuffix: string): Promise<Response> {
	const func = "src.ftp.listDirectory";
	const path = dstUrl.pathname || "/";
	// 先 CWD 进目录再发裸 NLST: 带路径参数的 NLST 在老式 ftpd 上会整行返回 "路径/名字", 裸 NLST 才返回纯名 (与 curl 等客户端一致)
	// CWD into the directory first, then a bare NLST: with a path argument older ftpds answer with whole "path/name" lines; only a bare NLST returns plain names (mirroring curl et al.)
	const cwdResp = await session.command(`CWD ${sanitizeFtpArg(path)}`);
	if (cwdResp.code !== 250) {
		throw new FtpError(cwdResp.code === 550 ? 404 : 502, `FTP CWD failed (code ${cwdResp.code})`, cwdResp.code);
	}
	const dataSocket = await openPassiveData(session);
	const resp = await session.command("NLST");
	if (resp.code !== 150 && resp.code !== 125) {
		dataSocket.close();
		throw new FtpError(resp.code === 550 ? 404 : 502, `FTP NLST failed (code ${resp.code})`, resp.code);
	}
	const listing = await new Response(dataSocket.readable).text();
	const done = await readFtpResponse(session.lineReader);
	if (done.code >= 400) throw new FtpError(502, `FTP NLST did not complete (code ${done.code})`, done.code);
	try {
		await session.command("QUIT");
	} catch {
		// 服务器可能直接断开, 忽略 / the server may drop the connection directly, ignore
	}
	session.close();
	// 兜底: 个别服务器即便裸 NLST 仍返回带路径前缀的条目, 取末段归一化, 防止链接套娃
	// fallback: some servers return path-prefixed entries even for a bare NLST; take the last segment so links do not nest
	const names = listing
		.split(/\r?\n/)
		.map((n) => n.split("/").pop() ?? n)
		.filter((n) => n !== "");
	console.debug("directory listed", { func, path, count: names.length });
	return new Response(renderDirectoryListing(dstUrl, proxyBase, names, tokenQuerySuffix), {
		status: 200,
		statusText: "OK",
		headers: { "content-type": "text/html; charset=utf-8" },
	});
}

/** 取文件: RETR 流式直通; 550 时回退为目录列表 (无尾斜杠的目录访问) / Fetch a file: stream via RETR; fall back to a directory listing on 550 (directory accessed without a trailing slash) */
async function retrieveFile(
	session: FtpSession,
	dstUrl: URL,
	proxyBase: string,
	waitUntil: (p: Promise<unknown>) => void,
	tokenQuerySuffix: string,
): Promise<Response> {
	const func = "src.ftp.retrieveFile";
	const path = dstUrl.pathname || "/";
	const dataSocket = await openPassiveData(session);
	const resp = await session.command(`RETR ${sanitizeFtpArg(path)}`);
	if (resp.code === 550) {
		console.debug("RETR reported 550, falling back to directory listing", { func, path });
		dataSocket.close();
		return listDirectory(session, dstUrl, proxyBase, tokenQuerySuffix);
	}
	if (resp.code !== 150 && resp.code !== 125) {
		dataSocket.close();
		throw new FtpError(502, `FTP RETR failed (code ${resp.code})`, resp.code);
	}
	// 数据流作为响应 body 流式直传; 控制连接交给 waitUntil 收尾
	// the data stream becomes the response body; the control connection is finalized via waitUntil
	waitUntil(finalizeTransfer(session));
	console.debug("file transfer started", { func, path });
	return new Response(dataSocket.readable, {
		status: 200,
		statusText: "OK",
		headers: { "content-type": guessContentType(path) },
	});
}

const STATUS_TEXT: Record<number, string> = {
	403: "Forbidden",
	404: "Not Found",
	502: "Bad gateway",
};

function toFtpErrorResponse(e: unknown): Response {
	if (e instanceof FtpError) {
		return new Response(e.message, { status: e.httpStatus, statusText: STATUS_TEXT[e.httpStatus] ?? "" });
	}
	console.error("unexpected FTP error", { func: "src.ftp.toFtpErrorResponse", error: String(e) });
	return new Response("FTP gateway error", { status: 502, statusText: "Bad gateway" });
}

/**
 * FTP 入口: 按 URL 取文件或目录列表, 返回可直接交给客户端的 Response。
 * waitUntil 用于承接 RETR 流式响应后的控制连接收尾; proxyBase 用于目录页链接生成;
 * tokenQuerySuffix 由 index.ts 在 token 来自 ?__proxy_token= 时构造, 随目录页链接传播。
 *
 * FTP entry point: fetches a file or directory listing by URL and returns a client-ready Response.
 * waitUntil carries the control-connection finalization for streamed RETR responses; proxyBase is used for
 * directory-page links; tokenQuerySuffix is built by index.ts when the token came via ?__proxy_token=
 * and propagates through the directory-page links.
 */
export async function fetchFtp(
	dstUrl: URL,
	waitUntil: (p: Promise<unknown>) => void,
	proxyBase: string,
	tokenQuerySuffix = "",
): Promise<Response> {
	const func = "src.ftp.fetchFtp";
	const hostname = dstUrl.hostname;
	const port = dstUrl.port ? Number(dstUrl.port) : 21;
	const logUrl = redactUrlCredentials(dstUrl);
	console.debug("FTP request accepted", { func, url: logUrl });
	let session: FtpSession | null = null;
	try {
		session = await openControlSession(hostname, port, ftpCredentials(dstUrl));
		const path = dstUrl.pathname || "/";
		if (path.endsWith("/")) {
			const response = await listDirectory(session, dstUrl, proxyBase, tokenQuerySuffix);
			session = null; // 所有权已移交给 listDirectory (其内部已收尾) / ownership transferred to listDirectory (it finalizes internally)
			return response;
		}
		const response = await retrieveFile(session, dstUrl, proxyBase, waitUntil, tokenQuerySuffix);
		session = null; // 控制连接由 waitUntil 的 finalizeTransfer 负责 / the control connection is finalizeTransfer's responsibility in waitUntil
		return response;
	} catch (e) {
		console.warn("FTP request failed", { func, url: logUrl, error: e instanceof FtpError ? `${e.httpStatus} ${e.message}` : String(e) });
		return toFtpErrorResponse(e);
	} finally {
		// 仅在所有权未移交 (出错/中断) 时兜底关闭 / close as a last resort only when ownership was not transferred (error/abort)
		if (session) session.close();
	}
}
