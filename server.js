import { fileURLToPath } from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { uvPath } from "@titaniumnetwork-dev/ultraviolet";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";
import { server as wisp } from "@mercuryworkshop/wisp-js/server";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---- Settings: read .env (SITE_PASSWORD=...) without needing extra packages ----
try {
  for (const line of fs.readFileSync(path.join(__dirname, ".env"), "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, "$2");
  }
} catch {}

const PORT = Number(process.env.PORT || 8080);
const PASSWORD = process.env.SITE_PASSWORD;
if (!PASSWORD) {
  console.error('\nNo password set. Create a file named ".env" next to server.js containing:\n  SITE_PASSWORD=your-password-here\n');
  process.exit(1);
}

// ---- Password gate ----
const sha = (s) => crypto.createHash("sha256").update(s).digest();
const PASSWORD_HASH = sha(PASSWORD);
// Sessions are signed with a key derived from the password, so changing the
// password automatically logs everyone out.
const SECRET = sha("gamesite-session:" + PASSWORD);
const COOKIE = "gs_session";
const SESSION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

const sign = (payload) => crypto.createHmac("sha256", SECRET).update(payload).digest("hex");
const makeToken = () => { const exp = String(Date.now() + SESSION_MS); return exp + "." + sign(exp); };

function isValidToken(token) {
  if (!token) return false;
  const [exp, sig] = token.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const a = Buffer.from(sig), b = Buffer.from(sign(exp));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function cookieFrom(header = "") {
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return null;
}

// Basic brute-force protection: 10 wrong tries per 15 minutes per IP.
const attempts = new Map();
const MAX_TRIES = 10, WINDOW_MS = 15 * 60 * 1000;
function tooMany(ip) {
  const a = attempts.get(ip);
  if (!a || a.resetAt < Date.now()) return false;
  return a.count >= MAX_TRIES;
}
function recordFail(ip) {
  const a = attempts.get(ip);
  if (!a || a.resetAt < Date.now()) attempts.set(ip, { count: 1, resetAt: Date.now() + WINDOW_MS });
  else a.count++;
}

// ---- Wisp (proxy tunnel) settings ----
wisp.options.allow_loopback_ips = false;
wisp.options.allow_private_ips = false;
// Prefer IPv4: many home networks have broken IPv6, which makes sites fail to load.
wisp.options.dns_result_order = "ipv4first";

// trustProxy: only believe forwarded headers from Caddy running on this machine.
const app = Fastify({ logger: false, trustProxy: "127.0.0.1" });

const PUBLIC_PATHS = new Set(["/login.html", "/login"]);

app.addHook("onRequest", async (req, reply) => {
  const url = req.url.split("?")[0];
  if (PUBLIC_PATHS.has(url) || url === "/logout") return;
  if (isValidToken(cookieFrom(req.headers.cookie))) return;
  const wantsPage = req.method === "GET" && (req.headers.accept || "").includes("text/html");
  if (wantsPage) return reply.redirect("/login.html");
  return reply.code(401).send({ error: "Login required" });
});

app.post("/login", async (req, reply) => {
  if (tooMany(req.ip)) return reply.code(429).send({ error: "Too many tries. Wait 15 minutes." });
  const given = String(req.body?.password ?? "");
  const ok = crypto.timingSafeEqual(sha(given), PASSWORD_HASH);
  if (!ok) { recordFail(req.ip); return reply.code(401).send({ error: "Wrong password" }); }
  attempts.delete(req.ip);
  const secure = req.protocol === "https" ? "; Secure" : "";
  reply.header("Set-Cookie", `${COOKIE}=${makeToken()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MS / 1000}${secure}`);
  return { ok: true };
});

app.get("/logout", async (req, reply) => {
  reply.header("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
  return reply.redirect("/login.html");
});

// Your game site (static files)
await app.register(fastifyStatic, { root: path.join(__dirname, "public") });

// Web proxy assets
await app.register(fastifyStatic, { root: uvPath, prefix: "/uv/", decorateReply: false });
await app.register(fastifyStatic, { root: baremuxPath, prefix: "/baremux/", decorateReply: false });
await app.register(fastifyStatic, {
  root: path.join(__dirname, "node_modules", "@mercuryworkshop", "epoxy-transport", "dist"),
  prefix: "/epoxy/", decorateReply: false,
});

// Wisp websocket endpoint (the proxy's tunnel). Also behind the password.
app.server.on("upgrade", (req, socket, head) => {
  if (req.url.startsWith("/wisp/") && isValidToken(cookieFrom(req.headers.cookie))) {
    wisp.routeRequest(req, socket, head);
  } else {
    socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
  }
});

app.listen({ port: PORT, host: "0.0.0.0" }).then(() =>
  console.log(`Game site running on http://localhost:${PORT} (password protected)`)
);
