import { createChallenge, deriveHmacKeySecret, verifySolution } from "altcha-lib";
import { deriveKey } from "altcha-lib/algorithms/web/pbkdf2";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };
const BLOCKED_HOSTS = new Set(["localhost", "localhost.localdomain", "metadata.google.internal"]);

export default {
  async fetch(request, env) {
    const requestUrl = new URL(request.url);
    const origin = request.headers.get("origin") || "";
    const cors = corsHeaders(origin, env);

    if (request.method === "OPTIONS") {
      if (!isAllowedOrigin(origin, env)) return json({ error: "Origin tidak diizinkan." }, 403, cors);
      return new Response(null, { status: 204, headers: cors });
    }
    if (origin && !isAllowedOrigin(origin, env)) return json({ error: "Origin tidak diizinkan." }, 403, cors);

    try {
      if (requestUrl.pathname === "/health" && request.method === "GET") {
        return json({ ok: true, service: "seo-audit-api", version: "1.0.0" }, 200, cors);
      }
      if (requestUrl.pathname === "/challenge" && request.method === "GET") {
        return await issueChallenge(env, cors);
      }
      if (requestUrl.pathname === "/audit" && request.method === "POST") {
        return await auditUrl(request, env, cors);
      }
      return json({ error: "Endpoint tidak ditemukan." }, 404, cors);
    } catch (error) {
      console.error("unhandled", error);
      return json({ error: "Terjadi kesalahan internal." }, 500, cors);
    }
  }
};

async function issueChallenge(env, cors) {
  requireSecret(env);
  const hmacKeySecret = await deriveHmacKeySecret(env.ALTCHA_HMAC_SECRET);
  const challenge = await createChallenge({
    algorithm: "PBKDF2/SHA-256",
    cost: 5000,
    counter: randomInt(5000, 10000),
    deriveKey,
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    hmacSignatureSecret: env.ALTCHA_HMAC_SECRET,
    hmacKeySignatureSecret: hmacKeySecret,
    data: { purpose: "seo-audit" }
  });
  return json(challenge, 200, { ...cors, "cache-control": "no-store" });
}

async function auditUrl(request, env, cors) {
  requireSecret(env);
  if (!isJson(request)) return json({ error: "Content-Type harus application/json." }, 415, cors);

  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 32_768) return json({ error: "Payload terlalu besar." }, 413, cors);

  const body = await request.json().catch(() => null);
  if (!body || typeof body.url !== "string" || typeof body.altcha !== "string") {
    return json({ error: "URL dan payload ALTCHA wajib diisi." }, 400, cors);
  }

  const verified = await verifyAltchaPayload(body.altcha, env);
  if (!verified) return json({ error: "Verifikasi keamanan gagal atau kedaluwarsa." }, 403, cors);

  const actor = request.headers.get("cf-connecting-ip") || request.cf?.colo || "anonymous";
  const limited = await env.AUDIT_RATE_LIMITER.limit({ key: `audit:${actor}` });
  if (!limited.success) return json({ error: "Batas audit tercapai. Coba lagi dalam satu menit." }, 429, { ...cors, "retry-after": "60" });

  let target;
  try { target = normalizePublicUrl(body.url); }
  catch (error) { return json({ error: error.message }, 400, cors); }

  const maxBytes = clamp(Number(env.MAX_HTML_BYTES || 1_048_576), 65_536, 2_097_152);
  const timeoutMs = clamp(Number(env.FETCH_TIMEOUT_MS || 10_000), 3_000, 15_000);

  try {
    const result = await safeFetchHtml(target, { maxBytes, timeoutMs, maxRedirects: 3 });
    return json({
      ok: true,
      requestedUrl: target.href,
      finalUrl: result.finalUrl,
      status: result.status,
      contentType: result.contentType,
      bytes: result.bytes,
      html: result.html
    }, 200, { ...cors, "cache-control": "no-store" });
  } catch (error) {
    const status = error.name === "AbortError" ? 504 : (error.status || 502);
    return json({ error: error.message || "Halaman tidak dapat diambil." }, status, cors);
  }
}

async function verifyAltchaPayload(encoded, env) {
  try {
    const decoded = decodeBase64Json(encoded);
    if (!decoded?.challenge || !decoded?.solution) return false;
    const hmacKeySecret = await deriveHmacKeySecret(env.ALTCHA_HMAC_SECRET);
    const result = await verifySolution({
      challenge: decoded.challenge,
      solution: decoded.solution,
      deriveKey,
      hmacSignatureSecret: env.ALTCHA_HMAC_SECRET,
      hmacKeySignatureSecret: hmacKeySecret
    });
    return result?.verified === true && result?.expired !== true;
  } catch (error) {
    console.warn("altcha verification failed", error?.message || error);
    return false;
  }
}

async function safeFetchHtml(initialUrl, options) {
  let current = initialUrl;
  for (let hop = 0; hop <= options.maxRedirects; hop++) {
    validatePublicTarget(current);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);
    let response;
    try {
      response = await fetch(current.href, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "accept": "text/html,application/xhtml+xml;q=0.9",
          "user-agent": "BibleInfographic-SEO-Audit/1.0"
        }
      });
    } finally { clearTimeout(timer); }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      if (hop === options.maxRedirects) throw httpError(508, "Terlalu banyak redirect.");
      const location = response.headers.get("location");
      if (!location) throw httpError(502, "Redirect tanpa tujuan.");
      current = new URL(location, current);
      continue;
    }

    if (!response.ok) throw httpError(502, `Target merespons HTTP ${response.status}.`);
    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    if (!contentType.includes("text/html") && !contentType.includes("application/xhtml+xml")) {
      throw httpError(415, "Target bukan dokumen HTML.");
    }
    const declared = Number(response.headers.get("content-length") || 0);
    if (declared > options.maxBytes) throw httpError(413, "HTML target melebihi batas 1 MB.");
    const bytes = await readCapped(response.body, options.maxBytes);
    const html = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return { html, bytes: bytes.byteLength, status: response.status, contentType, finalUrl: current.href };
  }
  throw httpError(508, "Redirect tidak dapat diselesaikan.");
}

async function readCapped(stream, maxBytes) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) throw httpError(413, "HTML target melebihi batas 1 MB.");
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return joined;
}

function normalizePublicUrl(value) {
  const url = new URL(value.trim());
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("Hanya URL HTTP atau HTTPS yang diizinkan.");
  if (url.username || url.password) throw new Error("URL dengan kredensial tidak diizinkan.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Port URL tidak diizinkan.");
  validatePublicTarget(url);
  url.hash = "";
  return url;
}

function validatePublicTarget(url) {
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || BLOCKED_HOSTS.has(host) || host.endsWith(".local") || host.endsWith(".internal")) {
    throw httpError(400, "Host lokal atau internal tidak diizinkan.");
  }
  if (isPrivateIpv4(host) || isPrivateIpv6(host)) throw httpError(400, "Alamat IP privat tidak diizinkan.");
}

function isPrivateIpv4(host) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;
  const p = host.split(".").map(Number);
  if (p.some(n => n < 0 || n > 255)) return true;
  return p[0] === 0 || p[0] === 10 || p[0] === 127 ||
    (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    p[0] >= 224;
}

function isPrivateIpv6(host) {
  const h = host.toLowerCase();
  return h === "::" || h === "::1" || h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe8") || h.startsWith("fe9") || h.startsWith("fea") || h.startsWith("feb") || h.startsWith("::ffff:127.") || h.startsWith("::ffff:10.") || h.startsWith("::ffff:192.168.");
}

function decodeBase64Json(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return JSON.parse(atob(padded));
}

function randomInt(min, max) {
  const range = max - min + 1;
  const maxUint = 0xffffffff;
  const limit = maxUint - (maxUint % range);
  const buf = new Uint32Array(1);
  do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
  return min + (buf[0] % range);
}

function corsHeaders(origin, env) {
  const headers = {
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-max-age": "86400",
    "vary": "Origin",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer"
  };
  if (isAllowedOrigin(origin, env)) headers["access-control-allow-origin"] = origin;
  return headers;
}

function isAllowedOrigin(origin, env) {
  if (!origin) return true;
  const allowed = String(env.ALLOWED_ORIGINS || "").split(",").map(v => v.trim()).filter(Boolean);
  return allowed.includes(origin);
}

function requireSecret(env) {
  if (!env.ALTCHA_HMAC_SECRET || env.ALTCHA_HMAC_SECRET.length < 32) throw new Error("ALTCHA_HMAC_SECRET belum dikonfigurasi dengan benar.");
}
function isJson(request) { return (request.headers.get("content-type") || "").toLowerCase().includes("application/json"); }
function clamp(value, min, max) { return Math.min(max, Math.max(min, value)); }
function httpError(status, message) { const e = new Error(message); e.status = status; return e; }
function json(data, status = 200, extra = {}) { return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...extra } }); }
