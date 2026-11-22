// GO Lists - access control for Cloudflare Pages.
// Settings needed in Cloudflare (Pages project > Settings):
//   KV binding  GOKV        - a KV namespace (stores requests and users)
//   Variable    ADMIN_CODE  - the admin's 12-digit trainer code
//   Secret      SECRET      - a long random string (signs log-ins, scrambles passwords)
//   Secret      SETUP_KEY   - a phrase only the admin knows, used once to set the admin password
// Nothing secret lives in this file.

const DAY = 86400000;
const WINDOW_DAYS = 7;            // days an approved person has to set a password
const COOKIE_DAYS = 180;          // how long a phone stays logged in
const ITER = 10000;               // password scrambling rounds (kept low for Cloudflare's free CPU limit)
const PUBLIC = /^\/(login\.html|manifest\.webmanifest|apple-touch-icon\.png|icon-[\w-]+\.png|favicon\.ico|robots\.txt)$/;
const BLOCKED = /^\/(functions|\.github)\/|^\/(update-data\.yml|costume-files\.yml|supabase-setup\.sql)$/;

const enc = new TextEncoder();
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const rand = n => b64u(crypto.getRandomValues(new Uint8Array(n)));
const digits6 = () => String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
const json = (o, st = 200, h = {}) => new Response(JSON.stringify(o), { status: st, headers: { "content-type": "application/json", "cache-control": "no-store", ...h } });
const cleanCode = c => String(c || "").replace(/\D/g, "");
const okCode = c => /^\d{12}$/.test(c);
const txt = (s, n) => String(s || "").replace(/[\u0000-\u001f]/g, " ").trim().slice(0, n);

async function hmac(secret, data) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}
async function sha(s) { return b64u(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function pwHash(pw, salt, secret) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw + "\u0000" + secret), "PBKDF2", false, ["deriveBits"]);
  return b64u(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: fromB64u(salt), iterations: ITER }, k, 256));
}
function same(a, b) { if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }

async function makeCookie(env, code, v) {
  const p = b64u(enc.encode(JSON.stringify({ c: code, v, e: Date.now() + COOKIE_DAYS * DAY })));
  return `gos=${p}.${await hmac(env.SECRET, p)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_DAYS * 86400}`;
}
const clearCookie = "gos=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
async function readCookie(req, env) {
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)gos=([^;]+)/);
  if (!m) return null;
  const [p, s] = m[1].split(".");
  if (!p || !s || !same(s, await hmac(env.SECRET, p))) return null;
  try { const o = JSON.parse(new TextDecoder().decode(fromB64u(p))); return o.e > Date.now() ? o : null; } catch (e) { return null; }
}
const getU = async (env, code) => { const r = await env.GOKV.get("u:" + code, "json"); return r || null; };
async function putU(env, code, u) {
  await env.GOKV.put("u:" + code, JSON.stringify(u), { metadata: { n: u.n, st: u.st, exp: u.exp || 0, t: u.t, sc: u.st === "approved" ? u.sc : undefined } });
}
// Full check: signature, still approved, password not reset since this log-in.
async function session(req, env) {
  const c = await readCookie(req, env); if (!c) return null;
  const u = await getU(env, c.c);
  if (!u || u.st !== "active" || u.v !== c.v) return null;
  return { code: c.c, name: u.n, admin: c.c === env.ADMIN_CODE };
}

async function api(path, req, env) {
  const body = req.method === "POST" ? await req.json().catch(() => ({})) : {};
  const code = cleanCode(body.code);

  if (path === "/api/me") { const s = await session(req, env); return s ? json(s) : json({ error: "not logged in" }, 401); }
  if (path === "/api/logout") return json({ ok: true }, 200, { "set-cookie": clearCookie });
  if (req.method !== "POST" && !path.startsWith("/api/admin/list")) return json({ error: "method" }, 405);

  if (path === "/api/request") {
    if (!okCode(code)) return json({ error: "Trainer codes are 12 digits." }, 400);
    const name = txt(body.name, 30); if (name.length < 2) return json({ error: "Please enter your trainer name." }, 400);
    const u = await getU(env, code);
    if (u && u.st === "active") return json({ error: "That trainer code already has access. Use Log in." }, 409);
    const token = rand(24), now = Date.now();
    if (code === env.ADMIN_CODE) { // admin bootstrap: approved at once, password needs SETUP_KEY too
      await putU(env, code, { n: name, st: "approved", exp: now + WINDOW_DAYS * DAY, ch: await sha(token), sc: digits6(), v: (u && u.v || 0) + 1, t: now });
      return json({ ok: true, token, approved: true, admin: true });
    }
    if (u && u.st === "approved" && u.exp > now) return json({ ok: true, token: null, approved: true, note: "Already approved: log in to set your password." });
    await env.GOKV.put("r:" + code, JSON.stringify({ n: name, m: txt(body.msg, 300), ch: await sha(token), t: now }), { expirationTtl: 30 * 86400, metadata: { n: name, m: txt(body.msg, 120), t: now } });
    return json({ ok: true, token });
  }

  if (path === "/api/login") {
    if (!okCode(code)) return json({ error: "Trainer codes are 12 digits." }, 400);
    const fk = "f:" + code, fails = +(await env.GOKV.get(fk) || 0);
    if (fails >= 5) return json({ error: "Too many wrong attempts. Try again in 15 minutes." }, 429);
    const u = await getU(env, code);
    if (!u) return json({ error: "That trainer code isn't approved yet. Use Request access." }, 403);
    if (u.st === "approved") return u.exp > Date.now() ? json({ setup: true, admin: code === env.ADMIN_CODE }) : json({ error: "Your approval has expired. Please request access again." }, 403);
    if (!same(await pwHash(String(body.pw || ""), u.s, env.SECRET), u.h)) {
      await env.GOKV.put(fk, String(fails + 1), { expirationTtl: 900 });
      return json({ error: "Wrong password." }, 403);
    }
    return json({ ok: true, name: u.n, admin: code === env.ADMIN_CODE }, 200, { "set-cookie": await makeCookie(env, code, u.v) });
  }

  if (path === "/api/setpw") {
    const u = okCode(code) ? await getU(env, code) : null;
    if (!u || u.st !== "approved" || !(u.exp > Date.now())) return json({ error: "This trainer code isn't waiting for a password. Request access first." }, 403);
    const tokOk = body.token && u.ch && same(await sha(String(body.token)), u.ch);
    const scOk = body.sc && u.sc && same(cleanCode(body.sc), u.sc);
    if (!tokOk && !scOk) return json({ error: "Please enter the 6-digit setup code you were given.", needSc: true }, 403);
    if (code === env.ADMIN_CODE && !(env.SETUP_KEY && same(String(body.key || ""), env.SETUP_KEY))) return json({ error: "Admin setup key is wrong.", needKey: true }, 403);
    const pw = String(body.pw || "");
    if (pw.length < 8) return json({ error: "Use at least 8 characters." }, 400);
    const s = rand(16);
    const nu = { n: u.n, st: "active", s, h: await pwHash(pw, s, env.SECRET), v: (u.v || 0) + 1, t: u.t, ch: u.ch };
    await putU(env, code, nu);
    return json({ ok: true, name: nu.n }, 200, { "set-cookie": await makeCookie(env, code, nu.v) });
  }

  if (path.startsWith("/api/admin/")) {
    const s = await session(req, env);
    if (!s || !s.admin) return json({ error: "Admin only." }, 403);
    const act = path.slice(11);
    if (act === "list") {
      const [r, u] = await Promise.all([env.GOKV.list({ prefix: "r:" }), env.GOKV.list({ prefix: "u:" })]);
      return json({
        requests: r.keys.map(k => ({ code: k.name.slice(2), ...(k.metadata || {}) })).sort((a, b) => a.t - b.t),
        users: u.keys.map(k => ({ code: k.name.slice(2), ...(k.metadata || {}) })).sort((a, b) => String(a.n).localeCompare(String(b.n)))
      });
    }
    if (!okCode(code)) return json({ error: "Bad trainer code." }, 400);
    const now = Date.now();
    if (act === "approve") {
      const r = await env.GOKV.get("r:" + code, "json"); if (!r) return json({ error: "Request not found." }, 404);
      const old = await getU(env, code), sc = digits6();
      await putU(env, code, { n: r.n, st: "approved", exp: now + WINDOW_DAYS * DAY, ch: r.ch, sc, v: (old && old.v || 0) + 1, t: now });
      await env.GOKV.delete("r:" + code);
      return json({ ok: true, sc });
    }
    if (act === "add") {
      const name = txt(body.name, 30); if (name.length < 2) return json({ error: "Enter their trainer name." }, 400);
      const old = await getU(env, code), sc = digits6();
      await putU(env, code, { n: name, st: "approved", exp: now + WINDOW_DAYS * DAY, sc, v: (old && old.v || 0) + 1, t: now });
      await env.GOKV.delete("r:" + code);
      return json({ ok: true, sc });
    }
    if (act === "decline") { await env.GOKV.delete("r:" + code); return json({ ok: true }); }
    if (act === "remove") { if (code === env.ADMIN_CODE) return json({ error: "You can't remove the admin." }, 400); await env.GOKV.delete("u:" + code); return json({ ok: true }); }
    if (act === "reset") {
      const u = await getU(env, code); if (!u) return json({ error: "User not found." }, 404);
      const sc = digits6();
      await putU(env, code, { n: u.n, st: "approved", exp: now + WINDOW_DAYS * DAY, ch: u.ch, sc, v: (u.v || 0) + 1, t: u.t });
      return json({ ok: true, sc });
    }
  }
  return json({ error: "Not found" }, 404);
}

export async function onRequest(ctx) {
  const { request: req, env, next } = ctx;
  const url = new URL(req.url), path = url.pathname;
  if (!env.GOKV || !env.SECRET || !env.ADMIN_CODE) return new Response("GO Lists is not set up yet: add GOKV, SECRET and ADMIN_CODE in Cloudflare.", { status: 503 });
  if (BLOCKED.test(path)) return new Response("Not found", { status: 404 });
  if (path.startsWith("/api/")) { try { return await api(path, req, env); } catch (e) { return json({ error: "Server error" }, 500); } }
  if (PUBLIC.test(path)) return next();
  const isPage = path === "/" || path.endsWith(".html") || (req.headers.get("accept") || "").includes("text/html");
  if (isPage) {
    if (await session(req, env)) return next();
    return new Response(null, { status: 302, headers: { location: "/login.html", "cache-control": "no-store" } });
  }
  // Data, scripts and pictures: a valid signed log-in is enough (the page check above catches removed users).
  if (await readCookie(req, env)) return next();
  return new Response("Log in required", { status: 401, headers: { "cache-control": "no-store" } });
}
