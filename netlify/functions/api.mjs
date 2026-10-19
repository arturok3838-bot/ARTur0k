// АРТурок — server part of the site on Netlify.
// Stores site texts, prices, photos, client requests and the admin password in Netlify Blobs.
// The first admin password comes from the ADMIN_PASSWORD environment variable (Netlify → Environment variables).
//
// Protection against flood and attacks
//  1. Netlify itself, before this code runs: one IP address may make at most 120 requests a minute
//     (the rateLimit rule below; extra requests get "429 Too Many Requests").
//  2. Here, always on: limits per client and per IP address for new requests, messages and password attempts.
//  3. Attack mode: when more than GUARD_VISITORS different addresses reach the server within GUARD_WINDOW
//     seconds (default: 100 in 40 s), or more than GUARD_NEW new clients send a request within one window
//     (default: 10), only GUARD_ADMIT new visitors (default: 5) per GUARD_WINDOW seconds may
//     send anything; everyone else waits in a queue and their request goes out automatically when a slot opens.
//     The admin and clients who had requests on the site before the attack began are always let through
//     (a visitor let in through the queue keeps access for 15 minutes), and the site itself
//     (texts, prices, photos) keeps opening for everyone from Netlify's cache. The mode switches itself off
//     GUARD_HOLD seconds (default 600) after the last spike; the admin can also switch it on or off by hand.
//     Requests that came in through the queue are marked, and the admin can delete them all with one button.
//  The numbers can be changed without code: add environment variables with these names in Netlify.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = {
  path: "/api/*",
  rateLimit: { action: "rate_limit", windowLimit: 120, windowSize: 60, aggregateBy: ["ip", "domain"] },
};

const MAX_JSON = 900_000, MAX_ORDER = 300_000, MAX_IMG = 4_500_000;
const CID = /^[a-f0-9]{32}$/, IMGID = /^[A-Za-z0-9_-]{8,80}$/;
const IMG_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif", "image/svg+xml"];
const LIM = {
  clientWritesPerMin: 12, // saves from one client per minute (requests, messages, read marks)
  clientMsgsPerMin: 6, // new messages from one client per minute
  clientReqsPerHour: 4, // new requests (orders) from one client per hour
  clientReqsTotal: 20, // requests in one client's cabinet
  msgsPerReq: 300, // messages in one request
  msgLen: 2000, // characters in one message
  newClientsPerIpHour: 5, // new clients from one IP address per hour
  loginFailsPerIp: 8, // wrong passwords from one address → login from it paused for 10 minutes
  loginFailsAbroad: 30, // wrong passwords from outside Russia within 10 minutes → login from abroad paused 10 minutes
};

const json = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...h } });
const fail = (s, code, msg, h) => json({ error: msg || code, code }, s, h);
const env = (k) => { try { const v = globalThis.Netlify?.env?.get(k); if (v != null && v !== "") return v; } catch (e) {} return process.env[k] || null; };
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const mac = (key, s) => crypto.createHmac("sha256", key).update(String(s)).digest("base64url");
const same = (a, b) => { const x = Buffer.isBuffer(a) ? a : Buffer.from(String(a)), y = Buffer.isBuffer(b) ? b : Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const pbk = (pw, salt) => crypto.pbkdf2Sync(String(pw), salt, 150000, 32, "sha256").toString("hex");
const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function merge(a, b) {
  const out = isObj(a) ? { ...a } : {};
  for (const k of Object.keys(b || {})) {
    if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
    const v = b[k];
    out[k] = isObj(v) && isObj(out[k]) ? merge(out[k], v) : v;
  }
  return out;
}
const err = (status, code) => Object.assign(new Error(code), { status, code });
async function readJson(req, max) {
  const t = await req.text();
  if (t.length > max) throw err(413, "too_large");
  try { return JSON.parse(t || "null"); } catch (e) { throw err(400, "invalid_argument"); }
}

/* ---------- settings of the attack mode ---------- */
let G = null;
function guardCfg() {
  if (G) return G;
  const num = (k, d) => { const v = Number(env(k)); return Number.isFinite(v) && v > 0 ? v : d; };
  return (G = { visitors: num("GUARD_VISITORS", 100), window: num("GUARD_WINDOW", 40), admit: num("GUARD_ADMIT", 5), hold: num("GUARD_HOLD", 600), newMax: num("GUARD_NEW", 10), trust: num("GUARD_TRUST", 600), pass: num("GUARD_PASS", 900) });
}
const winOf = (t) => Math.floor(t / (guardCfg().window * 1000));
const hourOf = (t) => Math.floor(t / 3600e3);

/* ---------- read-modify-write that is safe when many server copies write at once ---------- */
async function casJSON(st, key, fn, tries = 6) {
  for (let i = 0; i < tries; i++) {
    const cur = await st.getWithMetadata(key, { type: "json" });
    const next = fn(cur ? cur.data : null);
    if (next === undefined) return { value: cur ? cur.data : null, modified: false };
    const r = cur ? await st.setJSON(key, next, { onlyIfMatch: cur.etag }) : await st.setJSON(key, next, { onlyIfNew: true });
    if (r && r.modified) return { value: next, modified: true, created: !cur };
    await sleep(10 + Math.random() * 30 * (i + 1));
  }
  return null;
}

/* ---------- admin password, tokens and client passes ---------- */
let authC = null, authT = 0;
async function getAuth(st, fresh) {
  if (!fresh && authC && Date.now() - authT < 30000) return authC;
  let a = await st.get("auth", { type: "json" });
  if (!isObj(a) || !a.secret) {
    await casJSON(st, "auth", (d) => (isObj(d) && d.secret ? undefined : { ...(isObj(d) ? d : {}), secret: crypto.randomBytes(32).toString("hex"), ver: (isObj(d) && d.ver) || 1 }));
    a = await st.get("auth", { type: "json" });
  }
  authC = a; authT = Date.now();
  return a;
}
function checkPassword(a, pw) {
  if (a.hash && a.salt) return same(pbk(pw, a.salt), a.hash);
  const e = env("ADMIN_PASSWORD");
  if (!e) return null;
  return same(sha(pw), sha(e));
}
function sign(a) {
  const p = Buffer.from(JSON.stringify({ exp: Date.now() + 30 * 864e5, v: a.ver || 1 })).toString("base64url");
  return p + "." + mac(a.secret, p);
}
function verify(a, tok) {
  const [p, s] = String(tok || "").split(".");
  if (!p || !s || !a.secret) return false;
  if (!same(s, mac(a.secret, p))) return false;
  try { const d = JSON.parse(Buffer.from(p, "base64url").toString()); return d.exp > Date.now() && d.v === (a.ver || 1); } catch (e) { return false; }
}
async function isAdmin(st, req) {
  const tok = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (!tok) return false;
  if (verify(await getAuth(st), tok)) return true;
  return Date.now() - authT > 2000 ? verify(await getAuth(st, true), tok) : false;
}
// A client who has a request gets a pass. In attack mode it opens the cabinet only if it was issued at least
// GUARD_TRUST seconds before the attack began, so bots that sign up at the start of an attack get nothing from it.
// A visitor let in through the queue gets a short pass (GUARD_PASS seconds).
function passFor(a, cid, adm) {
  const t = Date.now(), d = adm ? { c: cid, iat: t, exp: t + guardCfg().pass * 1000, adm: 1 } : { c: cid, iat: t, exp: t + 180 * 864e5 };
  const p = Buffer.from(JSON.stringify(d)).toString("base64url");
  return p + "." + mac(a.secret, "pass:" + p);
}
function passInfo(a, tok, cid) {
  const [p, s] = String(tok || "").split(".");
  if (!p || !s || p.length > 300 || !same(s, mac(a.secret, "pass:" + p))) return null;
  try { const d = JSON.parse(Buffer.from(p, "base64url").toString()); return d.c === cid && d.exp > Date.now() ? d : null; } catch (e) { return null; }
}
const trusted = (pi, mode) => !!pi && (!attackOn(mode) || !!pi.adm || (pi.iat || 0) < (mode.since || 0) - guardCfg().trust * 1000);
// quick limits inside one server copy, checked before touching the storage
function hit(map, key, limit, ms) {
  const t = Date.now();
  let q = map.get(key);
  if (!q) { if (map.size > 50000) map.clear(); map.set(key, (q = [])); }
  while (q.length && t - q[0] > ms) q.shift();
  if (q.length >= limit) return false;
  q.push(t);
  return true;
}

/* ---------- traffic counting and attack mode ----------
   Each server copy remembers which addresses (as hashes, not the addresses themselves) it saw in the current
   window and every 2 seconds adds the new ones to one shared counter per window. The counter keeps up to
   200 hashes, so one visitor seen by several server copies is counted once. The estimate for the last
   GUARD_WINDOW seconds is: current window + previous window × the part of it still inside that period. */
const HCAP = 200;
const mem = { seenW: -1, seen: new Set(), pending: new Map(), lastFlush: 0, flushing: null, cnt: new Map(), mode: null, modeT: 0, admFull: -1, lastSweep: 0, state: null, stateT: 0, docs: new Map(), ipHits: new Map(), cidHits: new Map() };
const pend = (w) => { let p = mem.pending.get(w); if (!p) mem.pending.set(w, (p = { hs: new Map(), d: 0 })); return p; };
function note(ipH, cc) {
  const w = winOf(Date.now());
  if (w !== mem.seenW) { mem.seenW = w; mem.seen = new Set(); }
  if (mem.seen.has(ipH) || mem.seen.size > 100000) return;
  mem.seen.add(ipH);
  pend(w).hs.set(ipH, cc);
}
function addCounts(d, p) {
  d = isObj(d) ? { ...d } : {};
  const H = new Set(Array.isArray(d.h) ? d.h : []), c = isObj(d.c) ? { ...d.c } : {};
  let x = d.x || 0;
  for (const [h, cc] of p.hs) { if (H.has(h)) continue; if (H.size < HCAP) H.add(h); else x++; c[cc] = (c[cc] || 0) + 1; }
  const top = Object.entries(c).sort((a, b) => b[1] - a[1]);
  return { h: [...H], x, n: H.size + x, d: (d.d || 0) + p.d, c: Object.fromEntries(top.slice(0, 40)) };
}
function dropOld(st, w) { Promise.all([3, 4].flatMap((k) => ["g/cnt/", "g/adm/", "g/new/"].map((p) => p + (w - k))).map((key) => st.delete(key))).catch(() => {}); }
async function flush(st) {
  if (mem.flushing || !mem.pending.size || Date.now() - mem.lastFlush < 2000) return false;
  mem.lastFlush = Date.now();
  const job = (async () => {
    for (const [w, p] of [...mem.pending]) {
      mem.pending.delete(w);
      const r = await casJSON(st, "g/cnt/" + w, (d) => addCounts(d, p));
      if (r) { mem.cnt.set(w, r.value); if (r.created) dropOld(st, w); }
      else { const q = pend(w); q.d += p.d; for (const [h, cc] of p.hs) q.hs.set(h, cc); }
    }
    const now = winOf(Date.now());
    for (const k of [...mem.cnt.keys()]) if (k < now - 2) mem.cnt.delete(k);
    return true;
  })();
  mem.flushing = job.finally(() => { mem.flushing = null; });
  return job;
}
function estimate(w, t) {
  const W = guardCfg().window * 1000, cur = mem.cnt.get(w)?.n || 0, prev = mem.cnt.get(w - 1)?.n || 0;
  return Math.round(cur + prev * Math.max(0, 1 - (t - w * W) / W));
}
function countries(...docs) {
  const c = {};
  for (const d of docs) if (isObj(d?.c)) for (const k in d.c) c[k] = (c[k] || 0) + d.c[k];
  return Object.entries(c).sort((x, y) => y[1] - x[1]);
}
async function getMode(st, fresh) {
  const t = Date.now();
  if (!fresh && mem.mode && t - mem.modeT < 3000) return mem.mode;
  const m = await st.get("g/mode", { type: "json" });
  mem.mode = isObj(m) ? m : {}; mem.modeT = t;
  return mem.mode;
}
const attackOn = (m) => !!m && m.until > Date.now();
async function detect(st) {
  const g = guardCfg(), t = Date.now(), w = winOf(t);
  if (!mem.cnt.has(w)) return;
  if (!mem.cnt.has(w - 1)) mem.cnt.set(w - 1, (await st.get("g/cnt/" + (w - 1), { type: "json" })) || { n: 0 });
  const est = estimate(w, t);
  if (est > g.visitors) await startAttack(st, est, "visitors");
}
// One of GUARD_ADMIT places in the current window. The counter is shared by all server copies.
async function admitOne(st) {
  const g = guardCfg(), w = winOf(Date.now());
  if (mem.admFull === w) return false;
  const r = await casJSON(st, "g/adm/" + w, (d) => { const n = isObj(d) ? d.n || 0 : 0; return n >= g.admit ? undefined : { n: n + 1 }; });
  if (r && r.modified) { if (r.created) dropOld(st, w); return true; }
  mem.admFull = w;
  return false;
}
function busy() {
  const W = guardCfg().window * 1000, s = Math.ceil((W - (Date.now() % W)) / 1000) + 1 + Math.floor(Math.random() * 4);
  pend(winOf(Date.now())).d++;
  return json({ error: `Сейчас на сайт приходит слишком много запросов. Повторите через ${s} с`, code: "busy", retry: s }, 429, { "retry-after": String(s) });
}
const slow = () => fail(429, "slow-down", "Слишком часто. Подождите немного и повторите", { "retry-after": "20" });
async function guardInfo(st) {
  const g = guardCfg(), t = Date.now(), w = winOf(t);
  const [m, c0, c1, adm] = await Promise.all([getMode(st, true), st.get("g/cnt/" + w, { type: "json" }), st.get("g/cnt/" + (w - 1), { type: "json" }), st.get("g/adm/" + w, { type: "json" })]);
  if (c0) mem.cnt.set(w, c0);
  if (c1) mem.cnt.set(w - 1, c1);
  return {
    on: m.until > t, until: m.until || 0, since: m.since || 0, manual: !!m.manual, why: m.why || "", peak: m.peak || 0, quiet: m.quiet > t ? m.quiet : 0,
    est: c0 || c1 ? estimate(w, t) : 0, denied: (c0?.d || 0) + (c1?.d || 0), admitted: adm?.n || 0,
    over: (c0?.x || 0) + (c1?.x || 0) > 0, cap: HCAP, countries: countries(c0, c1).slice(0, 8), attackCountries: m.c || [], cfg: g,
  };
}
// Old counters are removed now and then, so the storage does not fill up after an attack.
async function sweep(st) {
  const t = Date.now(), w = winOf(t), h = hourOf(t), del = [];
  for (const pre of ["g/cnt/", "g/adm/", "g/new/"]) {
    const { blobs } = await st.list({ prefix: pre });
    for (const x of blobs) { const n = Number(x.key.slice(pre.length)); if (Number.isFinite(n) && n < w - 3) del.push(x.key); }
  }
  const r = await st.list({ prefix: "g/t/", directories: true }), hours = new Set();
  for (const s of [...(r.directories || []), ...(r.blobs || []).map((x) => x.key)]) { const mm = /^g\/t\/(\d+)/.exec(s); if (mm && Number(mm[1]) < h - 1) hours.add(mm[1]); }
  for (const hh of hours) { if (del.length >= 300) break; const { blobs } = await st.list({ prefix: "g/t/" + hh + "/" }); for (const x of blobs) del.push(x.key); }
  const list = del.slice(0, 300);
  for (let i = 0; i < list.length; i += 20) await Promise.all(list.slice(i, i + 20).map((k) => st.delete(k)));
}
// What a client's save adds compared with what is stored: new requests and messages.
function changes(old, next) {
  const R0 = isObj(old?.requests) ? old.requests : {}, R1 = isObj(next?.requests) ? next.requests : {};
  let newReqs = 0, newMsgs = 0, maxMsgs = 0, longMsg = false, badMsg = false;
  const keys = Object.keys(R1);
  for (const k of keys) {
    const r1 = R1[k], r0 = R0[k];
    if (!r0) newReqs++;
    const M1 = isObj(r1?.messages) ? r1.messages : {}, M0 = isObj(r0?.messages) ? r0.messages : {}, mk = Object.keys(M1);
    maxMsgs = Math.max(maxMsgs, mk.length);
    for (const j of mk) if (!M0[j]) { newMsgs++; if (String(M1[j]?.text || "").length > LIM.msgLen) longMsg = true; if (M1[j]?.from !== "client" || !str(M1[j]?.text, 1, LIM.msgLen)) badMsg = true; }
  }
  return { reqTotal: keys.length, newReqs, newMsgs, maxMsgs, longMsg, newKeys: keys.filter((k) => !R0[k]), badMsg };
}
// a new request must look like one sent from the order form
const str = (v, a, b) => typeof v === "string" && v.trim().length >= a && v.length <= b;
const validReq = (r, k) => isObj(r) && r.id === k && /^r[A-Za-z0-9_-]{3,60}$/.test(k) && str(r.name, 1, 100) && str(r.contact, 3, 120) && str(r.type, 1, 40) &&
  (r.comment == null || str(r.comment, 0, 4000)) && Number.isFinite(r.total) && r.total >= 0 && r.total < 1e9 && (r.status === undefined || r.status === "new");
async function startAttack(st, est, why) {
  const g = guardCfg(), t = Date.now(), w = winOf(t), m = await getMode(st, true);
  if (m.quiet > t) return m; // the admin switched the protection off by hand a few minutes ago
  if (m.until > t + (g.hold - 60) * 1000) return m; // already on and extended less than a minute ago
  const on = m.until > t;
  const next = { until: t + g.hold * 1000, since: on ? m.since : t, peak: Math.max(est || 0, on ? m.peak || 0 : 0), manual: on ? !!m.manual : false, why: on && m.why ? m.why : why, c: countries(mem.cnt.get(w), mem.cnt.get(w - 1)).slice(0, 8) };
  await st.setJSON("g/mode", next);
  mem.mode = next; mem.modeT = t;
  console.warn(`[guard] attack mode on (${why}${est ? ", ~" + est + " addresses in " + g.window + " s" : ""})`);
  return next;
}

export default async (req, context) => {
  const ctx = context || {};
  const url = new URL(req.url), m = req.method;
  const [a, b, c3] = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  const st = getStore({ name: "arturok-site", consistency: "strong" });
  const bg = (p) => { const q = Promise.resolve(p).catch((e) => console.error("[guard]", e)); try { ctx.waitUntil?.(q); } catch (e) {} return q; };
  try {
    const au = await getAuth(st);
    const ip = ctx.ip || req.headers.get("x-nf-client-connection-ip") || (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "0.0.0.0";
    const cc = /^[A-Z]{2}$/.test(ctx.geo?.country?.code || "") ? ctx.geo.country.code : "??";
    const ipH = mac(au.secret, "ip:" + ip).slice(0, 22);
    note(ipH, cc);
    if (!hit(mem.ipHits, ipH, 60, 10e3)) return slow();
    if (mem.pending.size && !mem.flushing && Date.now() - mem.lastFlush >= 2000) bg(flush(st).then((did) => did && detect(st)));
    if (Date.now() - mem.lastSweep > 20 * 60e3 && Math.random() < 0.05) { mem.lastSweep = Date.now(); bg(sweep(st)); }

    // ----- public -----
    if (a === "state" && m === "GET") {
      // Everyone gets the same texts and prices, so Netlify's cache serves them (fresh within 15–45 s).
      // The admin asks with ?v=… and gets them straight from the storage.
      const ask = url.searchParams.has("v"), fresh = ask && (await isAdmin(st, req));
      let body = !fresh && mem.state && Date.now() - mem.stateT < 10000 ? mem.state : null;
      if (!body) {
        const [content, config] = await Promise.all([st.get("site/content", { type: "json" }), st.get("site/config", { type: "json" })]);
        body = JSON.stringify({ content: content ?? null, config: config ?? null });
        mem.state = body; mem.stateT = Date.now();
      }
      return new Response(body, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-cache", "netlify-vary": "query=v", "netlify-cdn-cache-control": ask ? "no-store" : "public, s-maxage=15, stale-while-revalidate=30" } });
    }
    if (a === "img" && b && m === "GET") {
      if (!IMGID.test(b)) return fail(404, "not_found");
      const r = await st.getWithMetadata("img/" + b, { type: "arrayBuffer" });
      if (!r) return fail(404, "not_found");
      const type = IMG_TYPES.includes(r.metadata?.type) ? r.metadata.type : "application/octet-stream";
      return new Response(r.data, { headers: { "content-type": type, "cache-control": "public, max-age=31536000, immutable", "netlify-cdn-cache-control": "public, durable, max-age=31536000, immutable", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox" } });
    }
    if (a === "login" && m === "POST") {
      const t = Date.now(), h = hourOf(t), abroad = cc !== "RU" && cc !== "??";
      const k0 = `g/t/${h}/lock/${ipH}`, k1 = `g/t/${h - 1}/lock/${ipH}`;
      const [l0, l1, ga] = await Promise.all([st.get(k0, { type: "json" }), st.get(k1, { type: "json" }), abroad ? st.get("g/lockall", { type: "json" }) : null]);
      const until = Math.max(l0?.until || 0, l1?.until || 0, abroad ? ga?.until || 0 : 0);
      if (until > t) { const s = Math.ceil((until - t) / 1000); return fail(429, "too-many-requests", `Слишком много попыток. Повторите через ${Math.ceil(s / 60)} мин`, { "retry-after": String(s) }); }
      const body = await readJson(req, 4000), fa = await getAuth(st, true);
      const ok = checkPassword(fa, String(body?.password || ""));
      if (ok === null) return fail(503, "not-configured", "ADMIN_PASSWORD не задан");
      if (!ok) {
        const f = (l0?.f || 0) + 1;
        await st.setJSON(k0, f >= LIM.loginFailsPerIp ? { f: 0, until: t + 10 * 60e3 } : { f, until: 0 });
        if (abroad) await casJSON(st, "g/lockall", (d) => {
          const x = isObj(d) && t - (d.start || 0) < 10 * 60e3 ? { ...d } : { n: 0, start: t, until: isObj(d) ? d.until || 0 : 0 };
          x.n = (x.n || 0) + 1;
          if (x.n >= LIM.loginFailsAbroad) { x.until = t + 10 * 60e3; x.n = 0; x.start = t; console.warn("[guard] many wrong passwords from abroad, login from abroad paused"); }
          return x;
        }, 3);
        await sleep(400);
        return fail(401, "wrong-password", "Неверный пароль");
      }
      if (l0) bg(st.delete(k0));
      if (l1) bg(st.delete(k1));
      return json({ token: sign(fa) });
    }
    // ----- a client's own requests (identified by a random id kept in their browser) -----
    if (a === "my") {
      const cid = req.headers.get("x-client") || "";
      if (!CID.test(cid)) return fail(400, "invalid_argument");
      const key = "orders/" + cid, pi = passInfo(au, req.headers.get("x-pass"), cid);
      const mode = await getMode(st), attack = attackOn(mode), ok = trusted(pi, mode);
      if (m === "GET") {
        if (attack && !ok) return busy();
        const data = (await st.get(key, { type: "json" })) ?? null;
        return json({ data }, 200, data && !pi ? { "x-pass": passFor(au, cid) } : {});
      }
      if (m !== "PUT" && m !== "PATCH") return fail(405, "method_not_allowed");
      if (!hit(mem.cidHits, cid, LIM.clientWritesPerMin, 60e3)) return slow();
      let newPass = null;
      if (attack && !ok) {
        if (!(await admitOne(st))) return busy();
        newPass = passFor(au, cid, true);
      }
      const body = await readJson(req, MAX_ORDER);
      if (!isObj(body)) return fail(400, "invalid_argument");
      const cur = await st.getWithMetadata(key, { type: "json" });
      const old = cur?.data || null, meta = isObj(cur?.metadata) ? cur.metadata : {};
      const next = m === "PATCH" ? merge(old || {}, body) : body;
      if (JSON.stringify(next).length > MAX_ORDER) return fail(413, "too_large");
      const t = Date.now(), recent = (arr, ms) => (Array.isArray(arr) ? arr : []).filter((x) => typeof x === "number" && t - x < ms && x <= t);
      const w = recent(meta.w, 60e3), rq = recent(meta.rq, 3600e3), ms = recent(meta.ms, 60e3);
      if (w.length >= LIM.clientWritesPerMin) return slow();
      const d = changes(old, next);
      if (d.reqTotal > LIM.clientReqsTotal || d.maxMsgs > LIM.msgsPerReq || d.longMsg) return fail(413, "too_large");
      if (d.badMsg || d.newKeys.some((k) => !validReq(next.requests[k], k))) return fail(400, "bad_request", "Заявка заполнена неверно");
      if (d.newReqs && rq.length + d.newReqs > LIM.clientReqsPerHour) return slow();
      if (d.newMsgs && ms.length + d.newMsgs > LIM.clientMsgsPerMin) return slow();
      let ipoKey = null, ipo = null, since = attack ? mode.since || t : 0;
      if (!old) {
        ipoKey = `g/t/${hourOf(t)}/ipo/${ipH}`;
        ipo = (await st.get(ipoKey, { type: "json" })) || { n: 0 };
        if (ipo.n >= LIM.newClientsPerIpHour) return slow();
        // a wave of new clients switches the protection on at once, without waiting for the visitor count
        if (!attack) {
          const r = await casJSON(st, "g/new/" + winOf(t), (x) => ({ n: (isObj(x) ? x.n || 0 : 0) + 1 }));
          if (r && r.created) dropOld(st, winOf(t));
          if (r && r.value.n > guardCfg().newMax) { const mm = await startAttack(st, 0, "new"); if (attackOn(mm)) since = mm.since || t; }
        }
      }
      if (since && d.newReqs) {
        // in attack mode every new request from a visitor who was not a client before the attack takes a place in the queue
        const oldClient = !!pi && !pi.adm && trusted(pi, { until: t + 1, since });
        if (!oldClient) {
          if (!newPass) { if (!(await admitOne(st))) return busy(); newPass = passFor(au, cid, true); }
          for (const k of d.newKeys) next.requests[k].q = since;
        }
      }
      for (const k of d.newKeys) Object.assign(next.requests[k], { createdAt: t, updatedAt: t, status: "new", seenByAdmin: false });
      await st.setJSON(key, next, { metadata: { w: [...w, t], rq: [...rq, ...Array(Math.min(d.newReqs, 20)).fill(t)], ms: [...ms, ...Array(Math.min(d.newMsgs, 20)).fill(t)] } });
      if (ipoKey) await st.setJSON(ipoKey, { n: ipo.n + 1 });
      const np = newPass || (pi ? null : passFor(au, cid));
      return json({ ok: true }, 200, np ? { "x-pass": np } : {});
    }
    // ----- admin only -----
    if (!(await isAdmin(st, req))) return fail(401, "permission-denied", "Нужен вход в админку");
    if (a === "me") return json({ admin: true });
    if (a === "site" && (b === "content" || b === "config") && m === "PUT") {
      const body = await readJson(req, MAX_JSON);
      if (!isObj(body)) return fail(400, "invalid_argument");
      await st.setJSON("site/" + b, body);
      mem.state = null;
      return json({ ok: true });
    }
    if (a === "orders" && !b && m === "GET") {
      // only requests that changed since the last look are read again
      const { blobs } = await st.list({ prefix: "orders/" }), keys = new Set();
      const docs = (await Promise.all(blobs.map(async (x) => {
        keys.add(x.key);
        const c = mem.docs.get(x.key);
        if (c && x.etag && c.etag === x.etag) return { id: x.key.slice(7), data: c.data };
        const data = await st.get(x.key, { type: "json" });
        if (x.etag) mem.docs.set(x.key, { etag: x.etag, data });
        return { id: x.key.slice(7), data };
      }))).filter((d) => d.data);
      for (const k of [...mem.docs.keys()]) if (!keys.has(k)) mem.docs.delete(k);
      const queued = docs.reduce((n, x) => n + Object.values(isObj(x.data.requests) ? x.data.requests : {}).filter((r) => isObj(r) && r.q && r.status === "new").length, 0);
      return json({ docs, guard: { ...(await guardInfo(st)), queued } });
    }
    const untouched = (r) => isObj(r) && r.q && r.status === "new" && !r.finalPrice && !Object.values(isObj(r.messages) ? r.messages : {}).some((x) => x?.from === "studio");
    async function dropRequests(key, pick) {
      const cur = await st.getWithMetadata(key, { type: "json" }), doc = cur?.data;
      if (!isObj(doc?.requests)) return 0;
      const R = { ...doc.requests }, gone = Object.keys(R).filter((k) => pick(R[k], k));
      if (!gone.length) return 0;
      gone.forEach((k) => delete R[k]);
      if (!Object.keys(R).length) await st.delete(key);
      else await st.setJSON(key, { ...doc, requests: R }, isObj(cur.metadata) ? { metadata: cur.metadata } : {});
      return gone.length;
    }
    if (a === "orders" && b === "purge" && !c3 && m === "POST") {
      // removes requests that came through the queue during an attack and that nobody has worked on
      const { blobs } = await st.list({ prefix: "orders/" });
      let removed = 0;
      for (let i = 0; i < blobs.length; i += 20) removed += (await Promise.all(blobs.slice(i, i + 20).map((x) => dropRequests(x.key, untouched)))).reduce((s2, n) => s2 + n, 0);
      return json({ ok: true, removed });
    }
    if (a === "orders" && b && c3 && m === "DELETE") {
      if (!CID.test(b)) return fail(400, "invalid_argument");
      return json({ ok: true, removed: await dropRequests("orders/" + b, (r, k) => k === c3) });
    }
    if (a === "orders" && b && m === "PATCH") {
      if (!CID.test(b)) return fail(400, "invalid_argument");
      const key = "orders/" + b, body = await readJson(req, MAX_ORDER);
      if (!isObj(body)) return fail(400, "invalid_argument");
      const cur = await st.getWithMetadata(key, { type: "json" });
      await st.setJSON(key, merge(cur?.data || {}, body), isObj(cur?.metadata) ? { metadata: cur.metadata } : {});
      return json({ ok: true });
    }
    if (a === "guard" && !b && m === "GET") return json({ guard: await guardInfo(st) });
    if (a === "guard" && !b && m === "POST") {
      const body = await readJson(req, 1000), t = Date.now();
      const next = body?.on ? { until: t + 3600e3, since: t, manual: true, peak: 0, c: [] } : { until: 0, quiet: t + 15 * 60e3 };
      await st.setJSON("g/mode", next);
      mem.mode = next; mem.modeT = t;
      return json({ ok: true, guard: await guardInfo(st) });
    }
    if (a === "img" && !b && m === "POST") {
      const type = (req.headers.get("content-type") || "").split(";")[0].trim();
      if (!IMG_TYPES.includes(type)) return fail(415, "unsupported_type");
      const buf = await req.arrayBuffer();
      if (!buf.byteLength) return fail(400, "invalid_argument");
      if (buf.byteLength > MAX_IMG) return fail(413, "too_large");
      const id = "n" + Date.now().toString(36) + crypto.randomBytes(6).toString("hex");
      await st.set("img/" + id, buf, { metadata: { type } });
      return json({ id });
    }
    if (a === "img" && b && m === "DELETE") {
      if (IMGID.test(b)) await st.delete("img/" + b);
      return json({ ok: true });
    }
    if (a === "password" && m === "POST") {
      const body = await readJson(req, 4000), fa = await getAuth(st, true);
      if (checkPassword(fa, String(body?.old || "")) !== true) return fail(403, "wrong-password", "Текущий пароль неверный");
      const nw = String(body?.new || "");
      if (nw.length < 8) return fail(400, "weak-password", "Пароль короче 8 символов");
      const next = { ...fa, salt: crypto.randomBytes(16).toString("hex") };
      next.hash = pbk(nw, next.salt);
      next.ver = (fa.ver || 1) + 1;
      delete next.fails; delete next.lockUntil;
      await st.setJSON("auth", next);
      authC = next; authT = Date.now();
      return json({ ok: true, token: sign(next) });
    }
    return fail(404, "not_found");
  } catch (e) {
    if (e && e.status) return fail(e.status, e.code);
    console.error(e);
    return fail(500, "server_error");
  }
};
