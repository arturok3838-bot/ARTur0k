// «Номера города» — аккаунты игроков и облачное сохранение прогресса.
// Отдельная функция: свой адрес /game/api и своё хранилище "nomera-game", сайт АРТурок и заявки не затрагиваются.
// Игра открывается с GitHub Pages (arturok3838-bot.github.io) и шлёт сюда простой POST с текстом JSON:
//   { op: "register" | "login" | "load" | "save" | "me" | "password", login, password, token, save, base }
// Пароли хранятся только как PBKDF2-хеш с солью, вход — по подписанному токену на 180 дней.
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = {
  path: "/game/api",
  rateLimit: { action: "rate_limit", windowLimit: 90, windowSize: 60, aggregateBy: ["ip", "domain"] },
};

const MAX_SAVE = 1_500_000;
const LOGIN_RE = /^[a-z0-9][a-z0-9_.-]{2,23}$/;
const ORIGINS = ["https://arturok3838-bot.github.io"];
const mem = { saveT: new Map() };

const env = (k) => { try { const v = globalThis.Netlify?.env?.get(k); if (v != null && v !== "") return v; } catch (e) {} return process.env[k] || null; };
const origins = () => [...ORIGINS, ...String(env("GAME_ORIGINS") || "").split(",").map((x) => x.trim()).filter(Boolean)];
const mac = (key, s) => crypto.createHmac("sha256", key).update(String(s)).digest("base64url");
const same = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const pbk = (pw, salt) => crypto.pbkdf2Sync(String(pw), salt, 150000, 32, "sha256").toString("hex");
const hourOf = (t) => Math.floor(t / 3600e3), tenOf = (t) => Math.floor(t / 600e3);

function cors(res, req) {
  const o = req.headers.get("origin"), list = origins();
  res.headers.set("access-control-allow-origin", o && list.includes(o) ? o : list[0]);
  res.headers.append("vary", "Origin");
  return res;
}
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const fail = (s, code, msg) => json({ error: msg || code, code }, s);

async function secretOf(st) {
  let s = await st.get("secret", { type: "json" });
  if (s && s.k) return s.k;
  const k = crypto.randomBytes(32).toString("hex");
  await st.setJSON("secret", { k }, { onlyIfNew: true });
  s = await st.get("secret", { type: "json" });
  return s.k;
}
function sign(key, u, v) {
  const p = Buffer.from(JSON.stringify({ u, v, exp: Date.now() + 180 * 864e5 })).toString("base64url");
  return p + "." + mac(key, "game:" + p);
}
function readTok(key, tok) {
  const [p, s] = String(tok || "").split(".");
  if (!p || !s || p.length > 400 || !same(s, mac(key, "game:" + p))) return null;
  try { const d = JSON.parse(Buffer.from(p, "base64url").toString()); return d.exp > Date.now() ? d : null; } catch (e) { return null; }
}
// счётчик в хранилище: n попыток в окне
async function bump(st, key, max) {
  const c = (await st.get(key, { type: "json" })) || { n: 0 };
  if (c.n >= max) return false;
  await st.setJSON(key, { n: c.n + 1 });
  return true;
}
const over = async (st, key, max) => ((await st.get(key, { type: "json" })) || { n: 0 }).n >= max;

export default async (req, context) => {
  if (req.method === "OPTIONS") return cors(new Response(null, { status: 204, headers: { "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type", "access-control-max-age": "86400" } }), req);
  if (req.method !== "POST") return cors(fail(405, "method_not_allowed"), req);
  try { return cors(await handle(req, context || {}), req); }
  catch (e) { console.error("[game]", e); return cors(fail(500, "server", "Ошибка сервера, попробуй позже"), req); }
};

async function handle(req, ctx) {
  const t = await req.text();
  if (t.length > MAX_SAVE + 4000) return fail(413, "too_large", "Сохранение слишком большое");
  let b;
  try { b = JSON.parse(t); } catch (e) { return fail(400, "bad_json"); }
  const st = getStore({ name: "nomera-game", consistency: "strong" });
  const key = await secretOf(st), now = Date.now();
  const ip = ctx.ip || req.headers.get("x-nf-client-connection-ip") || (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "0.0.0.0";
  const ipH = mac(key, "ip:" + ip).slice(0, 22);
  const op = String(b?.op || "");
  const login = String(b?.login || "").trim().toLowerCase(), pw = String(b?.password || "");

  if (op === "register") {
    if (!LOGIN_RE.test(login)) return fail(400, "bad-login", "Логин: 3–24 символа — латинские буквы, цифры, точка, дефис или подчёркивание");
    if (pw.length < 6 || pw.length > 200) return fail(400, "weak-password", "Пароль — не короче 6 символов");
    if (!(await bump(st, `lim/reg/${hourOf(now)}/${ipH}`, 6))) return fail(429, "slow", "Слишком много регистраций, попробуй через час");
    const salt = crypto.randomBytes(16).toString("hex");
    const r = await st.setJSON("users/" + login, { login, salt, hash: pbk(pw, salt), ver: 1, createdAt: now }, { onlyIfNew: true });
    if (!r || !r.modified) return fail(409, "login-taken", "Этот логин уже занят");
    return json({ login, token: sign(key, login, 1) });
  }
  if (op === "login") {
    const fk = `lim/fail/${tenOf(now)}/${ipH}`;
    if (await over(st, fk, 10)) return fail(429, "slow", "Слишком много попыток, подожди 10 минут");
    const rec = LOGIN_RE.test(login) ? await st.get("users/" + login, { type: "json" }) : null;
    if (!rec || !same(pbk(pw, rec.salt), rec.hash)) { await bump(st, fk, 1e9); return fail(403, "wrong", "Неверный логин или пароль"); }
    const sv = await st.getMetadata("saves/" + login).catch(() => null);
    return json({ login, token: sign(key, login, rec.ver || 1), at: sv?.metadata?.at || 0 });
  }

  // дальше — только с токеном
  const d = readTok(key, b?.token);
  if (!d) return fail(401, "no-account", "Войди в аккаунт заново");
  const rec = await st.get("users/" + d.u, { type: "json" });
  if (!rec || (rec.ver || 1) !== d.v) return fail(401, "no-account", "Войди в аккаунт заново");

  if (op === "me") {
    const sv = await st.getMetadata("saves/" + d.u).catch(() => null);
    return json({ login: d.u, at: sv?.metadata?.at || 0 });
  }
  if (op === "load") {
    const sv = await st.getWithMetadata("saves/" + d.u, { type: "text" });
    return json({ login: d.u, at: sv?.metadata?.at || 0, save: sv?.data || null });
  }
  if (op === "save") {
    const s = b?.save, at = now;
    if (typeof s !== "string" || !s.length) return fail(400, "bad-save");
    if (s.length > MAX_SAVE) return fail(413, "too_large", "Сохранение слишком большое");
    const last = mem.saveT.get(d.u) || 0;
    if (now - last < 2500) return fail(429, "slow", "Слишком часто");
    mem.saveT.set(d.u, now);
    const cur = await st.getMetadata("saves/" + d.u).catch(() => null), curAt = cur?.metadata?.at || 0;
    // с момента последней синхронизации этого устройства прогресс сохранили с другого — не затираем его
    if (!b?.force && curAt && Number(b?.base) !== curAt) return json({ ok: false, stale: true, at: curAt });
    await st.set("saves/" + d.u, s, { metadata: { at, size: s.length } });
    return json({ ok: true, at });
  }
  if (op === "password") {
    const nw = String(b?.new || "");
    if (!same(pbk(String(b?.old || ""), rec.salt), rec.hash)) return fail(403, "wrong", "Текущий пароль неверный");
    if (nw.length < 6) return fail(400, "weak-password", "Пароль — не короче 6 символов");
    const salt = crypto.randomBytes(16).toString("hex"), next = { ...rec, salt, hash: pbk(nw, salt), ver: (rec.ver || 1) + 1 };
    await st.setJSON("users/" + d.u, next);
    return json({ ok: true, token: sign(key, d.u, next.ver) });
  }
  return fail(404, "not_found");
}
