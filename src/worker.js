// AU Hair Accessories — store backend + admin API
// Static site files are served from ./public (ASSETS). Everything under /api/* runs here.

const COLOURS = ["black", "brown", "dark-brown", "nude", "wine", "red", "pink", "purple", "royal-blue", "sky-blue", "white"];
const STATUSES = ["new", "confirmed", "dispatched", "delivered", "cancelled"];
const STEPS = ["new", "confirmed", "dispatched", "delivered"]; // the order journey; cancelled sits outside it
const SOLD = "('confirmed','dispatched','delivered')"; // confirmed = payment received
const normStatus = (s) => (s === "paid" ? "confirmed" : s);
const SHOP = { name: "AU Hair Accessories", address: "Shop A1, by Bayelsa Plaza, BBA Trade Fair Complex, Lagos", phone: "0912 643 3425", wa: "2349126433425", ig: "@auhairaccessories", web: "auhairaccessories.com" };
function custKey(phone) { let d = String(phone || "").replace(/\D/g, ""); if (d.startsWith("234")) d = d.slice(3); d = d.replace(/^0+/, ""); return d.length >= 7 ? d.slice(-10) : ""; }
function stageStamps(before, to) {
  // returns column updates so every step up to "to" has a time, and steps after it are cleared
  const now = nowISO(), f = {};
  if (to === "cancelled") { f.cancelled_at = now; return f; }
  f.cancelled_at = null;
  const idx = STEPS.indexOf(to);
  STEPS.slice(1).forEach((s, i) => { const k = s + "_at"; if (i + 1 <= idx) f[k] = before[k] || now; else f[k] = null; });
  return f;
}
const b64ToBytes = (d) => { const b = atob(String(d || "").replace(/^data:[^,]+,/, "")); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; };
const randTok = () => { const a = new Uint8Array(18); crypto.getRandomValues(a); return b64u(a); };
const EVENT_TYPES = ["page_view", "select_colour", "select_unit", "add_to_cart", "remove_from_cart", "open_cart", "start_checkout", "order_sent", "click_whatsapp", "click_social", "view_section"];

const DEFAULT_CATALOG = {
  store: { announcement: "", whatsapp: "2349126433425", metaPixel: "", tiktokPixel: "" },
  products: {
    regular: { hidden: false, dz: 1500, bulk: 1400, stockBig: null, colours: Object.fromEntries(COLOURS.map((c) => [c, { dozen: true, big: c === "black" }])) },
    mixed: { hidden: false, dz: null, bulk: 1400, stockBig: 2, colours: { mixed: { dozen: false, big: true } } },
    diy: { hidden: false, dz: 5500, bulk: 5200, stockBig: null, colours: { black: { dozen: true, big: true } } },
    stretch: { hidden: false, dz: 5500, bulk: 5200, stockBig: null, colours: { black: { dozen: true, big: true } } },
  },
};

const json = (d, status = 200, headers = {}) =>
  new Response(JSON.stringify(d), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const nowISO = () => new Date().toISOString();
const clampStr = (s, n = 300) => (s == null ? null : String(s).slice(0, n));

function deepMerge(base, over) {
  if (Array.isArray(base) || typeof base !== "object" || base === null) return over === undefined ? base : over;
  const out = { ...base };
  if (over && typeof over === "object") for (const k of Object.keys(over)) out[k] = k in base ? deepMerge(base[k], over[k]) : over[k];
  return out;
}

async function getSetting(env, key) {
  const r = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
  return r ? JSON.parse(r.value) : null;
}
async function setSetting(env, key, value) {
  await env.DB.prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
    .bind(key, JSON.stringify(value), nowISO()).run();
}
async function getCatalog(env) {
  return deepMerge(DEFAULT_CATALOG, (await getSetting(env, "catalog")) || {});
}
async function audit(env, { action, entity, entity_id, summary, before, after, undo_of = null }) {
  await env.DB.prepare("INSERT INTO audit (ts, action, entity, entity_id, summary, before, after, undo_of) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(nowISO(), action, entity, String(entity_id ?? ""), summary, before == null ? null : JSON.stringify(before), after == null ? null : JSON.stringify(after), undo_of).run();
}

// ---------- auth ----------
const enc = new TextEncoder();
// Password: once changed from the dashboard it is stored hashed (PBKDF2) in settings and replaces the original secret.
async function storedPw(env) { try { return await getSetting(env, "admin_pw"); } catch { return null; } }
async function pbkdf2(pw, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return b64u(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
async function passwordOk(env, pw) {
  const st = await storedPw(env);
  if (st && st.hash) return safeEqual(await pbkdf2(String(pw || ""), st.salt), st.hash);
  return !!env.ADMIN_PASSWORD && safeEqual(String(pw || ""), env.ADMIN_PASSWORD);
}
async function hmacKey(env) {
  const st = await storedPw(env);
  const raw = await crypto.subtle.digest("SHA-256", enc.encode("au-admin-session:" + (env.ADMIN_PASSWORD || "") + ":" + (st?.hash || "")));
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function makeToken(env) {
  const exp = Date.now() + 30 * 24 * 3600 * 1000;
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(String(exp)));
  return `${exp}.${b64u(sig)}`;
}
async function checkToken(env, tok) {
  if (!tok) return false;
  const [exp, sig] = tok.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  const expect = b64u(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(exp)));
  if (expect.length !== sig.length) return false;
  let diff = 0; for (let i = 0; i < sig.length; i++) diff |= expect.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}
function getCookie(req, name) {
  const c = req.headers.get("cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb); let d = 0; for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i]; return d === 0;
}

// ---------- helpers ----------
function deviceOf(ua = "") { if (/iPad|Tablet/i.test(ua)) return "tablet"; if (/Mobi|Android|iPhone/i.test(ua)) return "mobile"; return "desktop"; }
function sourceOf(referrer, utm) {
  if (utm) return String(utm).toLowerCase().slice(0, 40);
  if (!referrer) return "direct";
  let h = ""; try { h = new URL(referrer).hostname.toLowerCase(); } catch { return "direct"; }
  if (/auhairaccessories\.com|workers\.dev/.test(h)) return "internal";
  if (/facebook|fb\.|m\.facebook|l\.facebook/.test(h)) return "facebook";
  if (/instagram/.test(h)) return "instagram";
  if (/whatsapp|wa\.me|l\.wl\.co/.test(h)) return "whatsapp";
  if (/tiktok/.test(h)) return "tiktok";
  if (/google\./.test(h)) return "google";
  if (/t\.co|twitter|x\.com/.test(h)) return "x";
  return h.replace(/^www\./, "").slice(0, 40);
}
function rangeStart(days) { const d = new Date(); d.setUTCHours(0, 0, 0, 0); d.setUTCDate(d.getUTCDate() - (days - 1)); return d.toISOString(); }
// Lagos is UTC+1: shift for "today" and daily buckets
const LAGOS = "+1 hour";

async function readBody(req, max = 20000) {
  const t = await req.text();
  if (t.length > max) throw Object.assign(new Error("Body too large"), { status: 413 });
  return t ? JSON.parse(t) : {};
}
function orderRow(o) { return o && { ...o, status: normStatus(o.status), items: o.items ? JSON.parse(o.items) : [], deleted: !!o.deleted, customer: custKey(o.phone) }; }
const ORDER_SELECT = "SELECT o.*, r.token receipt_token, r.updated_at receipt_at, r.sent_at receipt_sent FROM orders o LEFT JOIN receipts r ON r.ref = o.ref";
const getOrder = async (env, ref) => orderRow(await env.DB.prepare(`${ORDER_SELECT} WHERE o.ref = ?`).bind(ref).first());

// ---------- public API ----------
async function publicApi(req, env, url, ctx) {
  const p = url.pathname, cf = req.cf || {};
  if (p === "/api/catalog" && req.method === "GET") {
    return json(await getCatalog(env), 200, { "cache-control": "no-store" });
  }
  if (p === "/api/event" && req.method === "POST") {
    const b = await readBody(req, 4000);
    const evs = Array.isArray(b.events) ? b.events.slice(0, 20) : [b];
    const ua = req.headers.get("user-agent") || "";
    const stmts = [];
    for (const e of evs) {
      if (!EVENT_TYPES.includes(e.type)) continue;
      stmts.push(env.DB.prepare("INSERT INTO events (ts, type, path, referrer, source, visitor, session, country, region, city, device, data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(nowISO(), e.type, clampStr(e.path, 200), clampStr(e.referrer, 300), sourceOf(e.referrer, e.utm), clampStr(e.visitor, 40), clampStr(e.session, 40),
          clampStr(cf.country, 4), clampStr(cf.region, 60), clampStr(cf.city, 60), deviceOf(ua), e.data ? clampStr(JSON.stringify(e.data), 1500) : null));
    }
    if (stmts.length) ctx.waitUntil(env.DB.batch(stmts));
    return json({ ok: true });
  }
  if (p === "/api/order" && req.method === "POST") {
    const b = await readBody(req, 20000);
    const c = b.customer || {};
    const items = (Array.isArray(b.items) ? b.items : []).slice(0, 50).map((i) => ({
      id: clampStr(i.id, 20), name: clampStr(i.name, 60), colour: clampStr(i.colour, 30), colourName: clampStr(i.colourName, 30),
      unit: i.unit === "big" ? "big" : "dozen", unitName: clampStr(i.unitName, 20), qty: Math.max(1, Math.min(9999, parseInt(i.qty) || 1)),
      dozens: Math.max(0, parseInt(i.dozens) || 0), price: Math.max(0, parseInt(i.price) || 0), line: Math.max(0, parseInt(i.line) || 0) }));
    if (!items.length) return json({ error: "No items" }, 400);
    const total = items.reduce((a, i) => a + i.line, 0);
    let ref = /^AU-[A-Z0-9]{4,8}$/.test(b.ref || "") ? b.ref : "AU-" + Math.random().toString(36).slice(2, 7).toUpperCase();
    const ins = (r) => env.DB.prepare("INSERT INTO orders (ref, created_at, updated_at, name, phone, state, lga, park, address, items, total, status, visitor, source) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'new', ?, ?)")
      .bind(r, nowISO(), nowISO(), clampStr(c.name, 100), clampStr(c.phone, 30), clampStr(c.state, 40), clampStr(c.lga, 60), clampStr(c.park, 120), clampStr(c.address, 300),
        JSON.stringify(items), total, clampStr(b.visitor, 40), clampStr(b.source, 40) || "website").run();
    try { await ins(ref); } catch (e) { ref = ref + "-" + Math.random().toString(36).slice(2, 4).toUpperCase(); await ins(ref); }
    return json({ ok: true, ref });
  }
  return json({ error: "Not found" }, 404);
}

// ---------- admin API ----------
async function adminApi(req, env, url) {
  const p = url.pathname, m = req.method;
  if (p === "/api/admin/login" && m === "POST") {
    const b = await readBody(req, 1000);
    if (!(await passwordOk(env, b.password))) {
      await new Promise((r) => setTimeout(r, 700));
      return json({ error: "Wrong password" }, 401);
    }
    const tok = await makeToken(env);
    return json({ ok: true }, 200, { "set-cookie": `au_admin=${tok}; Path=/api/admin; Max-Age=${30 * 24 * 3600}; HttpOnly; Secure; SameSite=Strict` });
  }
  if (p === "/api/admin/logout") return json({ ok: true }, 200, { "set-cookie": "au_admin=; Path=/api/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict" });
  if (!(await checkToken(env, getCookie(req, "au_admin")))) return json({ error: "Not signed in" }, 401);

  if (p === "/api/admin/me") return json({ ok: true });
  if (p === "/api/admin/password" && m === "POST") {
    const b = await readBody(req, 2000);
    if (!(await passwordOk(env, b.current))) { await new Promise((r) => setTimeout(r, 700)); return json({ error: "Your current password is wrong" }, 400); }
    const next = String(b.next || "");
    if (next.length < 8) return json({ error: "New password needs at least 8 characters" }, 400);
    if (next.length > 100) return json({ error: "New password is too long" }, 400);
    const salt = randTok();
    await setSetting(env, "admin_pw", { salt, hash: await pbkdf2(next, salt), changed_at: nowISO() });
    await audit(env, { action: "password", entity: "password", entity_id: "admin", summary: "Admin password changed", before: null, after: null });
    const tok = await makeToken(env); // new key: every other signed-in device is signed out
    return json({ ok: true }, 200, { "set-cookie": `au_admin=${tok}; Path=/api/admin; Max-Age=${30 * 24 * 3600}; HttpOnly; Secure; SameSite=Strict` });
  }

  // ---- summary / analytics
  if (p === "/api/admin/summary" && m === "GET") {
    const days = Math.max(1, Math.min(365, parseInt(url.searchParams.get("days")) || 30));
    const since = rangeStart(days);
    const todayStart = (() => { const d = new Date(Date.now() + 3600e3); d.setUTCHours(0, 0, 0, 0); return new Date(d.getTime() - 3600e3).toISOString(); })();
    const q = (sql, ...a) => env.DB.prepare(sql).bind(...a);
    const [vis, today, funnel, ordersAgg, statusAgg, daily, dailyOrders, sources, devices, cities, states, hours, topAdds, live, totalsAll] = await env.DB.batch([
      q("SELECT COUNT(DISTINCT visitor) v, COUNT(DISTINCT session) s, SUM(type='page_view') pv FROM events WHERE ts >= ?", since),
      q("SELECT COUNT(DISTINCT visitor) v, SUM(type='page_view') pv FROM events WHERE ts >= ?", todayStart),
      q(`SELECT type, COUNT(DISTINCT visitor) v, COUNT(*) n FROM events WHERE ts >= ? GROUP BY type`, since),
      q("SELECT COUNT(*) n, COALESCE(SUM(total),0) v FROM orders WHERE deleted=0 AND created_at >= ?", since),
      q("SELECT status, COUNT(*) n, COALESCE(SUM(total),0) v FROM orders WHERE deleted=0 AND created_at >= ? GROUP BY status", since),
      q(`SELECT date(ts, '${LAGOS}') d, COUNT(DISTINCT visitor) v, SUM(type='page_view') pv, SUM(type='add_to_cart') atc FROM events WHERE ts >= ? GROUP BY d ORDER BY d`, since),
      q(`SELECT date(created_at, '${LAGOS}') d, COUNT(*) n, COALESCE(SUM(total),0) v, SUM(CASE WHEN status IN ${SOLD} THEN total ELSE 0 END) sold FROM orders WHERE deleted=0 AND created_at >= ? GROUP BY d ORDER BY d`, since),
      q("SELECT source, COUNT(DISTINCT visitor) v FROM events WHERE ts >= ? AND type='page_view' AND source != 'internal' GROUP BY source ORDER BY v DESC LIMIT 12", since),
      q("SELECT device, COUNT(DISTINCT visitor) v FROM events WHERE ts >= ? GROUP BY device ORDER BY v DESC", since),
      q("SELECT COALESCE(city,'Unknown') city, COALESCE(country,'') country, COUNT(DISTINCT visitor) v FROM events WHERE ts >= ? GROUP BY city, country ORDER BY v DESC LIMIT 12", since),
      q("SELECT COALESCE(state,'Unknown') state, COUNT(*) n, COALESCE(SUM(total),0) v FROM orders WHERE deleted=0 AND created_at >= ? GROUP BY state ORDER BY n DESC LIMIT 15", since),
      q(`SELECT CAST(strftime('%H', ts, '${LAGOS}') AS INTEGER) h, COUNT(DISTINCT visitor) v FROM events WHERE ts >= ? GROUP BY h`, since),
      q("SELECT json_extract(data,'$.id') pid, json_extract(data,'$.colour') pcolour, json_extract(data,'$.unit') punit, COUNT(*) n FROM events WHERE ts >= ? AND type='add_to_cart' GROUP BY pid, pcolour, punit ORDER BY n DESC LIMIT 15", since),
      q("SELECT ts, type, path, source, city, country, device, visitor, data FROM events ORDER BY id DESC LIMIT 25"),
      q("SELECT COUNT(*) n, COALESCE(SUM(total),0) v FROM orders WHERE deleted=0"),
    ]);
    const r = (x) => x.results || [];
    const [soldAgg, waitingAgg, attention, orderSources, allSold] = await env.DB.batch([
      q(`SELECT COUNT(*) n, COALESCE(SUM(total),0) v FROM orders WHERE deleted=0 AND status IN ${SOLD} AND COALESCE(confirmed_at, created_at) >= ?`, since),
      q("SELECT COUNT(*) n, COALESCE(SUM(total),0) v FROM orders WHERE deleted=0 AND status='new'"),
      q("SELECT ref, name, phone, state, total, status, created_at, confirmed_at FROM orders WHERE deleted=0 AND status IN ('new','confirmed') ORDER BY id DESC LIMIT 12"),
      q(`SELECT COALESCE(source,'website') source, COUNT(*) n, COALESCE(SUM(total),0) v, SUM(CASE WHEN status IN ${SOLD} THEN total ELSE 0 END) sold FROM orders WHERE deleted=0 AND created_at >= ? GROUP BY source ORDER BY n DESC`, since),
      q(`SELECT COUNT(*) n, COALESCE(SUM(total),0) v FROM orders WHERE deleted=0 AND status IN ${SOLD}`),
    ]);
    // customers: new vs returning in this period
    const allOrd = r(await q("SELECT phone, created_at FROM orders WHERE deleted=0 AND status != 'cancelled' ORDER BY id").all());
    const first = {}, inRange = new Set();
    for (const o of allOrd) { const k = custKey(o.phone); if (!k) continue; if (!first[k]) first[k] = o.created_at; if (o.created_at >= since) inRange.add(k); }
    const newCust = [...inRange].filter((k) => first[k] >= since).length;
    // product popularity from orders
    const ordRows = r(await q("SELECT items FROM orders WHERE deleted=0 AND status != 'cancelled' AND created_at >= ?", since).all());
    const prod = {};
    for (const o of ordRows) for (const i of JSON.parse(o.items || "[]")) {
      const k = `${i.name}${i.colourName && i.id === "regular" ? " – " + i.colourName : ""}`;
      prod[k] = prod[k] || { item: k, dozens: 0, value: 0, orders: 0 }; prod[k].dozens += i.dozens || 0; prod[k].value += i.line || 0; prod[k].orders += 1;
    }
    return json({
      days, since,
      visitors: r(vis)[0], today: r(today)[0], funnel: r(funnel), orders: r(ordersAgg)[0], byStatus: r(statusAgg),
      daily: r(daily), dailyOrders: r(dailyOrders), sources: r(sources), devices: r(devices), cities: r(cities), states: r(states),
      hours: r(hours), topAdds: r(topAdds), live: r(live), allTime: r(totalsAll)[0], allSold: r(allSold)[0],
      sold: r(soldAgg)[0], waiting: r(waitingAgg)[0], attention: r(attention), orderSources: r(orderSources),
      customers: { active: inRange.size, new: newCust, returning: inRange.size - newCust, total: Object.keys(first).length },
      topOrdered: Object.values(prod).sort((a, b) => b.value - a.value).slice(0, 15),
    });
  }

  // ---- orders
  if (p === "/api/admin/orders" && m === "GET") {
    const st = url.searchParams.get("status"), qs = url.searchParams.get("q"), del = url.searchParams.get("deleted") === "1";
    let sql = `${ORDER_SELECT} WHERE o.deleted = ?`, a = [del ? 1 : 0];
    if (st && STATUSES.includes(st)) { sql += " AND o.status = ?"; a.push(st); }
    if (qs) { sql += " AND (o.ref LIKE ? OR o.name LIKE ? OR o.phone LIKE ? OR o.state LIKE ? OR o.lga LIKE ?)"; const l = `%${qs}%`; a.push(l, l, l, l, l); }
    const ck = url.searchParams.get("customer"); if (ck) { sql += " AND o.phone LIKE ?"; a.push("%" + ck.slice(-7)); }
    sql += " ORDER BY o.id DESC LIMIT 500";
    const res = await env.DB.prepare(sql).bind(...a).all();
    let list = (res.results || []).map(orderRow);
    if (ck) list = list.filter((o) => custKey(o.phone) === ck);
    return json({ orders: list });
  }
  if (p === "/api/admin/orders" && m === "POST") {
    const b = await readBody(req, 20000);
    const items = (b.items || []).map((i) => ({ ...i, qty: parseInt(i.qty) || 1, price: parseInt(i.price) || 0, line: (parseInt(i.qty) || 1) * (parseInt(i.price) || 0), dozens: parseInt(i.dozens) || 0 }));
    const total = items.reduce((s, i) => s + i.line, 0);
    const ref = "AU-" + Math.random().toString(36).slice(2, 7).toUpperCase();
    const st = STATUSES.includes(normStatus(b.status)) ? normStatus(b.status) : "new", stamps = stageStamps({}, st);
    await env.DB.prepare("INSERT INTO orders (ref, created_at, updated_at, name, phone, state, lga, park, address, items, total, status, notes, source, confirmed_at, dispatched_at, delivered_at, cancelled_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(ref, nowISO(), nowISO(), clampStr(b.name, 100), clampStr(b.phone, 30), clampStr(b.state, 40), clampStr(b.lga, 60), clampStr(b.park, 120), clampStr(b.address, 300),
        JSON.stringify(items), total, st, clampStr(b.notes, 2000) || "", clampStr(b.source, 40) || "manual", stamps.confirmed_at || null, stamps.dispatched_at || null, stamps.delivered_at || null, stamps.cancelled_at || null).run();
    const o = await getOrder(env, ref);
    await audit(env, { action: "create", entity: "order", entity_id: ref, summary: `Added order ${ref} (${b.name || "no name"})`, before: null, after: o });
    return json({ ok: true, order: o });
  }
  const om = p.match(/^\/api\/admin\/orders\/(AU-[A-Z0-9-]+)$/);
  if (om && m === "GET") { const o = await getOrder(env, om[1]); return o ? json({ order: o }) : json({ error: "Order not found" }, 404); }
  if (om && m === "PATCH") {
    const ref = om[1];
    const before = await getOrder(env, ref);
    if (!before) return json({ error: "Order not found" }, 404);
    const b = await readBody(req, 20000);
    const f = {}; const changes = [];
    if (b.status !== undefined) b.status = normStatus(b.status);
    if (b.status !== undefined && STATUSES.includes(b.status) && b.status !== before.status) { f.status = b.status; Object.assign(f, stageStamps(before, b.status)); changes.push(`${before.status} → ${b.status}`); }
    if (b.notes !== undefined && b.notes !== before.notes) { f.notes = clampStr(b.notes, 2000); changes.push("notes"); }
    if (b.deleted !== undefined && !!b.deleted !== before.deleted) { f.deleted = b.deleted ? 1 : 0; changes.push(b.deleted ? "deleted" : "restored"); }
    for (const k of ["name", "phone", "state", "lga", "park", "address"]) if (b[k] !== undefined && b[k] !== before[k]) { f[k] = clampStr(b[k], 300); changes.push(k); }
    if (b.items !== undefined) {
      const items = b.items.map((i) => ({ ...i, qty: parseInt(i.qty) || 1, price: parseInt(i.price) || 0, line: (parseInt(i.qty) || 1) * (parseInt(i.price) || 0) }));
      f.items = JSON.stringify(items); f.total = items.reduce((s, i) => s + i.line, 0); changes.push("items");
    }
    if (!changes.length) return json({ ok: true, order: before });
    f.updated_at = nowISO();
    const keys = Object.keys(f);
    await env.DB.prepare(`UPDATE orders SET ${keys.map((k) => `${k} = ?`).join(", ")} WHERE ref = ?`).bind(...keys.map((k) => f[k]), ref).run();
    const after = await getOrder(env, ref);
    await audit(env, { action: "update", entity: "order", entity_id: ref, summary: `Order ${ref}${before.name ? " (" + before.name + ")" : ""}: ${changes.join(", ")}`, before, after });
    return json({ ok: true, order: after });
  }

  // ---- receipts
  const rm = p.match(/^\/api\/admin\/orders\/(AU-[A-Z0-9-]+)\/receipt(\/sent)?$/);
  if (rm && m === "POST") {
    const ref = rm[1];
    const o = await getOrder(env, ref); if (!o) return json({ error: "Order not found" }, 404);
    if (rm[2]) { await env.DB.prepare("UPDATE receipts SET sent_at = ? WHERE ref = ?").bind(nowISO(), ref).run(); return json({ ok: true, order: await getOrder(env, ref) }); }
    const b = await readBody(req, 3_000_000);
    const img = b64ToBytes(b.img), og = b64ToBytes(b.og);
    if (img.length < 1000 || img.length > 1_500_000 || og.length > 600_000) return json({ error: "Receipt image size looks wrong" }, 400);
    const ex = await env.DB.prepare("SELECT token FROM receipts WHERE ref = ?").bind(ref).first();
    const token = ex?.token || randTok();
    await env.DB.prepare("INSERT INTO receipts (ref, token, img, og, created_at, updated_at) VALUES (?,?,?,?,?,?) ON CONFLICT(ref) DO UPDATE SET img = excluded.img, og = excluded.og, updated_at = excluded.updated_at")
      .bind(ref, token, img, og, nowISO(), nowISO()).run();
    if (!ex) await audit(env, { action: "receipt", entity: "receipt", entity_id: ref, summary: `Receipt made for ${ref}${o.name ? " (" + o.name + ")" : ""}`, before: null, after: null });
    return json({ ok: true, token, url: `${url.origin}/r/${token}`, order: await getOrder(env, ref) });
  }

  // ---- customer book
  if (p === "/api/admin/customers" && m === "GET") {
    const rows = ((await env.DB.prepare("SELECT ref, created_at, name, phone, state, lga, park, address, total, status, source, items, confirmed_at FROM orders WHERE deleted = 0 ORDER BY id").all()).results) || [];
    const notes = Object.fromEntries((((await env.DB.prepare("SELECT key, notes FROM customers").all()).results) || []).map((x) => [x.key, x.notes]));
    const C = {};
    for (const o of rows) {
      const k = custKey(o.phone) || "noref-" + o.ref; const st = normStatus(o.status);
      const c = (C[k] = C[k] || { key: k, name: "", phone: "", state: "", lga: "", park: "", address: "", first: o.created_at, last: o.created_at, orders: 0, sold: 0, soldOrders: 0, ordered: 0, dozens: 0, sources: {}, refs: [] });
      for (const f of ["name", "phone", "state", "lga", "park", "address"]) if (o[f]) c[f] = o[f]; // latest details win
      c.last = o.created_at; c.orders++; if (st !== "cancelled") c.ordered += o.total || 0;
      if (["confirmed", "dispatched", "delivered"].includes(st)) { c.sold += o.total || 0; c.soldOrders++; c.dozens += JSON.parse(o.items || "[]").reduce((a, i) => a + (i.dozens || 0), 0); }
      c.sources[o.source || "website"] = 1;
      c.refs.push({ ref: o.ref, at: o.created_at, total: o.total, status: st });
    }
    const list = Object.values(C).map((c) => ({ ...c, sources: Object.keys(c.sources), refs: c.refs.reverse(), notes: notes[c.key] || "" })).sort((a, b) => (a.last < b.last ? 1 : -1));
    return json({ customers: list });
  }
  const cm = p.match(/^\/api\/admin\/customers\/([0-9a-zA-Z-]+)$/);
  if (cm && m === "PUT") {
    const b = await readBody(req, 5000); const k = cm[1];
    const prev = await env.DB.prepare("SELECT notes FROM customers WHERE key = ?").bind(k).first();
    const notes = clampStr(b.notes, 2000) || "";
    await env.DB.prepare("INSERT INTO customers (key, notes, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET notes = excluded.notes, updated_at = excluded.updated_at").bind(k, notes, nowISO()).run();
    await audit(env, { action: "update", entity: "customer", entity_id: k, summary: `Customer notes updated${b.name ? " for " + clampStr(b.name, 60) : ""}`, before: { notes: prev?.notes || "" }, after: { notes } });
    return json({ ok: true });
  }

  // ---- catalog
  if (p === "/api/admin/catalog" && m === "GET") return json(await getCatalog(env));
  if (p === "/api/admin/catalog" && m === "PUT") {
    const b = await readBody(req, 50000);
    const before = await getCatalog(env);
    const after = deepMerge(DEFAULT_CATALOG, b.catalog || {});
    await setSetting(env, "catalog", after);
    await audit(env, { action: "update", entity: "catalog", entity_id: "catalog", summary: clampStr(b.summary, 300) || "Updated products & stock", before, after });
    return json({ ok: true, catalog: after });
  }

  // ---- activity log + undo
  if (p === "/api/admin/audit" && m === "GET") {
    const res = await env.DB.prepare("SELECT id, ts, action, entity, entity_id, summary, undone, undo_of FROM audit ORDER BY id DESC LIMIT 300").all();
    return json({ audit: res.results || [] });
  }
  const um = p.match(/^\/api\/admin\/audit\/(\d+)\/undo$/);
  if (um && m === "POST") {
    const a = await env.DB.prepare("SELECT * FROM audit WHERE id = ?").bind(um[1]).first();
    if (!a) return json({ error: "Not found" }, 404);
    if (a.undone) return json({ error: "Already undone" }, 400);
    const before = a.before ? JSON.parse(a.before) : null;
    if (a.entity === "catalog") {
      const current = await getCatalog(env);
      // revert only the values this change touched, keep everything changed since
      const after = a.after ? JSON.parse(a.after) : {};
      const next = JSON.parse(JSON.stringify(current));
      const walk = (x, y, path) => {
        if (x && y && typeof x === "object" && typeof y === "object" && !Array.isArray(x)) { for (const k of new Set([...Object.keys(x), ...Object.keys(y)])) walk(x[k], y[k], [...path, k]); return; }
        if (JSON.stringify(x) !== JSON.stringify(y)) { let o = next; for (const k of path.slice(0, -1)) o = o[k] = o[k] && typeof o[k] === "object" ? o[k] : {}; o[path[path.length - 1]] = x === undefined ? null : x; }
      };
      walk(before || {}, after, []);
      await setSetting(env, "catalog", next);
      await audit(env, { action: "undo", entity: "catalog", entity_id: "catalog", summary: `Undid: ${a.summary}`, before: current, after: next, undo_of: a.id });
    } else if (a.entity === "order") {
      const current = await getOrder(env, a.entity_id);
      if (!before) { // undo a create = delete (soft)
        await env.DB.prepare("UPDATE orders SET deleted = 1, updated_at = ? WHERE ref = ?").bind(nowISO(), a.entity_id).run();
      } else {
        await env.DB.prepare("UPDATE orders SET name=?, phone=?, state=?, lga=?, park=?, address=?, items=?, total=?, status=?, notes=?, deleted=?, confirmed_at=?, dispatched_at=?, delivered_at=?, cancelled_at=?, updated_at=? WHERE ref = ?")
          .bind(before.name, before.phone, before.state, before.lga, before.park, before.address, JSON.stringify(before.items || []), before.total, normStatus(before.status), before.notes || "", before.deleted ? 1 : 0,
            before.confirmed_at ?? null, before.dispatched_at ?? null, before.delivered_at ?? null, before.cancelled_at ?? null, nowISO(), a.entity_id).run();
      }
      const after = await getOrder(env, a.entity_id);
      await audit(env, { action: "undo", entity: "order", entity_id: a.entity_id, summary: `Undid: ${a.summary}`, before: current, after, undo_of: a.id });
    } else if (a.entity === "customer") {
      const cur = await env.DB.prepare("SELECT notes FROM customers WHERE key = ?").bind(a.entity_id).first();
      await env.DB.prepare("INSERT INTO customers (key, notes, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET notes = excluded.notes, updated_at = excluded.updated_at").bind(a.entity_id, before?.notes || "", nowISO()).run();
      await audit(env, { action: "undo", entity: "customer", entity_id: a.entity_id, summary: `Undid: ${a.summary}`, before: { notes: cur?.notes || "" }, after: { notes: before?.notes || "" }, undo_of: a.id });
    } else return json({ error: "Can't undo this" }, 400);
    await env.DB.prepare("UPDATE audit SET undone = 1 WHERE id = ?").bind(a.id).run();
    return json({ ok: true });
  }

  // ---- raw visitor activity
  if (p === "/api/admin/events" && m === "GET") {
    const t = url.searchParams.get("type"), lim = Math.min(1000, parseInt(url.searchParams.get("limit")) || 200);
    const res = t ? await env.DB.prepare("SELECT * FROM events WHERE type = ? ORDER BY id DESC LIMIT ?").bind(t, lim).all()
      : await env.DB.prepare("SELECT * FROM events ORDER BY id DESC LIMIT ?").bind(lim).all();
    return json({ events: res.results || [] });
  }

  // ---- CSV exports
  const ex = p.match(/^\/api\/admin\/export\/(orders|events)\.csv$/);
  if (ex && m === "GET") {
    const rows = ex[1] === "orders"
      ? (await env.DB.prepare("SELECT ref, created_at, status, confirmed_at, dispatched_at, delivered_at, cancelled_at, name, phone, state, lga, park, address, total, items, notes, source, deleted FROM orders ORDER BY id DESC").all()).results
      : (await env.DB.prepare("SELECT ts, type, path, source, referrer, country, region, city, device, visitor, session, data FROM events ORDER BY id DESC LIMIT 50000").all()).results;
    const cols = rows.length ? Object.keys(rows[0]) : [];
    const cell = (v) => { const s = v == null ? "" : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n");
    return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="au-${ex[1]}-${nowISO().slice(0, 10)}.csv"`, "cache-control": "no-store" } });
  }

  return json({ error: "Not found" }, 404);
}

// Store page with the ad pixels written straight into <head> (standard Meta / TikTok base code)
let pxCache = { t: 0, v: null };
async function pixelIds(env) {
  if (Date.now() - pxCache.t < 30000 && pxCache.v) return pxCache.v;
  let v = { meta: "", tt: "" };
  try { const c = await getCatalog(env); v = { meta: String(c.store.metaPixel || ""), tt: String(c.store.tiktokPixel || "") }; } catch {}
  pxCache = { t: Date.now(), v }; return v;
}
async function servePage(req, env) {
  const res = await env.ASSETS.fetch(req);
  if (!(res.headers.get("content-type") || "").includes("text/html")) return res;
  const { meta, tt } = await pixelIds(env);
  let head = "";
  if (/^\d{8,20}$/.test(meta)) head += `<!-- Meta Pixel Code -->
<script>
!function(f,b,e,v,n,t,s)
{if(f.fbq)return;n=f.fbq=function(){n.callMethod?
n.callMethod.apply(n,arguments):n.queue.push(arguments)};
if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
n.queue=[];t=b.createElement(e);t.async=!0;
t.src=v;s=b.getElementsByTagName(e)[0];
s.parentNode.insertBefore(t,s)}(window, document,'script',
'https://connect.facebook.net/en_US/fbevents.js');
fbq('init', '${meta}');
fbq('track', 'PageView');
</script>
<noscript><img height="1" width="1" style="display:none"
src="https://www.facebook.com/tr?id=${meta}&ev=PageView&noscript=1"
/></noscript>
<!-- End Meta Pixel Code -->
`;
  if (/^[A-Z0-9]{10,30}$/i.test(tt)) head += `<script>
!function(w,d,t){w.TiktokAnalyticsObject=t;var ttq=w[t]=w[t]||[];ttq.methods=["page","track","identify","instances","debug","on","off","once","ready","alias","group","enableCookie","disableCookie"],ttq.setAndDefer=function(t,e){t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}};for(var i=0;i<ttq.methods.length;i++)ttq.setAndDefer(ttq,ttq.methods[i]);ttq.instance=function(t){for(var e=ttq._i[t]||[],n=0;n<ttq.methods.length;n++)ttq.setAndDefer(e,ttq.methods[n]);return e},ttq.load=function(e,n){var r="https://analytics.tiktok.com/i18n/pixel/events.js";ttq._i=ttq._i||{},ttq._i[e]=[],ttq._i[e]._u=r,ttq._t=ttq._t||{},ttq._t[e]=+new Date,ttq._o=ttq._o||{},ttq._o[e]=n||{};var o=d.createElement("script");o.type="text/javascript",o.async=!0,o.src=r+"?sdkid="+e+"&lib="+t;var a=d.getElementsByTagName("script")[0];a.parentNode.insertBefore(o,a)};ttq.load('${tt}');ttq.page();}(window,document,'ttq');
</script>
`;
  const headers = new Headers(res.headers); headers.set("cache-control", "no-cache");
  if (!head) return new Response(res.body, { status: res.status, headers });
  return new HTMLRewriter().on("meta[charset]", { element(el) { el.after(head, { html: true }); } }).transform(new Response(res.body, { status: res.status, headers }));
}

// ---------- public receipt page: /r/<token>, /r/<token>/receipt.jpg, /r/<token>/preview.jpg ----------
const hx = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const ngn = (n) => "₦" + Math.round(n || 0).toLocaleString("en-NG");
const lagosDate = (iso, time = true) => iso ? new Date(iso).toLocaleString("en-NG", { timeZone: "Africa/Lagos", day: "numeric", month: "short", year: "numeric", ...(time ? { hour: "numeric", minute: "2-digit" } : {}) }) : "";
async function receiptPublic(env, url) {
  const m = url.pathname.match(/^\/r\/([A-Za-z0-9_-]{16,40})(?:\/(receipt|preview)\.jpg)?\/?$/);
  if (!m) return new Response("Not found", { status: 404 });
  const r = await env.DB.prepare("SELECT ref, token, updated_at" + (m[2] ? ", " + (m[2] === "receipt" ? "img" : "og") + " bin" : "") + " FROM receipts WHERE token = ?").bind(m[1]).first();
  if (!r) return new Response("This receipt link is not valid.", { status: 404, headers: { "content-type": "text/plain; charset=utf-8" } });
  if (m[2]) {
    const body = r.bin instanceof ArrayBuffer ? r.bin : new Uint8Array(r.bin || []);
    return new Response(body, { headers: { "content-type": "image/jpeg", "cache-control": "public, max-age=300", ...(url.searchParams.has("dl") ? { "content-disposition": `attachment; filename="AU-receipt-${r.ref}.jpg"` } : {}) } });
  }
  const o = orderRow(await env.DB.prepare("SELECT * FROM orders WHERE ref = ?").bind(r.ref).first());
  if (!o || o.deleted) return new Response("This receipt is no longer available.", { status: 404, headers: { "content-type": "text/plain; charset=utf-8" } });
  const v = encodeURIComponent(r.updated_at || "");
  const steps = [["new", "Order received", o.created_at], ["confirmed", "Payment confirmed", o.confirmed_at], ["dispatched", "Dispatched", o.dispatched_at], ["delivered", "Delivered", o.delivered_at]];
  const cur = o.status === "cancelled" ? -1 : STEPS.indexOf(o.status);
  const paid = cur >= 1;
  const title = `Receipt ${o.ref} · AU Hair Accessories`;
  const desc = `${paid ? "Payment confirmed" : "Order"} for ${o.name || "you"} · ${ngn(o.total)} (excluding logistics)`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${hx(title)}</title><meta name="robots" content="noindex, nofollow"><meta name="theme-color" content="#410440">
<meta property="og:type" content="website"><meta property="og:site_name" content="AU Hair Accessories"><meta property="og:title" content="${hx(title)}"><meta property="og:description" content="${hx(desc)}">
<meta property="og:image" content="${url.origin}/r/${r.token}/preview.jpg?v=${v}"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/favicon.ico"><link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap">
<style>*{box-sizing:border-box}html,body{margin:0;background:#F7F1F7;color:#24021F;font-family:Poppins,system-ui,sans-serif;-webkit-font-smoothing:antialiased;overflow-x:hidden}
.w{max-width:560px;margin:0 auto;padding:16px 16px 40px}.rc{background:#fff;border-radius:22px;overflow:hidden;box-shadow:0 20px 50px rgba(65,4,64,.12)}
.hd{background:radial-gradient(120% 140% at 85% 0%,#7A1577,#410440 55%,#24021F);color:#fff;padding:22px 22px 20px;position:relative}.hd img{height:38px;display:block}
.hd h1{margin:16px 0 2px;font-size:22px;letter-spacing:-.01em}.hd p{margin:0;opacity:.8;font-size:13px}
.st{position:absolute;right:18px;top:20px;border:2px solid #7CE0A6;color:#7CE0A6;border-radius:10px;padding:4px 10px;font-weight:800;font-size:13px;letter-spacing:.12em;transform:rotate(-6deg)}
.st.x{border-color:#FFB4BB;color:#FFB4BB}.st.p{border-color:#FFD58A;color:#FFD58A}
.bd{padding:18px 22px}.lb{font-size:11px;font-weight:700;letter-spacing:.14em;color:#A0229E;margin:0 0 6px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:13.5px}.kv span{color:#7A6479}.kv b{font-weight:600;text-align:right;overflow-wrap:anywhere}
hr{border:0;border-top:1.5px dashed #EADCEA;margin:16px 0}
.it{display:grid;grid-template-columns:1fr auto;gap:2px 10px;padding:9px 0;border-bottom:1px solid #F3E9F3;font-size:13.5px}.it:last-child{border:0}.it small{color:#7A6479;font-size:12px}.it b{text-align:right}
.tot{display:flex;justify-content:space-between;align-items:flex-end;background:#FFE7FF;border-radius:14px;padding:12px 14px;margin-top:10px}.tot b{font-size:24px;color:#410440}.tot small{display:block;color:#7A6479;font-size:11.5px}
.tr{display:grid;gap:0;margin-top:4px}.s{display:grid;grid-template-columns:26px 1fr;gap:10px;position:relative;padding-bottom:12px}.s:last-child{padding-bottom:0}
.s i{width:26px;height:26px;border-radius:50%;background:#EADCEA;display:grid;place-items:center;color:#fff;font-style:normal;font-size:14px;font-weight:800;z-index:1}
.s.on i{background:#1E9E5A}.s:not(:last-child)::after{content:"";position:absolute;left:12px;top:26px;bottom:0;width:2px;background:#EADCEA}.s.on:not(:last-child)::after{background:#1E9E5A}
.s b{font-size:13.5px;display:block;line-height:26px}.s small{color:#7A6479;font-size:12px;display:block;margin-top:-4px}
.ft{background:#24021F;color:#E9CFE8;padding:16px 22px;font-size:12.5px;line-height:1.6}.ft b{color:#fff}
.bt{display:flex;gap:10px;margin-top:14px}.bt a{flex:1;text-align:center;text-decoration:none;font-weight:700;border-radius:14px;padding:13px 10px;font-size:14px}
.g{background:#1DAA61;color:#fff}.o{background:#fff;color:#410440;border:1.5px solid #EADCEA}
@media print{.bt{display:none}body{background:#fff}.rc{box-shadow:none}}</style></head><body><div class="w"><div class="rc">
<div class="hd"><img src="/img/au-logo-reverse.png" alt="AU Hair Accessories"><span class="st ${o.status === "cancelled" ? "x" : paid ? "" : "p"}">${o.status === "cancelled" ? "CANCELLED" : paid ? "PAID" : "PENDING"}</span>
<h1>${paid ? "Payment receipt" : "Order summary"}</h1><p>${hx(o.ref)} · ${hx(lagosDate(o.confirmed_at || o.created_at))}</p></div>
<div class="bd"><p class="lb">BILLED TO</p><div class="kv"><span>Name</span><b>${hx(o.name || "—")}</b><span>Phone</span><b>${hx(o.phone || "—")}</b>
${o.state ? `<span>State</span><b>${hx(o.state)}${o.lga ? ", " + hx(o.lga) : ""}</b>` : ""}${o.park ? `<span>Waybill park</span><b>${hx(o.park)}</b>` : ""}${o.address ? `<span>Address</span><b>${hx(o.address)}</b>` : ""}</div>
<hr><p class="lb">ITEMS</p>${o.items.map((i) => `<div class="it"><span>${hx(i.name)}${i.colourName && i.id === "regular" ? " – " + hx(i.colourName) : ""}<br><small>${i.qty} ${i.unit === "big" ? hx(i.unitName || "bag") + (i.qty > 1 ? "s" : "") + (i.dozens ? " (" + i.dozens + " dozen)" : "") : "dozen"} × ${ngn(i.price)}</small></span><b>${ngn(i.line)}</b></div>`).join("")}
<div class="tot"><span><small>Total ${paid ? "paid" : ""}</small><small>Excluding logistics</small></span><b>${ngn(o.total)}</b></div>
<hr><p class="lb">ORDER PROGRESS</p><div class="tr">${o.status === "cancelled" ? `<div class="s"><i style="background:#C22F3B">×</i><span><b>Order cancelled</b><small>${hx(lagosDate(o.cancelled_at))}</small></span></div>` : steps.map((x, i) => `<div class="s ${i <= cur ? "on" : ""}"><i>${i <= cur ? "✓" : ""}</i><span><b>${x[1]}</b>${i <= cur && x[2] ? `<small>${hx(lagosDate(x[2]))}</small>` : ""}</span></div>`).join("")}</div></div>
<div class="ft"><b>AU Hair Accessories</b><br>${hx(SHOP.address)}<br>WhatsApp ${hx(SHOP.phone)} · ${hx(SHOP.ig)} · ${hx(SHOP.web)}<br>Thank you for shopping with us 💜</div></div>
<div class="bt"><a class="o" href="/r/${r.token}/receipt.jpg?dl=1&v=${v}">Download receipt</a><a class="g" href="https://wa.me/${SHOP.wa}?text=${encodeURIComponent("Hi AU, about my order " + o.ref)}">Chat with us</a></div>
<div class="bt"><a class="o" href="/">Shop again at ${hx(SHOP.web)}</a></div></div></body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" } });
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname === "/" || url.pathname === "/index.html") return servePage(req, env);
    if (url.pathname.startsWith("/r/")) { try { return await receiptPublic(env, url); } catch (e) { return new Response("Something went wrong", { status: 500 }); } }
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      if (url.pathname.startsWith("/api/admin/")) return await adminApi(req, env, url);
      return await publicApi(req, env, url, ctx);
    } catch (e) {
      return json({ error: e.message || "Server error" }, e.status || 500);
    }
  },
};
