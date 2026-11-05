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


  // ---- partners (wig-making classes we want to supply)
  if (p === "/api/admin/partner-config" && m === "GET") { const c = await partnerCfg(env); return json({ yourName: c.yourName, offer: c.offer, classOffer: c.classOffer, hasSearchKey: !!c.searchKey }); }
  if (p === "/api/admin/partner-config" && m === "PUT") {
    const b = await readBody(req, 10000); const c = await partnerCfg(env);
    if (typeof b.yourName === "string") c.yourName = clampStr(b.yourName.trim(), 60) || "Nonso";
    if (Array.isArray(b.offer)) c.offer = b.offer.map((x) => clampStr(String(x).trim(), 200)).filter(Boolean).slice(0, 8);
    if (typeof b.classOffer === "string") c.classOffer = clampStr(b.classOffer.trim(), 200) || DEFAULT_CLASS;
    if (typeof b.searchKey === "string") c.searchKey = b.searchKey.trim().slice(0, 200);
    await setSetting(env, "partner_cfg", c);
    await audit(env, { action: "update", entity: "settings", entity_id: "partner_cfg", summary: "Partner proposal settings updated", before: null, after: null });
    return json({ ok: true, yourName: c.yourName, offer: c.offer, classOffer: c.classOffer, hasSearchKey: !!c.searchKey });
  }
  if (p === "/api/admin/leads" && m === "GET") {
    const res = await env.DB.prepare(`SELECT ${LEAD_COLS}, (pdf IS NOT NULL) has_pdf FROM leads WHERE deleted = ? ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'contacted' THEN 1 WHEN 'replied' THEN 2 WHEN 'partner' THEN 3 ELSE 4 END, id DESC`).bind(url.searchParams.get("deleted") === "1" ? 1 : 0).all();
    return json({ leads: (res.results || []).map(leadRow) });
  }
  if (p === "/api/admin/leads" && m === "POST") {
    const b = await readBody(req, 20000);
    const list = Array.isArray(b.leads) ? b.leads : [b];
    const made = [];
    for (const l of list.slice(0, 50)) {
      if (!l.name) continue;
      const f = cleanLead(l);
      const ex = await env.DB.prepare("SELECT id FROM leads WHERE lower(name) = lower(?) AND deleted = 0").bind(f.name).first();
      if (ex) continue;
      const keys = Object.keys(f);
      const r = await env.DB.prepare(`INSERT INTO leads (${keys.join(",")}, created_at, updated_at, status, token) VALUES (${keys.map(() => "?").join(",")}, ?, ?, 'new', ?)`).bind(...keys.map((k) => f[k]), nowISO(), nowISO(), randTok()).run();
      made.push(r.meta.last_row_id);
    }
    if (made.length) await audit(env, { action: "create", entity: "lead", entity_id: made.join(","), summary: made.length === 1 ? `Added ${list[0].name} to Partners` : `Added ${made.length} classes to Partners`, before: null, after: { ids: made } });
    return json({ ok: true, added: made.length, ids: made });
  }
  if (p === "/api/admin/leads/search" && m === "POST") {
    const b = await readBody(req, 2000); const c = await partnerCfg(env);
    if (!c.searchKey) return json({ error: "no_key" }, 400);
    const q = clampStr(String(b.q || "wig making class Lagos"), 150);
    const r = await fetch(`https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(q)}&count=15&safesearch=moderate`, { headers: { "X-Subscription-Token": c.searchKey, accept: "application/json" } });
    if (!r.ok) return json({ error: r.status === 401 || r.status === 403 ? "The search key was not accepted" : r.status === 429 ? "Search limit reached for now, try again later" : "Search failed (" + r.status + ")" }, 400);
    const d = await r.json();
    const items = (d.web?.results || []).slice(0, 15).map((x) => ({ title: x.title, url: x.url, snippet: [x.description, ...(x.extra_snippets || [])].filter(Boolean).join(" ").replace(/<[^>]+>/g, "").slice(0, 600) }));
    const known = ((await env.DB.prepare("SELECT lower(name) n, source_url u FROM leads WHERE deleted = 0").all()).results || []);
    await Promise.all(items.map(async (it) => {
      it.contacts = extractContacts(it.url + " " + it.snippet);
      let host = ""; try { host = new URL(it.url).hostname; } catch {}
      if (!/facebook|instagram|tiktok|threads|x\.com|twitter|youtube/.test(host)) {
        try {
          const pr = await fetch(it.url, { headers: { "user-agent": "Mozilla/5.0 (compatible; AU-Partners/1.0)" }, signal: AbortSignal.timeout(4500), redirect: "follow" });
          if (pr.ok && (pr.headers.get("content-type") || "").includes("text/html")) { const html = (await pr.text()).slice(0, 400000); mergeContacts(it.contacts, extractContacts(html)); }
        } catch {}
      }
      it.known = known.some((k) => k.u === it.url || (it.title && k.n && it.title.toLowerCase().includes(k.n)));
    }));
    return json({ results: items });
  }
  const lm = p.match(/^\/api\/admin\/leads\/(\d+)(?:\/(proposal|pdf|sent|doc))?$/);
  if (lm) {
    const id = Number(lm[1]), act = lm[2];
    const before = leadRow(await env.DB.prepare(`SELECT ${LEAD_COLS} FROM leads WHERE id = ?`).bind(id).first());
    if (!before) return json({ error: "Not found" }, 404);
    if (!act && m === "PATCH") {
      const b = await readBody(req, 30000); const f = cleanLead(b, true);
      if (b.status !== undefined && LEAD_STATUS.includes(b.status)) f.status = b.status;
      if (b.deleted !== undefined) f.deleted = b.deleted ? 1 : 0;
      if (b.proposal !== undefined) f.proposal = JSON.stringify(b.proposal);
      const keys = Object.keys(f); if (!keys.length) return json({ ok: true, lead: before });
      f.updated_at = nowISO(); const ks = Object.keys(f);
      await env.DB.prepare(`UPDATE leads SET ${ks.map((k) => k + " = ?").join(", ")} WHERE id = ?`).bind(...ks.map((k) => f[k]), id).run();
      const after = leadRow(await env.DB.prepare(`SELECT ${LEAD_COLS} FROM leads WHERE id = ?`).bind(id).first());
      const what = b.status !== undefined && b.status !== before.status ? `${before.status} → ${b.status}` : b.deleted !== undefined ? (b.deleted ? "removed" : "restored") : b.proposal !== undefined ? "proposal edited" : "details updated";
      await audit(env, { action: "update", entity: "lead", entity_id: id, summary: `Partners · ${before.name}: ${what}`, before, after });
      return json({ ok: true, lead: after });
    }
    if (act === "doc" && m === "GET") return json({ doc: await proposalDoc(env, before) });
    if (act === "proposal" && m === "POST") {
      const prop = await writeProposal(env, before);
      await env.DB.prepare("UPDATE leads SET proposal = ?, proposal_at = ?, updated_at = ? WHERE id = ?").bind(JSON.stringify(prop), nowISO(), nowISO(), id).run();
      return json({ ok: true, lead: leadRow(await env.DB.prepare(`SELECT ${LEAD_COLS} FROM leads WHERE id = ?`).bind(id).first()) });
    }
    if (act === "pdf" && m === "POST") {
      const b = await readBody(req, 4_000_000);
      const pdf = b64ToBytes(b.pdf), og = b64ToBytes(b.og);
      if (pdf.length < 1000 || pdf.length > 2_500_000) return json({ error: "PDF size looks wrong" }, 400);
      await env.DB.prepare("UPDATE leads SET pdf = ?, og = ?, proposal_at = ?, updated_at = ? WHERE id = ?").bind(pdf, og, nowISO(), nowISO(), id).run();
      return json({ ok: true, lead: leadRow(await env.DB.prepare(`SELECT ${LEAD_COLS}, 1 has_pdf FROM leads WHERE id = ?`).bind(id).first()) });
    }
    if (act === "sent" && m === "POST") {
      const b = await readBody(req, 500);
      await env.DB.prepare("UPDATE leads SET status = CASE WHEN status = 'new' THEN 'contacted' ELSE status END, contacted_at = ?, updated_at = ? WHERE id = ?").bind(nowISO(), nowISO(), id).run();
      const after = leadRow(await env.DB.prepare(`SELECT ${LEAD_COLS}, (pdf IS NOT NULL) has_pdf FROM leads WHERE id = ?`).bind(id).first());
      await audit(env, { action: "update", entity: "lead", entity_id: id, summary: `Partners · proposal sent to ${before.name} by ${clampStr(b.channel, 20) || "message"}`, before, after });
      return json({ ok: true, lead: after });
    }
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
    } else if (a.entity === "lead") {
      if (!before) { // undo an add = remove those leads
        const ids = (a.after ? JSON.parse(a.after).ids : []) || [];
        for (const i of ids) await env.DB.prepare("UPDATE leads SET deleted = 1, updated_at = ? WHERE id = ?").bind(nowISO(), i).run();
      } else {
        const cur = leadRow(await env.DB.prepare(`SELECT ${LEAD_COLS} FROM leads WHERE id = ?`).bind(a.entity_id).first());
        const ks = [...LEAD_FIELDS, "teaches", "status", "deleted", "proposal", "contacted_at"];
        await env.DB.prepare(`UPDATE leads SET ${ks.map((k) => k + " = ?").join(", ")}, updated_at = ? WHERE id = ?`).bind(...ks.map((k) => k === "proposal" ? (before.proposal ? JSON.stringify(before.proposal) : null) : k === "deleted" || k === "teaches" ? (before[k] ? 1 : 0) : before[k] ?? null), nowISO(), a.entity_id).run();
        await audit(env, { action: "undo", entity: "lead", entity_id: a.entity_id, summary: `Undid: ${a.summary}`, before: cur, after: before, undo_of: a.id });
        await env.DB.prepare("UPDATE audit SET undone = 1 WHERE id = ?").bind(a.id).run();
        return json({ ok: true });
      }
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

// ---------- partners helpers ----------
const LEAD_STATUS = ["new", "contacted", "replied", "partner", "no"];
const LEAD_FIELDS = ["name", "kind", "city", "country", "whatsapp", "phone", "email", "instagram", "facebook", "website", "about", "price_info", "next_date", "source_url", "notes"];
const LEAD_COLS = "id, created_at, updated_at, " + LEAD_FIELDS.join(", ") + ", teaches, status, contacted_at, deleted, token, proposal, proposal_at";
function leadRow(l) { if (!l) return l; let pr = null; try { pr = l.proposal ? JSON.parse(l.proposal) : null; } catch {} return { ...l, proposal: pr, deleted: !!l.deleted, has_pdf: !!l.has_pdf, teaches: !!l.teaches }; }
function cleanLead(b, partial) {
  const f = {};
  for (const k of LEAD_FIELDS) { if (b[k] === undefined) continue; f[k] = clampStr(String(b[k] ?? "").trim(), k === "about" || k === "notes" ? 1500 : 300); }
  if (b.teaches !== undefined) f.teaches = b.teaches ? 1 : 0;
  else if (!partial && /academy|class|school|train|course|lesson/i.test(`${b.kind || ""} ${b.name || ""}`)) f.teaches = 1;
  return f;
}
const DEFAULT_OFFER = [
  "Partner prices: {mesh} a dozen on mesh dome caps and {cap} on wig caps, even on small orders",
  "Free sample dozen: One dozen of DIY or Stretch Mesh Dome Cap to test, you only cover logistics",
  "First pick of stock: You hear first when new stock lands",
  "Delivered to you: Sent to your city or workshop anywhere in Nigeria and West Africa",
  "Easy reorders: Order in a few taps on WhatsApp or auhairaccessories.com",
];
const DEFAULT_CLASS = "Class supply: Caps for your students' kits at partner prices, and we share your classes with our followers";
async function partnerCfg(env) {
  const d = { yourName: "Nonso", searchKey: "", offer: DEFAULT_OFFER, classOffer: DEFAULT_CLASS, v: 4 };
  const s = (await getSetting(env, "partner_cfg")) || {};
  if (!s.v || s.v < 4) delete s.offer; // earlier default wording is replaced by the current partnership offer
  return { ...d, ...s, v: 4 };
}
const perkOf = (line) => { const i = line.indexOf(":"); return i > 0 && i < 40 ? { t: line.slice(0, i).trim(), d: line.slice(i + 1).trim() } : { t: line.trim(), d: "" }; };
const NGN = (n) => "₦" + Math.round(n || 0).toLocaleString("en-NG");
const fillOffer = (t, cat) => String(t).replace(/\{mesh\}/g, NGN(cat.diy.bulk)).replace(/\{cap\}/g, NGN(cat.regular.bulk));
async function proposalDoc(env, l) {
  const c = await partnerCfg(env), cat = (await getCatalog(env)).products, N = NGN;
  const P = l.proposal || {};
  return {
    name: l.name, teaches: !!l.teaches, yourName: c.yourName, link: `/p/${l.token}`,
    intro: P.intro || `We'd love to be the wig cap supplier behind every unit ${l.name} makes, with quality caps, steady stock and partner prices.`,
    boxes: [["mesh", "DIY Mesh Dome Cap", "Full-size dome to build full wigs on"], ["mesh", "Stretch Mesh Dome Cap", "Stretch fit for closure & U-part wigs"], ["wind", "Breathable mesh", "Cool, light and dries fast"], ["truck", "Nigeria & West Africa", "Delivered to your city or workshop"]],
    products: [
      { img: "/img/p/making-cap-diy-mesh.jpg", name: "DIY Mesh Dome Cap", tag: "Build full wigs on it", pts: ["Cool mesh spandex", "High & tight band", "Full size"], was: N(cat.diy.dz), partner: N(cat.diy.bulk), bulkLabel: "Carton of 50 dozen", bulk: N(cat.diy.bulk * 50) },
      { img: "/img/p/making-cap-stretch-mesh.jpg", name: "Stretch Mesh Dome Cap", tag: "For closure & U-part wigs", pts: ["Stretch dome fit", "Breathable", "Dries fast"], was: N(cat.stretch.dz), partner: N(cat.stretch.bulk), bulkLabel: "Carton of 50 dozen", bulk: N(cat.stretch.bulk * 50) },
      { img: "/img/p/wearing-cap-black.jpg", name: "Regular Wig Cap", tag: "Under every install", pts: ["Thin sheer nylon", "Flat, smooth base", "11 colours"], was: N(cat.regular.dz), partner: N(cat.regular.bulk), bulkLabel: "Bag of 100 dozen", bulk: N(cat.regular.bulk * 100) },
    ],
    perks: c.offer.map((x) => perkOf(fillOffer(x, cat))), classPerk: l.teaches ? perkOf(fillOffer(c.classOffer, cat)) : null,
    steps: [["chat", "Send your order", "On WhatsApp or at auhairaccessories.com. Any quantity, partner prices."], ["box", "We pack & dispatch", "From our Trade Fair shop in Lagos, across Nigeria and West Africa."], ["star", "You build & sell", "Quality caps, steady supply, better margins."]],
    sample: { t: "Start with a free sample dozen", d: `One dozen of DIY or Stretch Mesh Dome Cap, free for ${l.name}. You only cover logistics.` },
    shop: SHOP,
  };
}
function extractContacts(text) {
  const t = String(text || "");
  const emails = [...new Set((t.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []).map((e) => e.toLowerCase()).filter((e) => !/\.(png|jpe?g|gif|webp|svg)$/.test(e) && !/example|sentry|wixpress|domain\.com|email\.com/.test(e)))].slice(0, 3);
  const wa = [...new Set((t.match(/(?:wa\.me\/|api\.whatsapp\.com\/send\?phone=)(\d{8,15})/g) || []).map((x) => x.replace(/\D/g, "")))].slice(0, 2);
  const phones = [...new Set((t.match(/(?:\+?234[\s-]?|\b0)[789][01]\d[\s-]?\d{3}[\s-]?\d{4}\b|\+233[\s-]?\d{2}[\s-]?\d{3}[\s-]?\d{4}|\b0[25]\d[\s-]?\d{3}[\s-]?\d{4}\b/g) || []).map((x) => x.replace(/[\s-]/g, "")))].slice(0, 3);
  const ig = [...new Set((t.match(/instagram\.com\/([A-Za-z0-9_.]{2,30})/g) || []).map((x) => x.split("/").pop()).filter((h) => !/^(p|reel|reels|explore|accounts|stories|tv|share)$/i.test(h)))].slice(0, 2);
  const fb = [...new Set((t.match(/facebook\.com\/[A-Za-z0-9_.\-\/?=]{3,80}/g) || []).filter((x) => !/sharer|plugins|tr\?|dialog/.test(x)))].slice(0, 1);
  return { emails, wa, phones, ig, fb };
}
function mergeContacts(a, b) { for (const k of Object.keys(b)) a[k] = [...new Set([...(a[k] || []), ...b[k]])].slice(0, 3); }
async function writeProposal(env, l) {
  const cat = await getCatalog(env), c = await partnerCfg(env), pr = cat.products;
  const facts = `AU Hair Accessories is a wig cap supplier at Shop A1, by Bayelsa Plaza, BBA Trade Fair Complex, Lagos, Nigeria. Online store: auhairaccessories.com (orders go to WhatsApp). WhatsApp 0912 643 3425. Instagram @auhairaccessories. Delivers across Nigeria and West Africa.
Products: DIY Mesh Dome Cap and Stretch Mesh Dome Cap - mesh caps wig makers pin to the block and sew bundles, closures and frontals onto (₦${pr.diy.dz} per dozen, ₦${pr.diy.bulk * 50} per carton of 50 dozen). Regular Wig Cap - thin sheer nylon cap worn under every wig install, 11 colours (₦${pr.regular.dz} per dozen, ₦${pr.regular.bulk * 100} per bag of 100 dozen). Prices exclude logistics.
Partner offer: ${c.offer.map((x) => "- " + fillOffer(x, pr)).join("\n")}${l.teaches ? "\n- " + fillOffer(c.classOffer, pr) : ""}
Sender: ${c.yourName}, AU Hair Accessories.`;
  const biz = `Business: ${l.name}${l.kind ? " (" + l.kind + ")" : ""}. Location: ${[l.city, l.country].filter(Boolean).join(", ") || "unknown"}. What we know: ${l.about || "a wig business"}. ${l.teaches ? "They ALSO teach wig making (mention class supply as a bonus, not the main point)." : "They do not teach classes; do not mention classes or students."}`;
  const first = l.name;
  const fallback = () => ({
    intro: `${first} turns bundles into beautiful wigs. We'd love to be the cap supplier behind every unit you build: quality caps, steady stock and partner prices${l.teaches ? ", plus supply for your classes" : ""}.`,
    whatsapp: `Hello ${first} 👋🏾\n\nI'm ${c.yourName} from AU Hair Accessories, wig cap suppliers at Trade Fair, Lagos. I love the wigs you make.\n\nWe'd like to be your cap supplier: mesh dome caps from ${NGN(pr.diy.bulk)} a dozen, even on small orders, delivered to you. You can start with a free sample dozen (you only cover logistics)${l.teaches ? ", and we can supply your classes too" : ""}.\n\nHere's a short proposal for ${first}:\n{link}\n\nCan we talk this week?`,
    emailSubject: `Business partnership: wig caps for ${first}`,
    emailBody: `Hello ${first},\n\nI'm ${c.yourName} from AU Hair Accessories, a wig cap supplier at BBA Trade Fair Complex, Lagos.\n\nWe'd love to partner with ${first} as your supplier of mesh dome caps and wig caps, the base of every unit you build.\n\nAs a partner you get:\n${c.offer.map((x) => "• " + perkOf(fillOffer(x, pr)).t).join("\n")}${l.teaches ? "\n• " + perkOf(c.classOffer).t : ""}\n\nThe full proposal, with prices:\n{link}\n\nCan we start with a free sample dozen? You only cover logistics.\n\nWarm regards,\n${c.yourName}\nAU Hair Accessories\nWhatsApp: 0912 643 3425\nauhairaccessories.com`,
  });
  if (!env.AI) return fallback();
  try {
    const sys = `You write short, warm, confident B2B supply-partnership outreach in Nigerian business English for AU Hair Accessories, written to wig businesses (wig makers, vendors, people who turn bundles into custom units). The goal is a business partnership: AU supplies their wig caps. Use ONLY the facts provided; never invent awards, numbers, names, dates or claims about the business you are writing to. Keep it short and easy to read. No hashtags. Return ONLY a JSON object with keys: intro (max 28 words, tailored to this business, speaks to them directly, for the top of the proposal), whatsapp (max 80 words, friendly, max 2 emojis, must contain the exact placeholder {link} on its own line, end with a simple question), emailSubject (max 60 chars), emailBody (90-140 words, plain text with line breaks, a short bullet list of the partner perks using only their titles, must contain {link} on its own line, sign off with the sender name, "AU Hair Accessories", "WhatsApp: 0912 643 3425" and "auhairaccessories.com"). Mention the free sample dozen (one dozen of mesh dome caps, they only cover logistics).`;
    const out = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", { messages: [{ role: "system", content: sys }, { role: "user", content: facts + "\n\n" + biz }], max_tokens: 900, temperature: 0.6 });
    const txt = String(out?.response ?? out?.result?.response ?? (typeof out === "string" ? out : JSON.stringify(out)));
    const j = JSON.parse(txt.slice(txt.indexOf("{"), txt.lastIndexOf("}") + 1));
    const fb = fallback(), ok = (v) => typeof v === "string" && v.trim().length > 10;
    const r = { intro: ok(j.intro) ? j.intro.trim() : fb.intro, whatsapp: ok(j.whatsapp) ? j.whatsapp.trim() : fb.whatsapp, emailSubject: ok(j.emailSubject) ? j.emailSubject.trim() : fb.emailSubject, emailBody: ok(j.emailBody) ? j.emailBody.trim() : fb.emailBody };
    if (r.intro.split(/\s+/).length > 40) r.intro = fb.intro;
    if (!r.whatsapp.includes("{link}")) r.whatsapp += "\n\n{link}";
    if (!r.emailBody.includes("{link}")) r.emailBody = r.emailBody.replace(/\n\n(Warm|Kind|Best)/, "\n\nThe full proposal: {link}\n\n$1");
    if (!r.emailBody.includes("{link}")) r.emailBody += "\n\nProposal: {link}";
    return r;
  } catch (e) { return fallback(); }
}
const ICONS = {
  naira: "M6 20V4l12 16V4M3 10h18M3 14h18", mesh: "M3 18a9 9 0 0 1 18 0zM7.5 10.5v7.5M12 9v9M16.5 10.5v7.5M4.5 14h15", wind: "M3 8h11a3 3 0 1 0-3-3M3 16h14a3 3 0 1 1-3 3M3 12h17", box: "M3 7l9-4 9 4v10l-9 4-9-4zM3 7l9 4 9-4M12 11v10", down: "M12 4v16M6 14l6 6 6-6", gift: "M20 12v9H4v-9M2 7h20v5H2zM12 21V7M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7zM12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z",
  star: "M12 2l3.1 6.3 6.9 1-5 4.9 1.2 6.8L12 17.8 5.8 21l1.2-6.8-5-4.9 6.9-1z", truck: "M1 4h14v12H1zM15 8h4l3 3v5h-7zM5.5 21a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5zM18.5 21a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z",
  cart: "M6 6h15l-1.5 9h-12zM6 6L5 3H2M9 21a1 1 0 1 0 0-2 1 1 0 0 0 0 2zM18 21a1 1 0 1 0 0-2 1 1 0 0 0 0 2z", chat: "M21 12a8 8 0 0 1-11.8 7L3 21l2-6A8 8 0 1 1 21 12z", grad: "M22 10L12 5 2 10l10 5 10-5zM6 12v5c3 2 9 2 12 0v-5",
};
const PERK_ICONS = ["naira", "gift", "star", "truck", "cart", "chat", "star", "gift"];
const svgI = (k, sz = 22) => `<svg width="${sz}" height="${sz}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${ICONS[k]}"/></svg>`;

// ---------- public proposal page: /p/<token>, /p/<token>/proposal.pdf, /p/<token>/preview.jpg ----------
async function proposalPublic(env, url) {
  const m = url.pathname.match(/^\/p\/([A-Za-z0-9_-]{16,40})(?:\/(proposal\.pdf|preview\.jpg))?\/?$/);
  if (!m) return new Response("Not found", { status: 404 });
  const col = m[2] === "proposal.pdf" ? "pdf" : m[2] === "preview.jpg" ? "og" : null;
  const l = await env.DB.prepare(`SELECT ${LEAD_COLS}, (pdf IS NOT NULL) has_pdf${col ? ", " + col + " bin" : ""} FROM leads WHERE token = ? AND deleted = 0`).bind(m[1]).first();
  if (!l) return new Response("This link is not available.", { status: 404, headers: { "content-type": "text/plain; charset=utf-8" } });
  if (col) {
    if (!l.bin) return new Response("Not ready yet", { status: 404 });
    const body = l.bin instanceof ArrayBuffer ? l.bin : new Uint8Array(l.bin);
    return new Response(body, { headers: { "content-type": col === "pdf" ? "application/pdf" : "image/jpeg", "cache-control": "public, max-age=300", ...(col === "pdf" ? { "content-disposition": `${url.searchParams.has("dl") ? "attachment" : "inline"}; filename="AU-Hair-Accessories-Partnership-Proposal.pdf"` } : {}) } });
  }
  const lead = leadRow(l), D = await proposalDoc(env, lead);
  const v = encodeURIComponent(lead.proposal_at || "");
  const title = `${lead.name} × AU Hair Accessories · Partnership proposal`;
  const date = new Date(lead.proposal_at || Date.now()).toLocaleDateString("en-NG", { timeZone: "Africa/Lagos", day: "numeric", month: "long", year: "numeric" });
  const wa = `https://wa.me/${SHOP.wa}?text=${encodeURIComponent(`Hello AU Hair Accessories, this is ${lead.name}. I saw your partnership proposal and I'd like my free sample dozen.`)}`;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${hx(title)}</title><meta name="robots" content="noindex, nofollow"><meta name="theme-color" content="#410440">
<meta property="og:type" content="website"><meta property="og:site_name" content="AU Hair Accessories"><meta property="og:title" content="${hx(title)}"><meta property="og:description" content="Mesh dome caps and wig caps at partner prices for ${hx(lead.name)}.">
${lead.has_pdf ? `<meta property="og:image" content="${url.origin}/p/${lead.token}/preview.jpg?v=${v}"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">` : ""}<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="/favicon.ico"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700;800&display=swap">
<style>*{box-sizing:border-box}html,body{margin:0;background:#F7F1F7;color:#24021F;font-family:Poppins,system-ui,sans-serif;-webkit-font-smoothing:antialiased;overflow-x:hidden}
.w{max-width:620px;margin:0 auto;padding:14px 14px 40px}.pp{background:#fff;border-radius:26px;overflow:hidden;box-shadow:0 20px 50px rgba(65,4,64,.12)}
.hd{background:radial-gradient(120% 140% at 85% 0%,#7A1577,#410440 55%,#24021F);color:#fff;padding:24px 22px 78px;position:relative;overflow:hidden}
.hd .wm{position:absolute;right:-40px;bottom:-40px;width:230px;opacity:.07}.hd .l{height:38px;display:block}
.eb{font-size:11px;letter-spacing:.2em;font-weight:700;color:#E58BE3;margin:24px 0 2px}.dt{font-size:12.5px;color:#E9CFE8;margin:0 0 10px}
.hd h1{margin:0;font-size:28px;line-height:1.15;letter-spacing:-.02em}.hd h1 i{font-style:normal;color:#E58BE3}.hd p{margin:12px 0 0;color:#F2DDF1;font-size:15px;line-height:1.55}
.bx{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:-52px 16px 0;position:relative}.bx div{background:#fff;border-radius:18px;padding:14px;box-shadow:0 10px 30px rgba(65,4,64,.14)}
.bx i{width:36px;height:36px;border-radius:11px;background:#FFE7FF;color:#A0229E;display:grid;place-items:center;margin-bottom:8px}.bx b{display:block;font-size:14px;line-height:1.25}.bx span{display:block;font-size:12px;color:#7A6479;line-height:1.4;margin-top:3px}
.sec{padding:30px 20px 0}.lb{font-size:11px;font-weight:700;letter-spacing:.2em;color:#A0229E;margin:0 0 4px}.sec h2{margin:0 0 14px;font-size:22px;letter-spacing:-.01em;line-height:1.2}
.pc{display:grid;grid-template-columns:104px 1fr;border:1.5px solid #F0E3EF;border-radius:20px;overflow:hidden;margin-bottom:12px}.pc img{width:104px;height:100%;min-height:200px;object-fit:cover;display:block;background:#F7F1F7}
.pc>div{padding:13px 12px;min-width:0}.pc b{display:block;font-size:15.5px;line-height:1.25}.pc em{font-style:normal;display:inline-block;background:#FFE7FF;color:#A0229E;font-size:11px;font-weight:700;border-radius:999px;padding:3px 9px;margin:6px 0 6px}
.pc ul{margin:0 0 8px;padding:0;list-style:none;font-size:12px;color:#7A6479;line-height:1.55}.pc li::before{content:"✓ ";color:#1E9E5A;font-weight:800}
.pr{display:flex;align-items:baseline;gap:6px;white-space:nowrap}.pr s{color:#A895A7;font-size:13px}.pr strong{font-size:20px;color:#410440;letter-spacing:-.02em}.pl{display:block;font-size:10px;letter-spacing:.14em;color:#1E9E5A;font-weight:700;margin-top:2px}.pr span{font-size:12px;color:#7A6479}
.bk{margin-top:7px;background:#F7F1F7;border-radius:10px;padding:6px 9px;font-size:11.5px;display:flex;justify-content:space-between;gap:6px;white-space:nowrap}.bk span{color:#7A6479}.bk b{display:inline;font-size:12.5px;color:#24021F}
.pk{display:grid;grid-template-columns:46px 1fr;gap:12px;align-items:start;padding:12px 0;border-bottom:1px solid #F3E9F3}.pk:last-child{border:0}.pk i{width:46px;height:46px;border-radius:14px;background:#410440;color:#fff;display:grid;place-items:center}
.pk b{display:block;font-size:15px}.pk span{font-size:13px;color:#7A6479;line-height:1.45}
.cls{margin-top:10px;background:linear-gradient(120deg,#FFE7FF,#F3E4FF);border-radius:18px;padding:14px;display:grid;grid-template-columns:44px 1fr;gap:12px;align-items:center}.cls i{width:44px;height:44px;border-radius:50%;background:#A0229E;color:#fff;display:grid;place-items:center}.cls b{display:block;font-size:14.5px}.cls span{font-size:13px;color:#5A3D58}
.ps{border:1.5px solid #F0E3EF;border-radius:20px;overflow:hidden}.pr2{padding:13px 14px;border-bottom:1px solid #F3E9F3}.pr2:last-child{border:0}.pr2:nth-child(odd){background:#FBF6FB}.pr2 b{font-size:14.5px;display:block;margin-bottom:6px}
.g3{display:grid;grid-template-columns:1fr 1.15fr 1.3fr;gap:6px}.g3 div{font-size:11px;color:#7A6479}.g3 div span{display:block;font-size:14px;color:#24021F;font-weight:600;margin-top:1px}.g3 div s{display:block;font-size:14px;color:#A895A7;margin-top:1px}.g3 .pp2 span{color:#410440;font-weight:800;font-size:15px}
.note{font-size:11.5px;color:#7A6479;margin:8px 0 0}
.st{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center;background:#F7F1F7;border-radius:18px;padding:14px 16px}.st em{font-style:normal;font-size:30px;font-weight:800;color:#E58BE3;letter-spacing:-.03em;line-height:1}
.st b{display:block;font-size:15px}.st span{font-size:12.5px;color:#7A6479;line-height:1.4}.st i{width:42px;height:42px;border-radius:50%;background:#fff;color:#A0229E;display:grid;place-items:center}
.ar{display:flex;justify-content:center;color:#E58BE3;margin:4px 0}
.cta{margin:30px 20px 0;background:radial-gradient(120% 160% at 90% 0%,#7A1577,#410440 60%,#24021F);color:#fff;border-radius:24px;padding:24px 20px;text-align:center}.cta i{width:54px;height:54px;border-radius:50%;background:rgba(255,255,255,.12);display:grid;place-items:center;margin:0 auto 10px;color:#fff}
.cta h3{margin:0 0 6px;font-size:21px}.cta p{margin:0 0 16px;color:#F2DDF1;font-size:14px;line-height:1.5}.cta a{display:inline-block;background:#1DAA61;color:#fff;text-decoration:none;font-weight:700;border-radius:14px;padding:13px 22px}
.ft{padding:22px 20px 24px;font-size:12.5px;color:#7A6479;line-height:1.7;text-align:center}.ft b{color:#24021F}
.bt{display:flex;gap:10px;margin-top:14px}.bt a{flex:1;text-align:center;text-decoration:none;font-weight:700;border-radius:14px;padding:13px 10px;font-size:14px;background:#fff;color:#410440;border:1.5px solid #EADCEA}
@media print{.bt{display:none}body{background:#fff}.pp{box-shadow:none}}</style></head><body><div class="w"><div class="pp">
<div class="hd"><img class="wm" src="/img/au-icon-white.png" alt=""><img class="l" src="/img/au-logo-reverse.png" alt="AU Hair Accessories">
<p class="eb">BUSINESS PARTNERSHIP PROPOSAL</p><p class="dt">${hx(date)}</p>
<h1>${hx(lead.name)} <i>×</i> AU Hair Accessories</h1><p>${hx(D.intro)}</p></div>
<div class="bx">${D.boxes.map((b) => `<div><i>${svgI(b[0], 20)}</i><b>${hx(b[1])}</b><span>${hx(b[2])}</span></div>`).join("")}</div>
<div class="sec"><p class="lb">WHAT WE SUPPLY</p><h2>The caps behind every wig you make</h2>${D.products.map((p) => `<div class="pc"><img src="${p.img}" alt="${hx(p.name)}"><div><b>${p.name}</b><em>${p.tag}</em><ul>${p.pts.map((x) => `<li>${x}</li>`).join("")}</ul>
<small class="pl">PARTNER PRICE</small><div class="pr"><s>${p.was}</s><strong>${p.partner}</strong><span>per dozen</span></div><div class="bk"><span>${p.bulkLabel}</span><b>${p.bulk}</b></div></div></div>`).join("")}</div>
<div class="sec"><p class="lb">AS OUR PARTNER</p><h2>What you get</h2>${D.perks.map((k, i) => `<div class="pk"><i>${svgI(PERK_ICONS[i])}</i><div><b>${hx(k.t)}</b><span>${hx(k.d)}</span></div></div>`).join("")}
${D.classPerk ? `<div class="cls"><i>${svgI("grad")}</i><div><b>You teach wig making too? ${hx(D.classPerk.t)}</b><span>${hx(D.classPerk.d)}</span></div></div>` : ""}</div>
<div class="sec"><p class="lb">PRICES</p><h2>Your partner price sheet</h2><div class="ps">${D.products.map((p) => `<div class="pr2"><b>${p.name}</b><div class="g3"><div>Normal price<s>${p.was} /dz</s></div><div class="pp2">Partner price<span>${p.partner} /dz</span></div><div>${p.bulkLabel}<span>${p.bulk}</span></div></div></div>`).join("")}</div><p class="note">Partner prices apply to any quantity. Prices exclude logistics.</p></div>
<div class="sec"><p class="lb">HOW IT WORKS</p><h2>Partnering is simple</h2>${D.steps.map((s, i) => `${i ? `<div class="ar">${svgI("down", 22)}</div>` : ""}<div class="st"><em>0${i + 1}</em><div><b>${s[1]}</b><span>${s[2]}</span></div><i>${svgI(s[0], 20)}</i></div>`).join("")}</div>
<div class="cta"><i>${svgI("gift", 26)}</i><h3>${hx(D.sample.t)}</h3><p>${hx(D.sample.d)}</p><a href="${wa}">Claim it on WhatsApp</a></div>
<div class="ft"><b>AU Hair Accessories</b> · ${hx(D.yourName)}<br>${hx(SHOP.address)}<br>WhatsApp ${hx(SHOP.phone)} · ${hx(SHOP.ig)} · ${hx(SHOP.web)}</div></div>
${lead.has_pdf ? `<div class="bt"><a href="/p/${lead.token}/proposal.pdf?dl=1&v=${v}">Download PDF</a></div>` : ""}</div></body></html>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex" } });
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
    if (url.pathname.startsWith("/p/")) { try { return await proposalPublic(env, url); } catch (e) { return new Response("Something went wrong", { status: 500 }); } }
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
