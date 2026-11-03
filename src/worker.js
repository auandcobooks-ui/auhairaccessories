// AU Hair Accessories — store backend + admin API
// Static site files are served from ./public (ASSETS). Everything under /api/* runs here.

const COLOURS = ["black", "brown", "dark-brown", "nude", "wine", "red", "pink", "purple", "royal-blue", "sky-blue", "white"];
const STATUSES = ["new", "confirmed", "paid", "dispatched", "delivered", "cancelled"];
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
async function hmacKey(env) {
  const raw = await crypto.subtle.digest("SHA-256", enc.encode("au-admin-session:" + (env.ADMIN_PASSWORD || "")));
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function makeToken(env) {
  const exp = Date.now() + 30 * 24 * 3600 * 1000;
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(String(exp)));
  return `${exp}.${b64u(sig)}`;
}
async function checkToken(env, tok) {
  if (!tok || !env.ADMIN_PASSWORD) return false;
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
function orderRow(o) { return o && { ...o, items: o.items ? JSON.parse(o.items) : [], deleted: !!o.deleted }; }

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
    if (!env.ADMIN_PASSWORD || !(await safeEqual(String(b.password || ""), env.ADMIN_PASSWORD))) {
      await new Promise((r) => setTimeout(r, 700));
      return json({ error: "Wrong password" }, 401);
    }
    const tok = await makeToken(env);
    return json({ ok: true }, 200, { "set-cookie": `au_admin=${tok}; Path=/api/admin; Max-Age=${30 * 24 * 3600}; HttpOnly; Secure; SameSite=Strict` });
  }
  if (p === "/api/admin/logout") return json({ ok: true }, 200, { "set-cookie": "au_admin=; Path=/api/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict" });
  if (!(await checkToken(env, getCookie(req, "au_admin")))) return json({ error: "Not signed in" }, 401);

  if (p === "/api/admin/me") return json({ ok: true });

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
      q(`SELECT date(created_at, '${LAGOS}') d, COUNT(*) n, COALESCE(SUM(total),0) v, SUM(CASE WHEN status IN ('paid','dispatched','delivered') THEN total ELSE 0 END) paid FROM orders WHERE deleted=0 AND created_at >= ? GROUP BY d ORDER BY d`, since),
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
    // product popularity from orders
    const ordRows = r(await q("SELECT items FROM orders WHERE deleted=0 AND created_at >= ?", since).all());
    const prod = {};
    for (const o of ordRows) for (const i of JSON.parse(o.items || "[]")) {
      const k = `${i.name}${i.colourName && i.id === "regular" ? " – " + i.colourName : ""}`;
      prod[k] = prod[k] || { item: k, dozens: 0, value: 0, orders: 0 }; prod[k].dozens += i.dozens || 0; prod[k].value += i.line || 0; prod[k].orders += 1;
    }
    return json({
      days, since,
      visitors: r(vis)[0], today: r(today)[0], funnel: r(funnel), orders: r(ordersAgg)[0], byStatus: r(statusAgg),
      daily: r(daily), dailyOrders: r(dailyOrders), sources: r(sources), devices: r(devices), cities: r(cities), states: r(states),
      hours: r(hours), topAdds: r(topAdds), live: r(live), allTime: r(totalsAll)[0],
      topOrdered: Object.values(prod).sort((a, b) => b.value - a.value).slice(0, 15),
    });
  }

  // ---- orders
  if (p === "/api/admin/orders" && m === "GET") {
    const st = url.searchParams.get("status"), qs = url.searchParams.get("q"), del = url.searchParams.get("deleted") === "1";
    let sql = "SELECT * FROM orders WHERE deleted = ?", a = [del ? 1 : 0];
    if (st && STATUSES.includes(st)) { sql += " AND status = ?"; a.push(st); }
    if (qs) { sql += " AND (ref LIKE ? OR name LIKE ? OR phone LIKE ? OR state LIKE ? OR lga LIKE ?)"; const l = `%${qs}%`; a.push(l, l, l, l, l); }
    sql += " ORDER BY id DESC LIMIT 500";
    const res = await env.DB.prepare(sql).bind(...a).all();
    return json({ orders: (res.results || []).map(orderRow) });
  }
  if (p === "/api/admin/orders" && m === "POST") {
    const b = await readBody(req, 20000);
    const items = (b.items || []).map((i) => ({ ...i, qty: parseInt(i.qty) || 1, price: parseInt(i.price) || 0, line: (parseInt(i.qty) || 1) * (parseInt(i.price) || 0), dozens: parseInt(i.dozens) || 0 }));
    const total = items.reduce((s, i) => s + i.line, 0);
    const ref = "AU-" + Math.random().toString(36).slice(2, 7).toUpperCase();
    await env.DB.prepare("INSERT INTO orders (ref, created_at, updated_at, name, phone, state, lga, park, address, items, total, status, notes, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
      .bind(ref, nowISO(), nowISO(), clampStr(b.name, 100), clampStr(b.phone, 30), clampStr(b.state, 40), clampStr(b.lga, 60), clampStr(b.park, 120), clampStr(b.address, 300),
        JSON.stringify(items), total, STATUSES.includes(b.status) ? b.status : "new", clampStr(b.notes, 2000) || "", clampStr(b.source, 40) || "manual").run();
    const o = orderRow(await env.DB.prepare("SELECT * FROM orders WHERE ref = ?").bind(ref).first());
    await audit(env, { action: "create", entity: "order", entity_id: ref, summary: `Added order ${ref} (${b.name || "no name"})`, before: null, after: o });
    return json({ ok: true, order: o });
  }
  const om = p.match(/^\/api\/admin\/orders\/(AU-[A-Z0-9-]+)$/);
  if (om && m === "PATCH") {
    const ref = om[1];
    const before = orderRow(await env.DB.prepare("SELECT * FROM orders WHERE ref = ?").bind(ref).first());
    if (!before) return json({ error: "Order not found" }, 404);
    const b = await readBody(req, 20000);
    const f = {}; const changes = [];
    if (b.status !== undefined && STATUSES.includes(b.status) && b.status !== before.status) { f.status = b.status; changes.push(`status ${before.status} → ${b.status}`); }
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
    const after = orderRow(await env.DB.prepare("SELECT * FROM orders WHERE ref = ?").bind(ref).first());
    await audit(env, { action: "update", entity: "order", entity_id: ref, summary: `Order ${ref}: ${changes.join(", ")}`, before, after });
    return json({ ok: true, order: after });
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
      const current = orderRow(await env.DB.prepare("SELECT * FROM orders WHERE ref = ?").bind(a.entity_id).first());
      if (!before) { // undo a create = delete (soft)
        await env.DB.prepare("UPDATE orders SET deleted = 1, updated_at = ? WHERE ref = ?").bind(nowISO(), a.entity_id).run();
      } else {
        await env.DB.prepare("UPDATE orders SET name=?, phone=?, state=?, lga=?, park=?, address=?, items=?, total=?, status=?, notes=?, deleted=?, updated_at=? WHERE ref = ?")
          .bind(before.name, before.phone, before.state, before.lga, before.park, before.address, JSON.stringify(before.items || []), before.total, before.status, before.notes || "", before.deleted ? 1 : 0, nowISO(), a.entity_id).run();
      }
      const after = orderRow(await env.DB.prepare("SELECT * FROM orders WHERE ref = ?").bind(a.entity_id).first());
      await audit(env, { action: "undo", entity: "order", entity_id: a.entity_id, summary: `Undid: ${a.summary}`, before: current, after, undo_of: a.id });
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
      ? (await env.DB.prepare("SELECT ref, created_at, status, name, phone, state, lga, park, address, total, items, notes, source, deleted FROM orders ORDER BY id DESC").all()).results
      : (await env.DB.prepare("SELECT ts, type, path, source, referrer, country, region, city, device, visitor, session, data FROM events ORDER BY id DESC LIMIT 50000").all()).results;
    const cols = rows.length ? Object.keys(rows[0]) : [];
    const cell = (v) => { const s = v == null ? "" : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const csv = [cols.join(","), ...rows.map((r) => cols.map((c) => cell(r[c])).join(","))].join("\n");
    return new Response(csv, { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="au-${ex[1]}-${nowISO().slice(0, 10)}.csv"`, "cache-control": "no-store" } });
  }

  return json({ error: "Not found" }, 404);
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      if (url.pathname.startsWith("/api/admin/")) return await adminApi(req, env, url);
      return await publicApi(req, env, url, ctx);
    } catch (e) {
      return json({ error: e.message || "Server error" }, e.status || 500);
    }
  },
};
