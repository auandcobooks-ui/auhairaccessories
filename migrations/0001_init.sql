CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, created_at TEXT NOT NULL, updated_at TEXT,
  name TEXT, phone TEXT, state TEXT, lga TEXT, park TEXT, address TEXT,
  items TEXT, total INTEGER, status TEXT DEFAULT 'new', notes TEXT DEFAULT '', deleted INTEGER DEFAULT 0,
  visitor TEXT, source TEXT);
CREATE INDEX IF NOT EXISTS orders_created ON orders(created_at);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, type TEXT, path TEXT, referrer TEXT, source TEXT,
  visitor TEXT, session TEXT, country TEXT, region TEXT, city TEXT, device TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_type_ts ON events(type, ts);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, action TEXT, entity TEXT, entity_id TEXT,
  summary TEXT, before TEXT, after TEXT, undone INTEGER DEFAULT 0, undo_of INTEGER);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
