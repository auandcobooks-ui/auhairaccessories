-- Partners: wig-making classes / academies AU wants to supply, with tailored proposals
CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT, updated_at TEXT,
  name TEXT, kind TEXT, city TEXT, country TEXT,
  whatsapp TEXT, phone TEXT, email TEXT, instagram TEXT, facebook TEXT, website TEXT,
  about TEXT, price_info TEXT, next_date TEXT, source_url TEXT, notes TEXT,
  status TEXT DEFAULT 'new', contacted_at TEXT, deleted INTEGER DEFAULT 0,
  token TEXT UNIQUE, proposal TEXT, proposal_at TEXT, pdf BLOB, og BLOB
);
CREATE INDEX IF NOT EXISTS leads_status ON leads(status);
