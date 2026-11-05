-- Order progress timestamps (an order moves New -> Confirmed & paid -> Dispatched -> Delivered)
ALTER TABLE orders ADD COLUMN confirmed_at TEXT;
ALTER TABLE orders ADD COLUMN dispatched_at TEXT;
ALTER TABLE orders ADD COLUMN delivered_at TEXT;
ALTER TABLE orders ADD COLUMN cancelled_at TEXT;

-- "paid" is merged into "confirmed" (confirmed means payment received)
UPDATE orders SET status = 'confirmed' WHERE status = 'paid';
UPDATE orders SET confirmed_at = updated_at WHERE status IN ('confirmed', 'dispatched', 'delivered') AND confirmed_at IS NULL;
UPDATE orders SET dispatched_at = updated_at WHERE status IN ('dispatched', 'delivered') AND dispatched_at IS NULL;
UPDATE orders SET delivered_at = updated_at WHERE status = 'delivered' AND delivered_at IS NULL;
UPDATE orders SET cancelled_at = updated_at WHERE status = 'cancelled' AND cancelled_at IS NULL;

-- Branded receipts: full receipt image + link-preview card, shared by a private link
CREATE TABLE IF NOT EXISTS receipts (
  ref TEXT PRIMARY KEY,
  token TEXT UNIQUE NOT NULL,
  img BLOB,
  og BLOB,
  created_at TEXT,
  updated_at TEXT,
  sent_at TEXT
);

-- Customer book notes (customers themselves are built from orders, keyed by phone)
CREATE TABLE IF NOT EXISTS customers (
  key TEXT PRIMARY KEY,
  notes TEXT,
  updated_at TEXT
);
