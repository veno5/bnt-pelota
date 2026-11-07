-- BNT Pelota: las funciones crean automaticamente estas tablas al configurar el binding D1 "DB".
-- Este archivo es la documentacion del esquema para respaldo y auditoria.
CREATE TABLE IF NOT EXISTS bnt_members (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 phone TEXT NOT NULL UNIQUE,
 pin_salt TEXT NOT NULL,
 pin_hash TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending',
 paid_until TEXT,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bnt_payments (
 id TEXT PRIMARY KEY,
 member_id TEXT NOT NULL,
 amount_cents INTEGER NOT NULL,
 currency TEXT NOT NULL,
 months INTEGER NOT NULL,
 previous_until TEXT,
 new_until TEXT NOT NULL,
 reference TEXT,
 created_at TEXT NOT NULL,
 FOREIGN KEY(member_id) REFERENCES bnt_members(id)
);
CREATE INDEX IF NOT EXISTS bnt_payments_member_idx ON bnt_payments(member_id,created_at);
CREATE TABLE IF NOT EXISTS bnt_sessions (
 token_hash TEXT PRIMARY KEY,
 actor TEXT NOT NULL,
 member_id TEXT,
 expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bnt_limits (
 key TEXT PRIMARY KEY,
 period_start INTEGER NOT NULL,
 count INTEGER NOT NULL
);
