const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'data.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE NOT NULL,
    email TEXT,
    region TEXT,
    subscription TEXT,
    provider TEXT,
    raw_json TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS download_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    download_key TEXT UNIQUE NOT NULL,
    used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS download_key_accounts (
    download_key_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    PRIMARY KEY (download_key_id, account_id),
    FOREIGN KEY (download_key_id) REFERENCES download_keys(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// 兼容旧库：增量添加保活相关字段
const existingCols = new Set(
  db.prepare(`PRAGMA table_info(accounts)`).all().map(c => c.name)
);
const addColumn = (name, ddl) => {
  if (!existingCols.has(name)) {
    db.exec(`ALTER TABLE accounts ADD COLUMN ${ddl}`);
  }
};
addColumn('access_token', 'access_token TEXT');
addColumn('expires_at', 'expires_at INTEGER');
addColumn('last_checked_at', 'last_checked_at TEXT');
addColumn('last_status', `last_status TEXT DEFAULT 'unknown'`);
addColumn('last_error', 'last_error TEXT');
addColumn('bit_window_id', 'bit_window_id TEXT');
addColumn('proxy_json', 'proxy_json TEXT');

module.exports = db;
