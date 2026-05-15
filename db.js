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
`);

module.exports = db;
