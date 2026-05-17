const express = require('express');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-me-in-production';

// 保活相关配置
const KEEPALIVE_INTERVAL_MS = Number(process.env.KEEPALIVE_INTERVAL_MS) || 10 * 60 * 1000; // 10 分钟扫一次
const REFRESH_THRESHOLD_MS = Number(process.env.REFRESH_THRESHOLD_MS) || 15 * 60 * 1000;   // 距过期 15 分钟内才刷
const KIRO_AUTH_ENDPOINT = 'https://prod.us-east-1.auth.desktop.kiro.dev';
const KIRO_VERSION = '0.6.18';
const KIRO_USER_AGENT = `aws-sdk-js/1.0.18 ua/2.1 os/windows lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE-${KIRO_VERSION}`;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function adminAuth(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(401).json({ error: '未授权' });
  }
  next();
}

app.post('/api/admin/login', (req, res) => {
  const key = req.body?.key;
  if (typeof key !== 'string' || key !== ADMIN_KEY) {
    return res.status(401).json({ error: '密钥错误' });
  }
  res.json({ ok: true });
});

const REQUIRED_FIELDS = ['clientId', 'clientSecret', 'refreshToken'];

function validateAccount(item) {
  if (!item || typeof item !== 'object') return false;
  // 社交登录只需要 refreshToken；IdC 需要全部三个
  if (typeof item.refreshToken !== 'string' || !item.refreshToken) return false;
  if (item.authMethod === 'social') return true;
  return REQUIRED_FIELDS.every(f => typeof item[f] === 'string' && item[f].length > 0);
}

// ========== Token 刷新 ==========

async function refreshOidcToken(refreshToken, clientId, clientSecret, region = 'us-east-1') {
  const url = `https://oidc.${region}.amazonaws.com/token`;
  const payload = { clientId, clientSecret, refreshToken, grantType: 'refresh_token' };
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (!response.ok) {
      const errorText = await response.text();
      return { success: false, error: `HTTP ${response.status}: ${errorText}` };
    }
    const data = await response.json();
    return {
      success: true,
      accessToken: data.accessToken,
      refreshToken: data.refreshToken || refreshToken,
      expiresIn: data.expiresIn
    };
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Unknown error' };
  }
}

async function refreshSocialToken(refreshToken) {
  const url = `${KIRO_AUTH_ENDPOINT}/refreshToken`;
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': KIRO_USER_AGENT
      },
      body: JSON.stringify({ refreshToken })
    });
    if (!response.ok) {
      const errorText = await response.text();
      return { success: false, error: `HTTP ${response.status}: ${errorText}` };
    }
    const data = await response.json();
    return {
      success: true,
      accessToken: data.accessToken,
      refreshToken: data.refreshToken || refreshToken,
      expiresIn: data.expiresIn
    };
  } catch (err) {
    return { success: false, error: err instanceof Error ? err.message : 'Unknown error' };
  }
}

async function refreshTokenForAccount(accountRow) {
  let raw;
  try {
    raw = JSON.parse(accountRow.raw_json);
  } catch {
    return { success: false, error: 'raw_json 解析失败' };
  }

  const { refreshToken, clientId, clientSecret, region, authMethod } = raw;
  if (!refreshToken) return { success: false, error: '缺少 refreshToken' };

  const result = authMethod === 'social'
    ? await refreshSocialToken(refreshToken)
    : await refreshOidcToken(refreshToken, clientId, clientSecret, region || 'us-east-1');

  return result;
}

// 把刷新结果落库
function persistRefresh(accountId, raw, result) {
  const now = new Date().toISOString();
  if (!result.success) {
    db.prepare(`
      UPDATE accounts
      SET last_status = 'error',
          last_error = ?,
          last_checked_at = ?
      WHERE id = ?
    `).run(result.error || 'Unknown error', now, accountId);
    return;
  }

  const expiresAt = result.expiresIn
    ? Date.now() + result.expiresIn * 1000
    : null;

  // 更新 raw_json 中的 token 字段，保证下载出去的也是最新的
  raw.accessToken = result.accessToken;
  raw.refreshToken = result.refreshToken;
  if (expiresAt) raw.expiresAt = expiresAt;

  db.prepare(`
    UPDATE accounts
    SET access_token = ?,
        expires_at = ?,
        last_status = 'active',
        last_error = NULL,
        last_checked_at = ?,
        raw_json = ?
    WHERE id = ?
  `).run(result.accessToken, expiresAt, now, JSON.stringify(raw), accountId);
}

async function refreshAccountById(id) {
  const row = db.prepare('SELECT * FROM accounts WHERE id = ?').get(id);
  if (!row) return { success: false, error: '账号不存在' };

  db.prepare(`UPDATE accounts SET last_status = 'refreshing' WHERE id = ?`).run(id);

  const raw = JSON.parse(row.raw_json);
  const result = await refreshTokenForAccount(row);
  persistRefresh(id, raw, result);
  return result;
}

// 定时保活：扫描所有未使用账号，过期或临近过期的刷新
async function keepAliveTick() {
  const rows = db.prepare(`
    SELECT id, expires_at, last_status
    FROM accounts
    WHERE used = 0
  `).all();

  const now = Date.now();
  const targets = rows.filter(r => {
    if (r.last_status === 'refreshing') return false;
    if (!r.expires_at) return true; // 未知状态，刷一次
    return r.expires_at - now <= REFRESH_THRESHOLD_MS;
  });

  if (!targets.length) return;
  console.log(`[keepalive] refreshing ${targets.length} account(s)`);

  for (const t of targets) {
    try {
      const r = await refreshAccountById(t.id);
      if (!r.success) {
        console.warn(`[keepalive] account ${t.id} failed: ${r.error}`);
      }
    } catch (err) {
      console.error(`[keepalive] account ${t.id} error:`, err);
    }
  }
}

// ========== 管理 API ==========

app.post('/api/admin/upload', adminAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: '未提供文件' });

  let parsed;
  try {
    parsed = JSON.parse(req.file.buffer.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'JSON 解析失败' });
  }

  const list = Array.isArray(parsed) ? parsed : [parsed];
  const valid = list.filter(validateAccount);
  if (!valid.length) return res.status(400).json({ error: '未找到有效账号' });

  const insert = db.prepare(`
    INSERT INTO accounts (client_id, email, region, subscription, provider, raw_json, last_status)
    VALUES (?, ?, ?, ?, ?, ?, 'unknown')
    ON CONFLICT(client_id) DO UPDATE SET
      email = excluded.email,
      region = excluded.region,
      subscription = excluded.subscription,
      provider = excluded.provider,
      raw_json = excluded.raw_json,
      used = 0,
      last_status = 'unknown',
      last_error = NULL
  `);

  const insertedIds = [];
  const tx = db.transaction(items => {
    for (const a of items) {
      const clientIdKey = a.clientId || `social:${a.refreshToken.slice(0, 32)}`;
      insert.run(
        clientIdKey,
        a.email || null,
        a.region || null,
        a.subscription || null,
        a.provider || null,
        JSON.stringify(a)
      );
      const row = db.prepare('SELECT id FROM accounts WHERE client_id = ?').get(clientIdKey);
      if (row) insertedIds.push(row.id);
    }
  });
  tx(valid);

  // 异步触发一次刷新，不阻塞响应
  Promise.allSettled(insertedIds.map(id => refreshAccountById(id)))
    .then(() => console.log(`[upload] initial refresh done for ${insertedIds.length} account(s)`));

  res.json({ inserted: valid.length, skipped: list.length - valid.length });
});

app.get('/api/admin/accounts', adminAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, client_id, email, region, subscription, provider, used,
           created_at, expires_at, last_status, last_error, last_checked_at
    FROM accounts
    ORDER BY id DESC
  `).all();
  res.json(rows);
});

app.delete('/api/admin/accounts/:id', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const result = db.prepare('DELETE FROM accounts WHERE id = ?').run(id);
  if (!result.changes) return res.status(404).json({ error: '账号不存在' });
  res.json({ ok: true });
});

// 手动刷新单个账号
app.post('/api/admin/accounts/:id/refresh', adminAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const result = await refreshAccountById(id);
  if (!result.success) return res.status(400).json(result);
  const row = db.prepare(`
    SELECT id, client_id, email, region, subscription, provider, used,
           created_at, expires_at, last_status, last_error, last_checked_at
    FROM accounts WHERE id = ?
  `).get(id);
  res.json({ ok: true, account: row });
});

// 批量刷新所有未使用账号
app.post('/api/admin/accounts/refresh-all', adminAuth, async (req, res) => {
  const rows = db.prepare(`SELECT id FROM accounts WHERE used = 0`).all();
  let ok = 0, fail = 0;
  for (const r of rows) {
    const result = await refreshAccountById(r.id);
    if (result.success) ok++; else fail++;
  }
  res.json({ total: rows.length, ok, fail });
});

app.post('/api/admin/generate-key', adminAuth, (req, res) => {
  const ids = Array.isArray(req.body?.accountIds) ? req.body.accountIds : [];
  const cleanIds = [...new Set(ids.filter(Number.isInteger))];
  if (!cleanIds.length) return res.status(400).json({ error: '请选择至少一个账号' });

  const placeholders = cleanIds.map(() => '?').join(',');
  const found = db.prepare(
    `SELECT id FROM accounts WHERE id IN (${placeholders}) AND used = 0`
  ).all(...cleanIds);

  if (found.length !== cleanIds.length) {
    return res.status(400).json({ error: '部分账号不存在或已被使用' });
  }

  const downloadKey = uuidv4();

  const tx = db.transaction(() => {
    const info = db.prepare(
      'INSERT INTO download_keys (download_key) VALUES (?)'
    ).run(downloadKey);
    const link = db.prepare(
      'INSERT INTO download_key_accounts (download_key_id, account_id) VALUES (?, ?)'
    );
    for (const id of cleanIds) link.run(info.lastInsertRowid, id);
  });
  tx();

  res.json({ key: downloadKey, count: cleanIds.length });
});

app.get('/api/admin/keys', adminAuth, (req, res) => {
  const keys = db.prepare(`
    SELECT k.id, k.download_key, k.used, k.created_at,
           COUNT(dka.account_id) AS account_count
    FROM download_keys k
    LEFT JOIN download_key_accounts dka ON dka.download_key_id = k.id
    GROUP BY k.id
    ORDER BY k.id DESC
  `).all();
  res.json(keys);
});

app.get('/api/download/:key', (req, res) => {
  const keyRow = db.prepare(
    'SELECT * FROM download_keys WHERE download_key = ? AND used = 0'
  ).get(req.params.key);

  if (!keyRow) return res.status(404).json({ error: '密钥无效或已使用' });

  const accounts = db.prepare(`
    SELECT a.raw_json
    FROM accounts a
    JOIN download_key_accounts dka ON dka.account_id = a.id
    WHERE dka.download_key_id = ? AND a.used = 0
  `).all(keyRow.id);

  if (!accounts.length) {
    return res.status(410).json({ error: '关联账号不可用' });
  }

  const payload = accounts.map(r => JSON.parse(r.raw_json));

  const tx = db.transaction(() => {
    db.prepare('UPDATE download_keys SET used = 1 WHERE id = ?').run(keyRow.id);
    db.prepare(`
      UPDATE accounts SET used = 1
      WHERE id IN (
        SELECT account_id FROM download_key_accounts WHERE download_key_id = ?
      )
    `).run(keyRow.id);
  });
  tx();

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="kiro-accounts.json"');
  res.send(JSON.stringify(payload, null, 2));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin.html`);

  // 启动后立即跑一次，再开定时
  keepAliveTick().catch(err => console.error('[keepalive] initial error:', err));
  setInterval(() => {
    keepAliveTick().catch(err => console.error('[keepalive] tick error:', err));
  }, KEEPALIVE_INTERVAL_MS);
});
