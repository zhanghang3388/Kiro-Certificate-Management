const express = require('express');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const { ProxyAgent, fetch: undiciFetch } = require('undici');
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

// Kiro 订阅 API 配置
const KIRO_SUBSCRIPTION_VERSION = '0.12.155';
const KIRO_BUILDER_ID_PROFILE_ARN = 'arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX';
const KIRO_SOCIAL_PROFILE_ARN = 'arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK';

// 给账号生成稳定的 machineId（与 register-cli 一致：cli-<clientId 前 12 字符>）
function getStableMachineId(accountId, clientId) {
  if (clientId && typeof clientId === 'string' && clientId.length >= 12) {
    return `cli-${clientId.slice(0, 12)}`;
  }
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(`kiro-device-${accountId}`).digest('hex');
}

function getSubscriptionUserAgent(machineId) {
  const suffix = machineId ? `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}-${machineId}` : `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}`;
  return `aws-sdk-js/1.0.0 ua/2.1 os/win32#10.0.19043 lang/js md/nodejs#22.22.0 api/codewhispererruntime#1.0.0 m/N,E ${suffix}`;
}
function getSubscriptionAmzUserAgent(machineId) {
  const suffix = machineId ? `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}-${machineId}` : `KiroIDE-${KIRO_SUBSCRIPTION_VERSION}`;
  return `aws-sdk-js/1.0.0 ${suffix}`;
}

function getQEndpoint(region) {
  if (region && region.startsWith('eu-')) return 'https://q.eu-central-1.amazonaws.com';
  return 'https://q.us-east-1.amazonaws.com';
}

function resolveProfileArn(raw) {
  if (raw.profileArn) return raw.profileArn;
  if (raw.provider === 'Github' || raw.provider === 'Google' || raw.authMethod === 'social') {
    return KIRO_SOCIAL_PROFILE_ARN;
  }
  return KIRO_BUILDER_ID_PROFILE_ARN;
}

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

// ========== Kiro 订阅 API ==========

function buildSubHeaders(accessToken, accountId, rawMachineId, clientId) {
  const machineId = rawMachineId || getStableMachineId(accountId, clientId);
  return {
    'Authorization': `Bearer ${accessToken}`,
    'content-type': 'application/json',
    'user-agent': getSubscriptionUserAgent(machineId),
    'x-amz-user-agent': getSubscriptionAmzUserAgent(machineId),
    'amz-sdk-invocation-id': uuidv4(),
    'amz-sdk-request': 'attempt=1; max=1'
  };
}

// 通过 getUsageLimits 自动探测账号实际所在区域（参考 register-cli）
const Q_REGION_BASES = [
  'https://q.us-east-1.amazonaws.com',
  'https://q.eu-central-1.amazonaws.com'
];
const KIRO_USAGE_UA = 'aws-sdk-js/1.0.18 ua/2.1 os/windows lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.18 m/E KiroIDE-0.6.18';

async function probeAccountRegion(accountRow, accessToken) {
  for (const base of Q_REGION_BASES) {
    const url = `${base}/getUsageLimits?origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true`;
    try {
      const resp = await fetchAwsForAccount(accountRow, url, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
          'User-Agent': KIRO_USAGE_UA
        }
      });
      if (resp.status === 200) {
        console.log(`[sub] probed region for account=${accountRow.id}: ${base}`);
        return base;
      }
      console.log(`[sub] probe ${base} → ${resp.status} for account=${accountRow.id}`);
    } catch (err) {
      console.warn(`[sub] probe ${base} error:`, err.message);
    }
  }
  return null;
}

// 把账号绑定的代理 / 环境代理转成 undici ProxyAgent
function buildProxyAgentForAccount(accountRow) {
  // 1. 账号粒度代理
  if (accountRow.proxy_json) {
    try {
      const p = JSON.parse(accountRow.proxy_json);
      if (p.proxyType && p.proxyType !== 'noproxy' && p.host && p.port) {
        const auth = p.proxyUserName
          ? `${encodeURIComponent(p.proxyUserName)}:${encodeURIComponent(p.proxyPassword || '')}@`
          : '';
        // undici 的 ProxyAgent 只直接支持 http/https；socks5 走 env 也不行, 只能提示
        const scheme = p.proxyType === 'https' ? 'http' : (p.proxyType === 'socks5' ? null : 'http');
        if (!scheme) {
          console.warn(`[sub] account=${accountRow.id} 代理类型 ${p.proxyType} 暂不支持给后端 AWS 调用使用, 跳过`);
        } else {
          const uri = `${scheme}://${auth}${p.host}:${p.port}`;
          return { agent: new ProxyAgent({ uri, requestTls: { rejectUnauthorized: false } }), source: `account#${accountRow.id}` };
        }
      }
    } catch (e) {
      console.warn(`[sub] account=${accountRow.id} 代理 JSON 解析失败:`, e.message);
    }
  }
  // 2. 环境变量代理（HTTPS_PROXY 等）
  const envProxy = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy;
  if (envProxy) {
    return { agent: new ProxyAgent({ uri: envProxy, requestTls: { rejectUnauthorized: false } }), source: 'env' };
  }
  return { agent: null, source: 'direct' };
}

async function fetchAwsForAccount(accountRow, url, init) {
  const { agent, source } = buildProxyAgentForAccount(accountRow);
  console.log(`[sub] fetch ${url} via ${source}`);
  if (agent) {
    return undiciFetch(url, { ...init, dispatcher: agent });
  }
  return fetch(url, init);
}

// 确保账号有可用的 access token，必要时先刷新
async function ensureFreshAccessToken(accountRow) {
  const raw = JSON.parse(accountRow.raw_json);
  const expiresSoon = !accountRow.expires_at || accountRow.expires_at - Date.now() < 60 * 1000;
  if (accountRow.access_token && !expiresSoon) {
    return { ok: true, accessToken: accountRow.access_token, raw };
  }
  const result = await refreshTokenForAccount(accountRow);
  persistRefresh(accountRow.id, raw, result);
  if (!result.success) return { ok: false, error: result.error };
  return { ok: true, accessToken: result.accessToken, raw };
}

async function listAvailableSubscriptions(accountRow) {
  const fresh = await ensureFreshAccessToken(accountRow);
  if (!fresh.ok) return { success: false, error: fresh.error };

  // 通过 getUsageLimits 探测真实区域, 探测失败回退到 raw.region
  let baseUrl = await probeAccountRegion(accountRow, fresh.accessToken);
  if (!baseUrl) baseUrl = getQEndpoint(fresh.raw.region);

  const url = `${baseUrl}/listAvailableSubscriptions`;
  const headers = buildSubHeaders(fresh.accessToken, accountRow.id, fresh.raw.machineId, fresh.raw.clientId);
  const body = JSON.stringify({ profileArn: resolveProfileArn(fresh.raw) });
  console.log(`[sub] listAvailableSubscriptions account=${accountRow.id} email=${accountRow.email} base=${baseUrl} profileArn=${resolveProfileArn(fresh.raw)}`);
  try {
    const response = await fetchAwsForAccount(accountRow, url, { method: 'POST', headers, body });
    const text = await response.text();
    if (!response.ok) {
      console.error(`[sub] list failed account=${accountRow.id} status=${response.status} body=${text.slice(0, 500)}`);
      return { success: false, error: `HTTP ${response.status}: ${text.slice(0, 200)}` };
    }
    const data = JSON.parse(text);
    return { success: true, plans: data.subscriptionPlans || [], disclaimer: data.disclaimer || [], baseUrl };
  } catch (err) {
    console.error(`[sub] list error account=${accountRow.id}`, err);
    return { success: false, error: err.message || 'Unknown error' };
  }
}

async function createSubscriptionToken(accountRow, subscriptionType) {
  const fresh = await ensureFreshAccessToken(accountRow);
  if (!fresh.ok) return { success: false, error: fresh.error };

  // 同样先探测区域
  let baseUrl = await probeAccountRegion(accountRow, fresh.accessToken);
  if (!baseUrl) baseUrl = getQEndpoint(fresh.raw.region);

  const url = `${baseUrl}/CreateSubscriptionToken`;
  const profileArn = resolveProfileArn(fresh.raw);
  const headers = buildSubHeaders(fresh.accessToken, accountRow.id, fresh.raw.machineId, fresh.raw.clientId);

  console.log(`[sub] CreateSubscriptionToken account=${accountRow.id} email=${accountRow.email} base=${baseUrl} subscriptionType=${subscriptionType || '(none)'} profileArn=${profileArn} authMethod=${fresh.raw.authMethod || ''} provider=${fresh.raw.provider || ''}`);

  // 参考 register-cli: 新账号 Stripe 关联未就绪时会返回 200 空 url 或 4xx, 重试 6 次每次间隔 4 秒
  const ATTEMPTS = 6;
  const INTERVAL_MS = 4000;
  let lastError = '未知错误';

  for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
    const payload = {
      clientToken: uuidv4(),
      profileArn,
      provider: 'STRIPE'
    };
    if (subscriptionType) payload.subscriptionType = subscriptionType;

    try {
      const response = await fetchAwsForAccount(accountRow, url, {
        method: 'POST',
        headers: { ...headers, 'amz-sdk-invocation-id': uuidv4() },
        body: JSON.stringify(payload)
      });
      const text = await response.text();

      if (response.ok) {
        let data = {};
        try { data = JSON.parse(text); } catch {}
        if (data.encodedVerificationUrl) {
          console.log(`[sub] create ok account=${accountRow.id} attempt=${attempt}/${ATTEMPTS} status=${data.status}`);
          return { success: true, url: data.encodedVerificationUrl, status: data.status, raw: data };
        }
        lastError = `200 但缺 encodedVerificationUrl: ${text.slice(0, 200)}`;
        console.warn(`[sub] account=${accountRow.id} attempt=${attempt}/${ATTEMPTS} ${lastError}`);
      } else {
        lastError = `HTTP ${response.status}: ${text.slice(0, 400)}`;
        console.error(`[sub] account=${accountRow.id} attempt=${attempt}/${ATTEMPTS} ${lastError}`);
      }
    } catch (err) {
      lastError = err.message || 'Unknown error';
      console.error(`[sub] account=${accountRow.id} attempt=${attempt}/${ATTEMPTS} fetch error:`, err);
    }

    if (attempt < ATTEMPTS) {
      await new Promise(r => setTimeout(r, INTERVAL_MS));
    }
  }

  return { success: false, error: `重试 ${ATTEMPTS} 次仍失败: ${lastError}` };
}

// ========== Settings (BitBrowser 配置) ==========

const DEFAULT_BITBROWSER_API = 'http://127.0.0.1:54345';

function getSettings() {
  const rows = db.prepare('SELECT key, value FROM settings').all();
  const map = Object.fromEntries(rows.map(r => [r.key, r.value]));
  return {
    bitbrowserEnabled: map.bitbrowser_enabled === '1',
    bitbrowserApi: map.bitbrowser_api || DEFAULT_BITBROWSER_API,
    bitbrowserGroupId: map.bitbrowser_group_id || ''
  };
}

function saveSettings(patch) {
  const upsert = db.prepare(`
    INSERT INTO settings (key, value) VALUES (?, ?)
    ON CONFLICT(key) DO UPDATE SET value = excluded.value
  `);
  const tx = db.transaction(() => {
    if ('bitbrowserEnabled' in patch) upsert.run('bitbrowser_enabled', patch.bitbrowserEnabled ? '1' : '0');
    if ('bitbrowserApi' in patch) upsert.run('bitbrowser_api', String(patch.bitbrowserApi || ''));
    if ('bitbrowserGroupId' in patch) upsert.run('bitbrowser_group_id', String(patch.bitbrowserGroupId || ''));
  });
  tx();
}

// ========== BitBrowser 配置说明 ==========
// 比特指纹浏览器只在你本机监听 127.0.0.1, 因此服务部署到 VPS 后无法直接调用,
// 真正的开窗动作由前端 JS 在你打开管理页的浏览器里直连本地比特 API 完成。
// 这里只负责保存 / 读取地址等配置, 给前端 fetch 用。




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
           created_at, expires_at, last_status, last_error, last_checked_at,
           bit_window_id, proxy_json
    FROM accounts
    ORDER BY id DESC
  `).all();
  // 把 proxy_json 反序列化, 隐藏密码（仅返回是否设置过）
  for (const r of rows) {
    if (r.proxy_json) {
      try {
        const p = JSON.parse(r.proxy_json);
        r.proxy = {
          proxyType: p.proxyType || 'noproxy',
          host: p.host || '',
          port: p.port || '',
          proxyUserName: p.proxyUserName || '',
          hasPassword: !!p.proxyPassword
        };
      } catch { r.proxy = null; }
    } else {
      r.proxy = null;
    }
    delete r.proxy_json;
  }
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

// ===== 账号代理 / 比特窗口绑定 =====

const ALLOWED_PROXY_TYPES = new Set(['noproxy', 'http', 'https', 'socks5', 'ssh']);

app.put('/api/admin/accounts/:id/proxy', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const row = db.prepare('SELECT id, proxy_json FROM accounts WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: '账号不存在' });

  const body = req.body || {};
  const proxyType = String(body.proxyType || 'noproxy').toLowerCase();
  if (!ALLOWED_PROXY_TYPES.has(proxyType)) {
    return res.status(400).json({ error: '无效的代理类型' });
  }

  if (proxyType === 'noproxy') {
    db.prepare('UPDATE accounts SET proxy_json = NULL WHERE id = ?').run(id);
    return res.json({ ok: true, proxy: null });
  }

  // 保留旧密码：当前端没传 proxyPassword 字段时不覆盖
  let prev = {};
  if (row.proxy_json) {
    try { prev = JSON.parse(row.proxy_json) || {}; } catch {}
  }

  const proxy = {
    proxyType,
    host: String(body.host || '').trim(),
    port: String(body.port || '').trim(),
    proxyUserName: String(body.proxyUserName || '').trim(),
    proxyPassword: typeof body.proxyPassword === 'string'
      ? body.proxyPassword
      : (prev.proxyPassword || '')
  };

  if (!proxy.host || !proxy.port) {
    return res.status(400).json({ error: 'host 和 port 必填' });
  }

  db.prepare('UPDATE accounts SET proxy_json = ? WHERE id = ?').run(JSON.stringify(proxy), id);
  res.json({
    ok: true,
    proxy: {
      proxyType: proxy.proxyType,
      host: proxy.host,
      port: proxy.port,
      proxyUserName: proxy.proxyUserName,
      hasPassword: !!proxy.proxyPassword
    }
  });
});

// 拉取完整代理配置（包含密码），供前端调比特用
app.get('/api/admin/accounts/:id/proxy-detail', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const row = db.prepare('SELECT proxy_json FROM accounts WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: '账号不存在' });
  if (!row.proxy_json) return res.json({ proxy: null });
  try {
    res.json({ proxy: JSON.parse(row.proxy_json) });
  } catch {
    res.json({ proxy: null });
  }
});

app.put('/api/admin/accounts/:id/bit-window', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const windowId = req.body?.windowId;
  if (windowId !== null && typeof windowId !== 'string') {
    return res.status(400).json({ error: 'windowId 必须是字符串或 null' });
  }
  const result = db.prepare('UPDATE accounts SET bit_window_id = ? WHERE id = ?').run(windowId || null, id);
  if (!result.changes) return res.status(404).json({ error: '账号不存在' });
  res.json({ ok: true });
});

// ===== 订阅 API =====
app.get('/api/admin/accounts/:id/subscriptions', adminAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const row = db.prepare('SELECT * FROM accounts WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: '账号不存在' });
  const result = await listAvailableSubscriptions(row);
  if (!result.success) return res.status(400).json({ error: result.error });
  res.json({ plans: result.plans, disclaimer: result.disclaimer });
});

app.post('/api/admin/accounts/:id/subscription-url', adminAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const row = db.prepare('SELECT * FROM accounts WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: '账号不存在' });

  const subscriptionType = req.body?.subscriptionType;
  const tokenResult = await createSubscriptionToken(row, subscriptionType);
  if (!tokenResult.success) return res.status(400).json({ error: tokenResult.error });
  if (!tokenResult.url) return res.status(400).json({ error: '响应中没有支付链接' });

  // 比特浏览器开窗动作由前端浏览器直连本地 API 完成
  res.json({ url: tokenResult.url });
});

// ===== 设置 API =====

app.get('/api/admin/settings', adminAuth, (req, res) => {
  res.json(getSettings());
});

app.post('/api/admin/settings', adminAuth, (req, res) => {
  const body = req.body || {};
  const patch = {};
  if (typeof body.bitbrowserEnabled === 'boolean') patch.bitbrowserEnabled = body.bitbrowserEnabled;
  if (typeof body.bitbrowserApi === 'string') patch.bitbrowserApi = body.bitbrowserApi.trim();
  if (typeof body.bitbrowserGroupId === 'string') patch.bitbrowserGroupId = body.bitbrowserGroupId.trim();
  saveSettings(patch);
  res.json({ ok: true, settings: getSettings() });
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
