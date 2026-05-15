# Kiro 凭证管理系统

一个简易的 Kiro 账号凭证管理 + 一次性下载密钥分发系统。

## 功能

- 管理员上传 Kiro 账号 JSON 文件，自动解析为账号列表（按 `clientId` 去重）。
- 多选账号 → 生成一次性下载密钥（UUID）。
- 用户使用密钥下载，返回与上传时同格式的 JSON 文件。密钥使用一次后失效，关联账号标记为已使用。

## 启动

```bash
npm install
ADMIN_KEY=your-secret npm start
```

环境变量：
- `ADMIN_KEY` 管理员密钥（必填，生产环境务必设置）
- `PORT` 端口，默认 `3000`

页面：
- 管理员登录：`/login.html`
- 管理后台：`/admin.html`（需登录）
- 用户下载：`/`

## VPS 部署示例

```bash
git clone https://github.com/zhanghang3388/Kiro-Certificate-Management.git
cd Kiro-Certificate-Management
npm ci --omit=dev
ADMIN_KEY=your-secret PORT=3000 node server.js
```

建议用 `pm2` / `systemd` 守护进程，并通过 nginx 反向代理 + HTTPS 暴露。

```bash
npm i -g pm2
ADMIN_KEY=your-secret pm2 start server.js --name kiro
pm2 save
pm2 startup
```

## 数据

- SQLite 文件 `data.db`（已在 `.gitignore` 中），首次启动自动创建表。
- 重置数据：停止服务后删除 `data.db*` 三个文件。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/admin/login` | 校验管理员密钥 |
| POST | `/api/admin/upload` | 上传账号 JSON |
| GET | `/api/admin/accounts` | 账号列表 |
| DELETE | `/api/admin/accounts/:id` | 删除账号 |
| POST | `/api/admin/generate-key` | 多选生成下载密钥 |
| GET | `/api/admin/keys` | 已生成密钥列表 |
| GET | `/api/download/:key` | 用户下载（一次性） |

除 `/api/download/:key` 和 `/api/admin/login` 外，所有 admin 接口需要 `x-admin-key` 请求头。
