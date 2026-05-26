const express = require('express');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const Database = require('better-sqlite3');
const { exec } = require('child_process'); // For RCE/Command Injection vulns
const fs   = require('fs');                // For LFI vuln

const app = express();
const PORT = 3000;

// ─── SQLite Setup ──────────────────────────────────────────────────────────
const db = new Database(path.join(__dirname, 'logs.db'));

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

// Create the request_logs table if it doesn't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS request_logs (
    id               TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    method           TEXT NOT NULL,
    path             TEXT NOT NULL,
    protocol         TEXT NOT NULL,
    request_line     TEXT NOT NULL,
    headers          TEXT,
    body             TEXT,
    ip               TEXT,
    status           INTEGER,
    response_headers TEXT,
    response_body    TEXT
  );
`);

// Migrate existing DBs — add new columns if they don't exist yet
try { db.exec(`ALTER TABLE request_logs ADD COLUMN response_headers TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE request_logs ADD COLUMN response_body    TEXT`); } catch (_) {}

// Prepared statements for performance
const insertLog = db.prepare(`
  INSERT INTO request_logs (id, timestamp, method, path, protocol, request_line, headers, body, ip, status)
  VALUES (@id, @timestamp, @method, @path, @protocol, @requestLine, @headers, @body, @ip, @status)
`);

const updateStatus = db.prepare(`
  UPDATE request_logs SET status = ?, response_headers = ?, response_body = ? WHERE id = ?
`);

const getLogsPage = db.prepare(`
  SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?
`);

const countLogs = db.prepare(`
  SELECT COUNT(*) as total FROM request_logs
`);

// Create the custom_endpoints table
db.exec(`
  CREATE TABLE IF NOT EXISTS custom_endpoints (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_path TEXT UNIQUE NOT NULL,
    content_type  TEXT DEFAULT 'application/json',
    response_body TEXT DEFAULT '{"message": "Custom Response"}',
    custom_headers TEXT DEFAULT '{}'
  );
`);

try { db.exec(`ALTER TABLE custom_endpoints ADD COLUMN custom_headers TEXT DEFAULT '{}'`); } catch (_) {}

// Seed /custom/1 to /custom/5 if they don't exist
const checkCustom = db.prepare(`SELECT count(*) as count FROM custom_endpoints`).get();
if (checkCustom.count === 0) {
  const insertCustom = db.prepare(`INSERT INTO custom_endpoints (endpoint_path, response_body) VALUES (?, ?)`);
  const insertMany = db.transaction(() => {
    for (let i = 1; i <= 5; i++) {
      insertCustom.run(`/custom/${i}`, `{\n  "message": "Hello from custom endpoint ${i}!"\n}`);
    }
  });
  insertMany();
}

const getAllCustomEndpoints = db.prepare(`SELECT * FROM custom_endpoints ORDER BY id ASC`);
const getCustomEndpoint = db.prepare(`SELECT * FROM custom_endpoints WHERE endpoint_path = ?`);
const updateCustomEndpoint = db.prepare(`UPDATE custom_endpoints SET content_type = ?, response_body = ?, custom_headers = ? WHERE id = ?`);

const clearAllLogs = db.prepare(`
  DELETE FROM request_logs
`);

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Auth: Session Store ──────────────────────────────────────────────────
// Lightweight in-memory session (no extra npm deps needed)
const sessions = new Map(); // token → { username, createdAt }
const SESSION_COOKIE = 'rl_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// Demo credentials
const DEMO_USERS = [
  { username: 'snapsec0x01@gmail.com', password: 'snapsec0x01@gmail.com' },
];

function parseCookies(cookieHeader = '') {
  return Object.fromEntries(
    cookieHeader.split(';').map(c => c.trim().split('=').map(s => decodeURIComponent(s.trim())))
  );
}

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token   = cookies[SESSION_COOKIE];
  if (!token) return null;
  const sess = sessions.get(token);
  if (!sess) return null;
  if (Date.now() - sess.createdAt > SESSION_TTL_MS) { sessions.delete(token); return null; }
  return sess;
}

// ─── Auth: Login / Logout Routes (public — must be before auth guard) ────
app.get('/login', (req, res) => {
  if (getSession(req)) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password, next } = req.body;
  const user = DEMO_USERS.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.redirect('/login?error=1');
  }
  const token = uuidv4();
  sessions.set(token, { username: user.username, createdAt: Date.now() });
  res.setHeader('Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800`);
  // Redirect to original destination or home
  const dest = (next && next.startsWith('/') && !next.startsWith('//')) ? next : '/';
  res.redirect(dest);
});

app.get('/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const token   = cookies[SESSION_COOKIE];
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; Max-Age=0`);
  res.redirect('/login');
});

// ─── Auth: Guard Middleware (all routes below this point are protected) ────
// Public exceptions:
//   • /login           — the login page itself
//   • /public/*        — CSS, fonts, static assets
//   • /vulnerabilities/api/users — intentionally unprotected (vuln demo)
app.use((req, res, next) => {
  const PUBLIC_PATHS = ['/login', '/logout'];
  if (
    PUBLIC_PATHS.includes(req.path) ||
    req.path.startsWith('/public/') ||
    req.path === '/vulnerabilities/api/users'
  ) return next();

  if (!getSession(req)) {
    // API requests get 401 JSON; page requests get redirected
    const wantsJson = req.headers.accept?.includes('application/json') ||
                      req.headers['content-type']?.includes('application/json') ||
                      req.path.startsWith('/api/') ||
                      req.path.startsWith('/graphql');
    if (wantsJson) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Authentication required', loginUrl: '/login' });
    }
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
  }
  // Attach user to request for downstream use
  req.currentUser = getSession(req);
  next();
});

// ─── ANSI color helpers ───────────────────────────────────────────────────
const ANSI = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  // Methods
  green:   '\x1b[32m',
  blue:    '\x1b[34m',
  yellow:  '\x1b[33m',
  magenta: '\x1b[35m',
  red:     '\x1b[31m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',
  gray:    '\x1b[90m',
};

const METHOD_COLORS = {
  GET:    ANSI.green,
  POST:   ANSI.blue,
  PUT:    ANSI.yellow,
  PATCH:  ANSI.magenta,
  DELETE: ANSI.red,
};

function statusColor(code) {
  if (code >= 500) return ANSI.red;
  if (code >= 400) return ANSI.yellow;
  if (code >= 300) return ANSI.cyan;
  return ANSI.green;
}

// ─── Request Logger Middleware ─────────────────────────────────────────────
app.use((req, res, next) => {
  // Skip logging for UI pages and static assets
  const skip = ['/', '/logs', '/custom', '/vulnerabilities', '/login', '/favicon.ico'].some(p => req.path === p) ||
               req.path.startsWith('/public/') ||
               req.path.startsWith('/api/logs') ||
               req.path.startsWith('/api/custom-endpoints') ||
               req.path === '/api/me';

  if (skip) return next();

  const startTime  = process.hrtime.bigint();   // nanosecond precision
  const timestamp  = new Date().toISOString();
  const id         = uuidv4();

  // Capture raw body for display
  let rawBody = '';
  if (req.body && Object.keys(req.body).length > 0) {
    rawBody = JSON.stringify(req.body, null, 4);
  }

  // Build headers string (filter noise headers)
  const excludeHeaders = ['connection', 'transfer-encoding'];
  const headersLines = Object.entries(req.headers)
    .filter(([k]) => !excludeHeaders.includes(k.toLowerCase()))
    .map(([k, v]) => `${capitalizeHeader(k)}: ${v}`)
    .join('\n');

  const protocol = `HTTP/${req.httpVersion}`;
  const requestLine = `${req.method} ${req.originalUrl} ${protocol}`;

  const logEntry = {
    id,
    timestamp,
    method:      req.method,
    path:        req.originalUrl,
    protocol,
    requestLine,
    headers:     headersLines,
    body:        rawBody,
    ip:          req.ip || req.connection.remoteAddress,
    status:      null,
  };

  // Insert into SQLite immediately (response fields filled on finish)
  insertLog.run(logEntry);

  // ── Intercept response body ───────────────────────────────────────────
  let capturedResponseBody = '';

  const _json = res.json.bind(res);
  res.json = function (data) {
    capturedResponseBody = JSON.stringify(data, null, 4);
    return _json(data);
  };

  const _send = res.send.bind(res);
  res.send = function (data) {
    if (!capturedResponseBody && typeof data === 'string') {
      capturedResponseBody = data;
    }
    return _send(data);
  };

  // Update DB once response is fully sent
  res.on('finish', () => {
    const resHeaders = res.getHeaders ? res.getHeaders() : {};
    const excludeResHeaders = ['connection', 'transfer-encoding', 'keep-alive'];
    const resHeadersStr = Object.entries(resHeaders)
      .filter(([k]) => !excludeResHeaders.includes(k.toLowerCase()))
      .map(([k, v]) => `${capitalizeHeader(k)}: ${v}`)
      .join('\n');

    updateStatus.run(res.statusCode, resHeadersStr, capturedResponseBody, id);

    // ── Pretty console log ────────────────────────────────────────────────
    const elapsedMs  = Number(process.hrtime.bigint() - startTime) / 1e6;
    const timeStr    = elapsedMs < 1000
      ? `${elapsedMs.toFixed(1)}ms`
      : `${(elapsedMs / 1000).toFixed(2)}s`;
    const methodCol  = METHOD_COLORS[req.method] || ANSI.white;
    const statusCol  = statusColor(res.statusCode);

    console.log(
      `${ANSI.gray}[~]${ANSI.reset} ` +
      `${ANSI.bold}${methodCol}${req.method.padEnd(6)}${ANSI.reset} ` +
      `${ANSI.white}${req.originalUrl}${ANSI.reset} ` +
      `${statusCol}${ANSI.bold}${res.statusCode}${ANSI.reset} ` +
      `${ANSI.dim}${timeStr}${ANSI.reset}`
    );
  });

  next();
});

function capitalizeHeader(header) {
  return header
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join('-');
}

// ─── Serve Static Files ────────────────────────────────────────────────────
app.use('/public', express.static(path.join(__dirname, 'public')));

// ─── Pages ────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/logs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'logs.html'));
});

app.get('/custom', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'custom.html'));
});

app.get('/vulnerabilities', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'vulnerabilities.html'));
});

// ─── Auth: Current User API ────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  const sess = getSession(req);
  if (!sess) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, username: sess.username });
});

// ─── Demo API Endpoints ────────────────────────────────────────────────────
app.get('/api/user', (req, res) => {
  res.json({ success: true, method: 'GET', message: 'Fetched user data', data: { id: 1, name: 'John Doe', email: 'john@example.com' } });
});

// ─── Demo API Endpoints ────────────────────────────────────────────────────
app.get('/api/admin', (req, res) => {
  res.json({ success: true, method: 'GET', message: 'Admin Data Fetched Successfully', data: { id: 0, name: 'Admin Admin', email: 'admin@admin.com' } });
});

app.post('/api/user', (req, res) => {
  res.status(201).json({ success: true, method: 'POST', message: 'User created', data: { id: 2, ...req.body } });
});

app.put('/api/user', (req, res) => {
  res.json({ success: true, method: 'PUT', message: 'User replaced', data: { id: 1, ...req.body } });
});

app.patch('/api/user', (req, res) => {
  res.json({ success: true, method: 'PATCH', message: 'User updated', data: { id: 1, ...req.body } });
});

app.delete('/api/user', (req, res) => {
  res.json({ success: true, method: 'DELETE', message: 'User deleted', data: { id: 1 } });
});

// ─── Custom Endpoints Actual Routes ────────────────────────────────────────
app.all('/custom/:id', (req, res) => {
  const endpoint = `/custom/${req.params.id}`;
  const customData = getCustomEndpoint.get(endpoint);

  if (!customData) {
    return res.status(404).json({ error: 'Custom endpoint not found' });
  }

  res.set('Content-Type', customData.content_type);
  if (customData.custom_headers) {
    try {
      const headers = JSON.parse(customData.custom_headers);
      for (const [key, value] of Object.entries(headers)) {
        res.set(key, value);
      }
    } catch (e) {
      console.error('Failed to parse custom headers:', e);
    }
  }
  res.send(customData.response_body);
});

// ─── Admin APIs ────────────────────────────────────────────────────────────
app.get('/api/custom-endpoints', (req, res) => {
  try {
    const endpoints = getAllCustomEndpoints.all();
    res.json(endpoints);
  } catch (err) {
    console.error('Error fetching custom endpoints:', err.message);
    res.status(500).json({ error: 'Failed to fetch custom endpoints' });
  }
});

app.put('/api/custom-endpoints/:id', (req, res) => {
  try {
    const { content_type, response_body, custom_headers } = req.body;
    updateCustomEndpoint.run(content_type, response_body, custom_headers || '{}', req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating custom endpoint:', err.message);
    res.status(500).json({ error: 'Failed to update custom endpoint' });
  }
});

// ─── Logs API ──────────────────────────────────────────────────────────────
const PAGE_SIZE = 100;

app.get('/api/logs', (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page)  || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || PAGE_SIZE);
    const offset = (page - 1) * limit;

    const { total } = countLogs.get();
    const totalPages = Math.max(1, Math.ceil(total / limit));

    const rows = getLogsPage.all(limit, offset);

    // Normalize column names to camelCase for the frontend
    const logs = rows.map(row => ({
      id:              row.id,
      timestamp:       row.timestamp,
      method:          row.method,
      path:            row.path,
      protocol:        row.protocol,
      requestLine:     row.request_line,
      headers:         row.headers,
      body:            row.body,
      ip:              row.ip,
      status:          row.status,
      responseHeaders: row.response_headers,
      responseBody:    row.response_body,
    }));

    res.json({ logs, total, page, totalPages, limit });
  } catch (err) {
    console.error('Error reading logs:', err.message);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

app.delete('/api/logs', (req, res) => {
  try {
    clearAllLogs.run();
    res.json({ success: true, message: 'All logs cleared' });
  } catch (err) {
    console.error('Error clearing logs:', err.message);
    res.status(500).json({ error: 'Failed to clear logs' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// ─── VULNERABILITY ROUTES (adapted from testApp reference) ─────────────────
// ════════════════════════════════════════════════════════════════════════════

// ── 1. Reflected XSS ───────────────────────────────────────────────────────
app.get('/vulnerabilities/xss', (req, res) => {
  const input = req.query.input || '';
  // VULNERABLE: Reflects input directly without escaping
  res.send(`<!DOCTYPE html><html><head><title>XSS Demo</title><link rel="stylesheet" href="/public/style.css"></head><body>
    <nav class="navbar"><div class="nav-inner"><span class="brand-name">RequestLogger</span>
    <div class="nav-links">
      <a href="/" class="nav-link">Home</a>
      <a href="/vulnerabilities" class="nav-link active">Vulnerabilities</a>
      <a href="/logs" class="nav-link">View Logs</a>
    </div></div></nav>
    <main class="main-container"><h1>XSS Demo</h1><p>You said: ${input}</p>
    <a href="/vulnerabilities" style="color:var(--accent);">← Back to Vulnerabilities</a></main>
  </body></html>`);
});

// ── 2. Stored XSS (Guestbook) ──────────────────────────────────────────────
// Uses the existing logs.db via better-sqlite3
db.exec(`CREATE TABLE IF NOT EXISTS guestbook (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);
const insertGuestbook = db.prepare(`INSERT INTO guestbook(message) VALUES(?)`);
const getAllGuestbook  = db.prepare(`SELECT * FROM guestbook ORDER BY created_at DESC`);

app.get('/vulnerabilities/stored-xss', (req, res) => {
  const rows = getAllGuestbook.all();
  let messages = rows.map(r => `<div style="border:1px solid #e5e7eb;border-radius:8px;padding:12px;margin:8px 0">
      <small style="color:#6b7280">${r.created_at}</small><br>${r.message}</div>`).join('');
  res.send(`<!DOCTYPE html><html><head><title>Stored XSS</title><link rel="stylesheet" href="/public/style.css"></head><body>
    <nav class="navbar"><div class="nav-inner"><span class="brand-name">RequestLogger</span>
    <div class="nav-links"><a href="/" class="nav-link">Home</a>
      <a href="/vulnerabilities" class="nav-link active">Vulnerabilities</a>
      <a href="/logs" class="nav-link">View Logs</a></div></div></nav>
    <main class="main-container">
      <h1>Guestbook (Stored XSS)</h1>
      <form method="POST" action="/vulnerabilities/stored-xss" style="margin-bottom:20px">
        <textarea name="message" placeholder="Leave a message..." rows="3" style="width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:8px;font-family:inherit"></textarea><br>
        <button type="submit" style="margin-top:8px;padding:8px 20px;background:var(--accent);color:white;border:none;border-radius:8px;cursor:pointer">Sign Guestbook</button>
      </form>
      <h3>Messages:</h3>${messages || '<p style="color:#6b7280">No messages yet.</p>'}
      <br><a href="/vulnerabilities" style="color:var(--accent);">← Back to Vulnerabilities</a>
    </main></body></html>`);
});

app.post('/vulnerabilities/stored-xss', (req, res) => {
  const message = req.body.message;
  // VULNERABLE: Storing input directly without sanitization
  insertGuestbook.run(message);
  res.redirect('/vulnerabilities/stored-xss');
});

// ── 3. Open Redirect ────────────────────────────────────────────────────────
app.get('/vulnerabilities/redirect', (req, res) => {
  const url = req.query.url;
  // VULNERABLE: Redirects to arbitrary URL
  if (url) res.redirect(url);
  else res.send('Missing url parameter. Try ?url=https://example.com');
});

// ── 4. Cookie Injection / Reflection ───────────────────────────────────────
app.get('/vulnerabilities/cookie-reflect', (req, res) => {
  const param = req.query.param;
  if (param) {
    // VULNERABLE: Reflects parameter into cookie value
    res.cookie('vulnerable_cookie', param);
    res.json({ message: 'Cookie set', cookie: 'vulnerable_cookie=' + param });
  } else {
    res.send('Missing param. Try ?param=evil');
  }
});

// ── 5. CRLF Injection ──────────────────────────────────────────────────────
app.get('/vulnerabilities/crlf', (req, res) => {
  const input = req.query.input;
  if (input) {
    // VULNERABLE: Injecting input into a custom header
    res.setHeader('X-Custom-Header', input);
    res.json({ message: 'Header set', header: 'X-Custom-Header: ' + input });
  } else {
    res.send('Missing input. Try ?input=test%0d%0aInjected-Header: evil');
  }
});

// ── 6. OS Command Injection ─────────────────────────────────────────────────
app.get('/vulnerabilities/ping', (req, res) => {
  const ip = req.query.ip;
  if (ip) {
    // VULNERABLE: Concatenating input directly into exec
    exec(`ping -c 1 ${ip}`, (error, stdout, stderr) => {
      if (error) return res.send(`<pre>Error: ${error.message}</pre>`);
      res.send(`<pre>${stdout}</pre>`);
    });
  } else {
    res.send('Missing ip parameter. Try ?ip=127.0.0.1');
  }
});

// ── 7. Python Code Injection ────────────────────────────────────────────────
app.get('/vulnerabilities/pymath', (req, res) => {
  const code = req.query.code;
  if (code) {
    // VULNERABLE: Executing arbitrary Python code
    exec(`python3 -c "print(${code})"`, (error, stdout, stderr) => {
      if (error) return res.send(`<pre>Error: ${stderr || error.message}</pre>`);
      res.send(`<pre>Result: ${stdout}</pre>`);
    });
  } else {
    res.send('Missing code parameter. Try ?code=2%2B2');
  }
});

// ── 8. Insecure Deserialization ─────────────────────────────────────────────
app.get('/vulnerabilities/deserialize', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Insecure Deserialization</title><link rel="stylesheet" href="/public/style.css"></head><body>
    <nav class="navbar"><div class="nav-inner"><span class="brand-name">RequestLogger</span>
    <div class="nav-links"><a href="/" class="nav-link">Home</a>
      <a href="/vulnerabilities" class="nav-link active">Vulnerabilities</a>
      <a href="/logs" class="nav-link">View Logs</a></div></div></nav>
    <main class="main-container">
      <h1>Insecure Deserialization</h1>
      <p>Enter a JS payload to "deserialize" (execute):</p>
      <form method="POST" action="/vulnerabilities/deserialize">
        <textarea name="payload" rows="3" style="width:100%;padding:10px;border:1px solid #e5e7eb;border-radius:8px;font-family:'JetBrains Mono',monospace">console.log("Deserialized!")</textarea><br>
        <button type="submit" style="margin-top:8px;padding:8px 20px;background:var(--accent);color:white;border:none;border-radius:8px;cursor:pointer">Deserialize</button>
      </form>
      <br><a href="/vulnerabilities" style="color:var(--accent);">← Back to Vulnerabilities</a>
    </main></body></html>`);
});

app.post('/vulnerabilities/deserialize', express.urlencoded({ extended: true }), (req, res) => {
  const payload = req.body.payload;
  try {
    // VULNERABLE: Using eval() to simulate insecure deserialization
    const result = eval(payload); // eslint-disable-line no-eval
    res.send(`Object deserialized. Result: ${result}`);
  } catch (e) {
    res.send(`Deserialization error: ${e.message}`);
  }
});

// ── 9. Local File Inclusion (LFI) ───────────────────────────────────────────
app.get('/vulnerabilities/lfi', (req, res) => {
  const file = req.query.file;
  if (file) {
    // VULNERABLE: Reading arbitrary file path
    fs.readFile(file, 'utf8', (err, data) => {
      if (err) return res.send(`Error reading file: ${err.message}`);
      res.send(`<pre>${data}</pre>`);
    });
  } else {
    res.send('Missing file parameter. Try ?file=/etc/passwd');
  }
});

// ── 10. SSRF ────────────────────────────────────────────────────────────────
app.get('/vulnerabilities/ssrf', (req, res) => {
  const url = req.query.url;
  if (url) {
    // VULNERABLE: Fetching arbitrary URL
    exec(`curl -s --max-time 5 "${url}"`, (error, stdout) => {
      if (error) return res.send('Error fetching URL');
      res.send(`<pre>${stdout}</pre>`);
    });
  } else {
    res.send('Missing url parameter. Try ?url=http://localhost:3000');
  }
});

// ── 11. Angular CSTI ────────────────────────────────────────────────────────
app.get('/vulnerabilities/csti', (req, res) => {
  const name = req.query.name || 'World';
  res.send(`<!DOCTYPE html><html ng-app><head>
    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.9/angular.min.js"><\/script>
  </head><body>
    <h1>Hello ${name}</h1>
    <p>Try injecting <code>{{7*7}}</code> in the name parameter</p>
    <a href="/vulnerabilities">← Back to Vulnerabilities</a>
  </body></html>`);
});

// ── 12. ASP.NET Trace Simulation ────────────────────────────────────────────
app.get('/trace.axd', (req, res) => {
  res.type('text/plain');
  res.send(`Application Trace\n\nRequests:\n1. GET /login (200 OK)\n2. POST /login (302 Found)\n...`);
});

// ── 13. IDOR ────────────────────────────────────────────────────────────────
// Uses mock user data (no real users table in this app)
const mockUsers = [
  { id: 1, username: 'admin', password: 'admin123', isAdmin: 1 },
  { id: 2, username: 'alice', password: 'password1', isAdmin: 0 },
  { id: 3, username: 'bob',   password: 'letmein',   isAdmin: 0 },
];

app.get('/vulnerabilities/idor/user', (req, res) => {
  const id = parseInt(req.query.id);
  if (!id) return res.send('Missing id parameter. Try ?id=1');
  // VULNERABLE: No check if the requested ID matches the logged-in user
  const user = mockUsers.find(u => u.id === id);
  if (!user) return res.json({ error: 'User not found' });
  res.json({ id: user.id, username: user.username, password: user.password + ' (Sensitive Data Exposed!)', isAdmin: user.isAdmin });
});

// ── 14. Unprotected API ─────────────────────────────────────────────────────
app.get('/vulnerabilities/api/users', (req, res) => {
  // VULNERABLE: Exposing all user data without auth check
  res.json(mockUsers);
});

// ── 15. SQL Injection ───────────────────────────────────────────────────────
// Uses better-sqlite3 (synchronous) for simulation
db.exec(`CREATE TABLE IF NOT EXISTS vuln_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  isAdmin INTEGER DEFAULT 0
)`);
try {
  db.exec(`INSERT INTO vuln_users(username, password, isAdmin) VALUES('admin','admin123',1),('alice','pass1',0),('bob','letmein',0)`);
} catch (_) {} // Ignore duplicate seed errors

app.get('/vulnerabilities/sqli', (req, res) => {
  const search = req.query.search || '';
  // VULNERABLE: SQL Injection via direct concatenation
  let sql = `SELECT id, username, isAdmin FROM vuln_users WHERE 1=1`;
  if (search) sql += ` AND username LIKE '%${search}%'`;
  let rows, error;
  try { rows = db.prepare(sql).all(); }
  catch (e) { error = e.message; }
  res.json({ query: sql, results: rows, error: error || null });
});

// ── 16. Prototype Pollution ─────────────────────────────────────────────────
const merge = (target, source) => {
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
};

app.get('/vulnerabilities/pollution', (req, res) => {
  res.json({ description: 'POST a JSON body with __proto__ to pollute Object.prototype', currentAdminCheck: ({}).isAdmin });
});

app.post('/vulnerabilities/pollution', (req, res) => {
  let payload = req.body;
  let config = {};
  // VULNERABLE: Recursive merge without key validation
  merge(config, payload);
  res.json({ message: 'Config merged', adminCheck: config.isAdmin || ({}).isAdmin, config });
});

// ── 17. Insecure Cookies ────────────────────────────────────────────────────
app.get('/vulnerabilities/insecure-cookies', (req, res) => {
  // VULNERABLE: Setting cookies with missing security flags
  res.cookie('vuln_cookie', 'exploitable_value', { httpOnly: false, secure: false });
  res.json({
    message: 'Insecure cookie set',
    cookie: 'vuln_cookie=exploitable_value',
    issues: ['Missing HttpOnly', 'Missing Secure', 'Missing SameSite']
  });
});

// ── 18. CORS Vulnerabilities ────────────────────────────────────────────────
app.get('/vulnerabilities/cors', (req, res) => {
  res.json({ endpoints: [
    '/vulnerabilities/cors/wildcard',
    '/vulnerabilities/cors/subdomain',
    '/vulnerabilities/cors/reflection',
    '/vulnerabilities/cors/regex',
    '/vulnerabilities/cors/null'
  ]});
});
app.get('/vulnerabilities/cors/wildcard', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({ secret: 'Wildcard+Creds', user: 'admin' });
});
app.get('/vulnerabilities/cors/subdomain', (req, res) => {
  const origin = req.headers.origin;
  if (origin && origin.endsWith('example.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ secret: 'Subdomain Bypass', origin });
});
app.get('/vulnerabilities/cors/reflection', (req, res) => {
  const origin = req.headers.origin;
  if (origin) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Access-Control-Allow-Credentials', 'true'); }
  res.json({ secret: 'Reflection', origin });
});
app.get('/vulnerabilities/cors/regex', (req, res) => {
  const origin = req.headers.origin;
  if (origin && /example.com/.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.json({ secret: 'Regex Bypass', origin });
});
app.get('/vulnerabilities/cors/null', (req, res) => {
  const origin = req.headers.origin;
  if (origin === 'null') { res.setHeader('Access-Control-Allow-Origin', 'null'); res.setHeader('Access-Control-Allow-Credentials', 'true'); }
  res.json({ secret: 'Null Origin Trusted', origin });
});

// ── 19. XPath Injection (Simulation) ───────────────────────────────────────
app.get('/vulnerabilities/xpath', (req, res) => {
  const username = req.query.username || '';
  const query = `//user[name/text()='${username}']`;
  let result = 'No match found';
  if (username.includes("' or '1'='1") || username === 'admin') {
    result = { name: 'admin', secret: 'SuperSecretAdminData' };
  } else if (username === 'guest') {
    result = { name: 'guest', secret: 'GuestData' };
  }
  res.json({ query, result });
});

// ── 20. LDAP Injection (Simulation) ────────────────────────────────────────
app.get('/vulnerabilities/ldap', (req, res) => {
  const user = req.query.user || '';
  const filter = `(&(uid=${user})(objectClass=person))`;
  const users = ['alice', 'bob', 'admin'];
  let result;
  if (user.includes('*')) result = { match: users };
  else if (users.includes(user)) result = { match: user };
  else result = { match: null };
  res.json({ filter, result });
});

// ── 21. HTTP Header Injection ───────────────────────────────────────────────
app.get('/vulnerabilities/header-injection', (req, res) => {
  const customHeader = req.query.header_val;
  if (customHeader) {
    try {
      res.setHeader('X-User-Input', customHeader);
      res.json({ message: 'Header set', header: `X-User-Input: ${customHeader}` });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  } else {
    res.send('Missing header_val parameter. Try ?header_val=test');
  }
});

// ── 22. Mass Assignment ─────────────────────────────────────────────────────
app.get('/vulnerabilities/mass-assignment', (req, res) => {
  res.json({
    description: 'POST a JSON body — the backend blindly copies all fields to the user object.',
    hint: 'Try sending "isAdmin": true or "role": "admin" in the request body.',
    currentUser: { id: 101, username: 'guest', email: 'guest@example.com', role: 'guest', isAdmin: false }
  });
});

app.post('/vulnerabilities/mass-assignment', (req, res) => {
  let user = { id: 101, username: 'guest', email: 'guest@example.com', role: 'guest', isAdmin: false };
  const input = req.body;
  // VULNERABLE: Mass assignment
  Object.assign(user, input);
  res.json({ message: 'Profile Updated', updatedUser: user });
});

// ── 23. GraphQL Introspection ───────────────────────────────────────────────
app.get('/vulnerabilities/graphql', (req, res) => {
  res.json({ description: 'POST a GraphQL query to /graphql. Try {__schema{types{name}}} to introspect.' });
});

app.post('/graphql', (req, res) => {
  const query = (req.body && req.body.query) || '';
  // VULNERABLE: Introspection enabled
  if (query.includes('__schema') || query.includes('__type')) {
    return res.json({ data: { __schema: { types: [
      { name: 'User', fields: [{ name: 'id' }, { name: 'username' }, { name: 'password' }, { name: 'isAdmin' }] },
      { name: 'Post', fields: [{ name: 'id' }, { name: 'title' }, { name: 'content' }] }
    ]}}});
  }
  if (query.includes('getUser')) {
    return res.json({ data: { getUser: { name: 'Alice', id: '1' } } });
  }
  res.json({ error: 'Unknown query' });
});

// ── 24. Information Disclosure ──────────────────────────────────────────────
app.get('/internal-ip', (req, res) => {
  // VULNERABLE: Exposing internal network details
  res.json({ internal_ip: '10.0.0.15', subnet: '10.0.0.0/24', gateway: '10.0.0.1' });
});

app.get('/version', (req, res) => {
  // VULNERABLE: Software version disclosure
  res.setHeader('X-Powered-By', 'Express/4.17.1');
  res.json({ app: 'VulnApp 1.0.0-dev', runtime: `Node.js ${process.version}`, framework: 'Express v4.17.1', database: 'SQLite' });
});

app.get('/env', (req, res) => {
  // VULNERABLE: Dumping process environment
  res.json(process.env);
});

app.get('/config.js.bak', (req, res) => {
  // VULNERABLE: Serving backup file with hardcoded credentials
  res.type('text/javascript');
  res.send(`// BACKUP DATE: 2025-01-01\nconst config = {\n  db_host: "localhost",\n  db_user: "admin",\n  db_pass: "SuperSecretPassword123!" // HARDCODED SECRET\n};\nmodule.exports = config;`);
});

app.get('/.git/HEAD', (req, res) => {
  res.type('text/plain');
  res.send('ref: refs/heads/main');
});

app.get('/.env', (req, res) => {
  // VULNERABLE: Dotfile exposure
  res.type('text/plain');
  res.send(`PORT=3000\nDB_PASSWORD=production_secret_key_change_me\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`);
});

app.get('/swagger.json', (req, res) => {
  res.json({
    swagger: '2.0',
    info: { title: 'Vulnerable API', version: '1.0.0' },
    paths: { '/login': { post: { summary: 'Login' } }, '/admin/users': { get: { summary: 'List Users (Admin Only)' } } }
  });
});

app.get('/vulnerabilities/directory-listing', (req, res) => {
  // VULNERABLE: Simulating open directory listing
  res.type('text/html');
  res.send(`<!DOCTYPE html><html><head><title>Index of /uploads/</title></head><body>
    <h1>Index of /uploads/</h1><hr>
    <table><tr><th>Name</th><th>Last modified</th><th>Size</th></tr>
    <tr><td><a href="#">Parent Directory/</a></td><td>-</td><td>-</td></tr>
    <tr><td><a href="/config.js.bak">config.js.bak</a></td><td>2025-01-01 12:00</td><td>1024</td></tr>
    <tr><td><a href="/.env">.env</a></td><td>2025-02-15 08:30</td><td>512</td></tr>
    <tr><td><a href="#">user_exports.csv</a></td><td>2025-03-10 14:22</td><td>5MB</td></tr>
    </table><hr>
    <address>Apache/2.4.1 (Unix) Server at localhost Port 3000</address>
  </body></html>`);
});

// ─── Graceful Shutdown ─────────────────────────────────────────────────────
process.on('SIGINT', () => {
  db.close();
  console.log('\n📦 SQLite connection closed. Goodbye!\n');
  process.exit(0);
});

// ─── Start Server ──────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Request Logger running at http://localhost:${PORT}`);
  console.log(`   Home  → http://localhost:${PORT}/`);
  console.log(`   Logs  → http://localhost:${PORT}/logs`);
  console.log(`   DB    → ${path.join(__dirname, 'logs.db')}\n`);
});
