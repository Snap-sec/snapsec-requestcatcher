const express = require('express');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const Database = require('better-sqlite3');

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

const getAllLogs = db.prepare(`
  SELECT * FROM request_logs ORDER BY timestamp DESC
`);

const clearAllLogs = db.prepare(`
  DELETE FROM request_logs
`);

// ─── Middleware ────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  const skip = ['/', '/logs', '/favicon.ico'].some(p => req.path === p) ||
               req.path.startsWith('/public') ||
               req.path.startsWith('/api/logs');

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

// ─── Demo API Endpoints ────────────────────────────────────────────────────
app.get('/api/user', (req, res) => {
  res.json({ success: true, method: 'GET', message: 'Fetched user data', data: { id: 1, name: 'John Doe', email: 'john@example.com' } });
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

// ─── Logs API ──────────────────────────────────────────────────────────────
app.get('/api/logs', (req, res) => {
  try {
    const logs = getAllLogs.all();
    // Normalize column names to camelCase for the frontend
    const normalized = logs.map(row => ({
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
    res.json(normalized);
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
