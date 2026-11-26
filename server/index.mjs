// HTTP server: serves the static app from the source tree and the small
// JSON API used for accounts (login, sessions, admin user management).

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, resolve, sep } from 'node:path';
import { countUsers, initDb, pool, publicUser } from './db.mjs';
import { HttpError, readJson, sendJson, str } from './http.mjs';
import {
  activeAdminCount,
  clearSessionCookie,
  createSession,
  currentUser,
  destroySession,
  destroyUserSessions,
  hashPassword,
  requireAdmin,
  sessionCookie,
  verifyPassword
} from './auth.mjs';

const ROOT = resolve(process.env.BASE44_WEB_ROOT || process.cwd());
const PORT = Number(process.env.PORT || 3000);
const INDEX = resolve(ROOT, 'index.html');

const TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.webmanifest', 'application/manifest+json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.jpg', 'image/jpeg'],
  ['.jpeg', 'image/jpeg'],
  ['.gif', 'image/gif'],
  ['.ico', 'image/x-icon'],
  ['.woff2', 'font/woff2'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.md', 'text/markdown; charset=utf-8']
]);

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,39}$/;

function send(res, status, headers, body) {
  res.writeHead(status, { 'Cache-Control': 'no-store, must-revalidate', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(body);
}

function redirect(res, location) {
  send(res, 302, { Location: location, 'Content-Type': 'text/plain; charset=utf-8' }, 'Redirecting');
}

function validateUsername(value) {
  const username = String(value ?? '').trim().toLowerCase();
  if (!USERNAME_RE.test(username)) {
    throw new HttpError(400, 'שם משתמש: 3–40 תווים, אותיות באנגלית קטנות, ספרות, נקודה, מקף או קו תחתון');
  }
  return username;
}

function validatePassword(value) {
  const password = String(value ?? '');
  if (password.length < 8) throw new HttpError(400, 'הסיסמה חייבת להכיל לפחות 8 תווים');
  if (password.length > 200) throw new HttpError(400, 'הסיסמה ארוכה מדי');
  return password;
}

// --- login throttling (in-memory, per username + address) -------------------
const attempts = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 10;

function throttleKey(req, username) {
  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  return `${username}|${ip}`;
}
function assertNotThrottled(key) {
  const entry = attempts.get(key);
  if (!entry) return;
  if (Date.now() - entry.first > WINDOW_MS) { attempts.delete(key); return; }
  if (entry.count >= MAX_ATTEMPTS) throw new HttpError(429, 'יותר מדי ניסיונות התחברות. נסו שוב בעוד רבע שעה.');
}
function noteFailure(key) {
  const entry = attempts.get(key);
  if (!entry || Date.now() - entry.first > WINDOW_MS) attempts.set(key, { first: Date.now(), count: 1 });
  else entry.count++;
}

// --- API --------------------------------------------------------------------
async function handleApi(req, res, pathname) {
  const method = req.method;

  if (pathname === '/api/health' && method === 'GET') {
    await pool.query('SELECT 1');
    sendJson(res, 200, { ok: true });
    return;
  }

  if (pathname === '/api/setup' && method === 'GET') {
    sendJson(res, 200, { needsBootstrap: (await countUsers()) === 0 });
    return;
  }

  if (pathname === '/api/bootstrap' && method === 'POST') {
    const body = await readJson(req);
    if ((await countUsers()) > 0) throw new HttpError(409, 'כבר קיים משתמש במערכת — יש להתחבר');
    const displayName = str(body.displayName, { name: 'שם מלא', max: 80 });
    const username = validateUsername(body.username);
    const password = validatePassword(body.password);
    const { rows } = await pool.query(
      `INSERT INTO users (username, display_name, password_hash, role)
       VALUES ($1, $2, $3, 'admin')
       RETURNING id, username, display_name, role, is_active, created_at`,
      [username, displayName, hashPassword(password)]
    );
    const token = await createSession(rows[0].id);
    sendJson(res, 201, { user: publicUser(rows[0]) }, { 'Set-Cookie': sessionCookie(req, token) });
    return;
  }

  if (pathname === '/api/login' && method === 'POST') {
    const body = await readJson(req);
    const username = String(body.username ?? '').trim().toLowerCase();
    const password = String(body.password ?? '');
    const key = throttleKey(req, username);
    assertNotThrottled(key);

    const { rows } = await pool.query(
      `SELECT id, username, display_name, password_hash, role, is_active, created_at
         FROM users WHERE username = $1`,
      [username]
    );
    const user = rows[0];
    if (!user || !verifyPassword(password, user.password_hash)) {
      noteFailure(key);
      throw new HttpError(401, 'שם משתמש או סיסמה שגויים');
    }
    if (!user.is_active) throw new HttpError(403, 'המשתמש מושבת — פנו למנהל המערכת');

    attempts.delete(key);
    await pool.query('DELETE FROM sessions WHERE expires_at < now()');
    const token = await createSession(user.id);
    sendJson(res, 200, { user: publicUser(user) }, { 'Set-Cookie': sessionCookie(req, token) });
    return;
  }

  if (pathname === '/api/logout' && method === 'POST') {
    await destroySession(req);
    sendJson(res, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie(req) });
    return;
  }

  if (pathname === '/api/session' && method === 'GET') {
    const user = await currentUser(req);
    if (!user) throw new HttpError(401, 'נדרשת התחברות');
    sendJson(res, 200, { user: publicUser(user) });
    return;
  }

  // --- admin: user management ----------------------------------------------
  if (pathname === '/api/users' && method === 'GET') {
    await requireAdmin(req);
    const { rows } = await pool.query(
      `SELECT id, username, display_name, role, is_active, created_at
         FROM users ORDER BY created_at`
    );
    sendJson(res, 200, { users: rows.map(publicUser) });
    return;
  }

  if (pathname === '/api/users' && method === 'POST') {
    await requireAdmin(req);
    const body = await readJson(req);
    const username = validateUsername(body.username);
    const displayName = str(body.displayName, { name: 'שם מלא', max: 80 });
    const password = validatePassword(body.password);
    const role = body.role === 'admin' ? 'admin' : 'user';
    const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existing.rowCount) throw new HttpError(409, 'שם המשתמש כבר קיים');
    const { rows } = await pool.query(
      `INSERT INTO users (username, display_name, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, display_name, role, is_active, created_at`,
      [username, displayName, hashPassword(password), role]
    );
    sendJson(res, 201, { user: publicUser(rows[0]) });
    return;
  }

  const userIdMatch = pathname.match(/^\/api\/users\/([0-9a-f-]{36})$/);
  if (userIdMatch && (method === 'PATCH' || method === 'DELETE')) {
    const admin = await requireAdmin(req);
    const targetId = userIdMatch[1];
    const { rows: targetRows } = await pool.query(
      'SELECT id, role, is_active FROM users WHERE id = $1',
      [targetId]
    );
    const target = targetRows[0];
    if (!target) throw new HttpError(404, 'המשתמש לא נמצא');
    const isSelf = target.id === admin.id;

    if (method === 'DELETE') {
      if (isSelf) throw new HttpError(400, 'אי אפשר למחוק את החשבון שאיתו אתם מחוברים');
      if (target.role === 'admin' && target.is_active && (await activeAdminCount()) <= 1) {
        throw new HttpError(400, 'חייב להישאר לפחות מנהל פעיל אחד');
      }
      await pool.query('DELETE FROM users WHERE id = $1', [targetId]);
      sendJson(res, 200, { ok: true });
      return;
    }

    const body = await readJson(req);
    const fields = [];
    const values = [];
    const nextRole = body.role === undefined ? target.role : (body.role === 'admin' ? 'admin' : 'user');
    const nextActive = body.isActive === undefined ? target.is_active : Boolean(body.isActive);

    if (isSelf && nextRole !== 'admin') throw new HttpError(400, 'אי אפשר להסיר מעצמכם הרשאות מנהל');
    if (isSelf && !nextActive) throw new HttpError(400, 'אי אפשר להשבית את החשבון שאיתו אתם מחוברים');
    const losesAdmin = target.role === 'admin' && target.is_active && (nextRole !== 'admin' || !nextActive);
    if (losesAdmin && (await activeAdminCount()) <= 1) {
      throw new HttpError(400, 'חייב להישאר לפחות מנהל פעיל אחד');
    }

    if (body.displayName !== undefined) {
      values.push(str(body.displayName, { name: 'שם מלא', max: 80 }));
      fields.push(`display_name = $${values.length}`);
    }
    if (body.role !== undefined) {
      values.push(nextRole);
      fields.push(`role = $${values.length}`);
    }
    if (body.isActive !== undefined) {
      values.push(nextActive);
      fields.push(`is_active = $${values.length}`);
    }
    if (body.password !== undefined && body.password !== '') {
      values.push(hashPassword(validatePassword(body.password)));
      fields.push(`password_hash = $${values.length}`);
    }
    if (!fields.length) throw new HttpError(400, 'לא נשלח שדה לעדכון');

    values.push(targetId);
    const { rows } = await pool.query(
      `UPDATE users SET ${fields.join(', ')} WHERE id = $${values.length}
       RETURNING id, username, display_name, role, is_active, created_at`,
      values
    );
    if (!nextActive || body.password) await destroyUserSessions(targetId);
    sendJson(res, 200, { user: publicUser(rows[0]) });
    return;
  }

  throw new HttpError(404, 'הנתיב לא נמצא');
}

// --- static files -----------------------------------------------------------
async function serveStatic(req, res, pathname) {
  if (pathname === '/' || pathname === '/index.html') {
    if (!(await currentUser(req))) return redirect(res, '/login.html');
  }
  if (pathname === '/admin.html' || pathname === '/admin') {
    const user = await currentUser(req);
    if (!user) return redirect(res, '/login.html');
    if (user.role !== 'admin') return redirect(res, '/');
  }
  if (pathname === '/login.html' || pathname === '/login') {
    if (await currentUser(req)) return redirect(res, '/');
  }
  if (pathname.startsWith('/server/') || pathname.split('/').some((part) => part.startsWith('.'))) {
    return send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not found');
  }

  let file = resolve(ROOT, '.' + (pathname.endsWith('/') ? pathname + 'index.html' : pathname));
  if (file !== ROOT && !file.startsWith(ROOT + sep)) {
    return send(res, 403, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Forbidden');
  }

  let body;
  try {
    body = await readFile(file);
  } catch {
    if (extname(pathname)) return send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not found');
    file = INDEX;
    try {
      body = await readFile(file);
    } catch {
      return send(res, 404, { 'Content-Type': 'text/plain; charset=utf-8' }, 'Not found');
    }
  }

  send(res, 200, {
    'Content-Type': TYPES.get(extname(file).toLowerCase()) || 'application/octet-stream',
    'Content-Length': body.length
  }, req.method === 'HEAD' ? undefined : body);
}

const server = createServer(async (req, res) => {
  const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  try {
    if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'POST' && req.method !== 'PATCH' && req.method !== 'DELETE') {
      send(res, 405, { 'Content-Type': 'text/plain; charset=utf-8', Allow: 'GET, HEAD, POST, PATCH, DELETE' }, 'Method Not Allowed');
      return;
    }
    if (pathname.startsWith('/api/')) {
      await handleApi(req, res, pathname);
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      send(res, 405, { 'Content-Type': 'text/plain; charset=utf-8', Allow: 'GET, HEAD' }, 'Method Not Allowed');
      return;
    }
    await serveStatic(req, res, pathname);
  } catch (err) {
    if (err instanceof HttpError) {
      sendJson(res, err.status, { error: err.message });
      return;
    }
    console.error('request failed', err);
    sendJson(res, 500, { error: 'שגיאת שרת' });
  }
});

initDb()
  .then(() => {
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`[base44] serving ${ROOT} on http://0.0.0.0:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('[base44] database init failed', err);
    process.exit(1);
  });

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => server.close(() => pool.end().finally(() => process.exit(0))));
}
