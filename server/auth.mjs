// Password hashing, session cookies and request guards.

import crypto from 'node:crypto';
import { pool } from './db.mjs';
import { HttpError } from './http.mjs';

const COOKIE_NAME = 'us_session';
const SESSION_DAYS = 30;

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password, stored) {
  const [scheme, saltHex, hashHex] = String(stored || '').split('$');
  if (scheme !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  await pool.query(
    `INSERT INTO sessions (token_hash, user_id, expires_at)
     VALUES ($1, $2, now() + ($3 || ' days')::interval)`,
    [tokenHash(token), userId, String(SESSION_DAYS)]
  );
  return token;
}

export async function destroySession(req) {
  const token = readCookie(req, COOKIE_NAME);
  if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash(token)]);
}

export async function destroyUserSessions(userId) {
  await pool.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
}

function readCookie(req, name) {
  const header = String(req.headers.cookie || '');
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      return decodeURIComponent(part.slice(eq + 1).trim());
    }
  }
  return null;
}

function isHttps(req) {
  const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  return proto === 'https';
}

/**
 * Cookie attributes. In the Base44 preview the app runs inside a cross-site
 * iframe, where a SameSite=Lax cookie is never sent, so the preview
 * (BASE44_PREVIEW_MODE === '1') uses SameSite=None; Secure. Unset, a normal
 * same-origin deployment keeps SameSite=Lax.
 */
function cookieAttrs(req) {
  if (process.env.BASE44_PREVIEW_MODE === '1') return 'Path=/; HttpOnly; SameSite=None; Secure';
  return `Path=/; HttpOnly; SameSite=Lax${isHttps(req) ? '; Secure' : ''}`;
}

export function sessionCookie(req, token) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; ${cookieAttrs(req)}; Max-Age=${SESSION_DAYS * 24 * 60 * 60}`;
}

export function clearSessionCookie(req) {
  return `${COOKIE_NAME}=; ${cookieAttrs(req)}; Max-Age=0`;
}

/** The signed-in user for this request, or null. */
export async function currentUser(req) {
  const token = readCookie(req, COOKIE_NAME);
  if (!token) return null;
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.created_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [tokenHash(token)]
  );
  const user = rows[0];
  if (!user || !user.is_active) return null;
  return user;
}

export async function requireUser(req) {
  const user = await currentUser(req);
  if (!user) throw new HttpError(401, 'נדרשת התחברות');
  return user;
}

export async function requireAdmin(req) {
  const user = await requireUser(req);
  if (user.role !== 'admin') throw new HttpError(403, 'נדרשות הרשאות מנהל');
  return user;
}

export async function activeAdminCount() {
  const { rows } = await pool.query(
    "SELECT count(*)::int AS n FROM users WHERE role = 'admin' AND is_active"
  );
  return rows[0].n;
}
