// Small helpers shared by the API routes: JSON responses and typed errors.

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function sendJson(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers
  });
  res.end(body);
}

/**
 * Read a JSON body. Mutating requests must be application/json, which a
 * cross-site HTML form cannot send — a simple CSRF guard on top of SameSite.
 */
export async function readJson(req) {
  const type = String(req.headers['content-type'] || '');
  if (!/^application\/json\b/i.test(type)) throw new HttpError(415, 'נדרש Content-Type: application/json');
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 1_000_000) throw new HttpError(413, 'הבקשה גדולה מדי');
  }
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, 'גוף הבקשה אינו JSON תקין');
  }
}

export function str(value, { name, min = 1, max = 200 } = {}) {
  const text = String(value ?? '').trim();
  if (text.length < min) throw new HttpError(400, `${name} חייב להכיל לפחות ${min} תווים`);
  if (text.length > max) throw new HttpError(400, `${name} ארוך מדי`);
  return text;
}
