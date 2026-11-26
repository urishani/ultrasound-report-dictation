// Postgres pool + schema bootstrap. The database runs as a compose service;
// startup retries until it accepts connections.

import pg from 'pg';

const { Pool } = pg;

// Connection settings come from DATABASE_URL or, when absent, the standard
// PG* variables the compose stack sets (PGHOST/PGUSER/PGPASSWORD/PGDATABASE).
export const pool = new Pool({
  ...(process.env.DATABASE_URL ? { connectionString: process.env.DATABASE_URL } : {}),
  max: 10
});

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL UNIQUE,
  display_name text NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
`;

export async function initDb() {
  for (let attempt = 1; attempt <= 30; attempt++) {
    try {
      await pool.query('SELECT 1');
      await pool.query(SCHEMA);
      return;
    } catch (err) {
      if (attempt === 30) throw err;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

export async function countUsers() {
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
  return rows[0].n;
}

export function publicUser(row) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name,
    role: row.role,
    isActive: row.is_active,
    createdAt: row.created_at
  };
}
