// Where an account is signed in from, and cutting one of them.
//
// Sessions here are signed cookies, which is what lets any replica accept one without
// shared state. The price is that a cookie cannot be taken back, and the epoch on the
// account only answers the blunt version of the question: cut EVERYTHING. An
// administrator looking at an account after an incident is asking a sharper one, which
// is where it is open from and whether one of those places is a surprise.
//
// So the cookie also carries a session id, and that id has a row. The row is the thing
// an administrator can delete. Deleting it does not invalidate the signature, it
// removes the session from the set this deployment will accept, which is the same
// outcome and is the only one available without shared secrets per session.
//
// WHAT IS KEPT, AND WHY IT IS NOT MORE. The address a session was last seen from and
// the browser string it sent, because an account open from somewhere nobody recognises
// is the finding. Not every request, not a trail of pages: that would be a second audit
// log, of the people using the tool rather than the people being searched, and nobody
// asked for one.

import { sql, dbEnabled } from "./db";
import { bootstrap } from "./schema";

export const sessionsTracked = dbEnabled;

const build = bootstrap(async () => {
  const q = sql();
  if (!q) return;
  await q`CREATE TABLE IF NOT EXISTS octopus_sessions (
    sid        text PRIMARY KEY,
    user_id    text NOT NULL,
    created_at bigint NOT NULL,
    last_seen  bigint NOT NULL,
    expires_at bigint NOT NULL,
    ip         text,
    agent      text
  )`;
  await q`CREATE INDEX IF NOT EXISTS octopus_sessions_user ON octopus_sessions (user_id)`;
});

export interface SessionRow {
  sid: string; userId: string; createdAt: number; lastSeen: number; expiresAt: number;
  ip?: string; agent?: string;
}

/** Called once when a cookie is issued. */
export async function openSession(sid: string, userId: string, expiresAt: number, ip?: string, agent?: string): Promise<void> {
  if (!sessionsTracked) return;
  const q = sql();
  if (!q) return;
  await build();
  const now = Date.now();
  await q`INSERT INTO octopus_sessions (sid, user_id, created_at, last_seen, expires_at, ip, agent)
          VALUES (${sid}, ${userId}, ${now}, ${now}, ${expiresAt}, ${ip || null}, ${(agent || "").slice(0, 300) || null})
          ON CONFLICT (sid) DO UPDATE SET last_seen = EXCLUDED.last_seen`;
  // opportunistic, because nobody schedules a job and an expired row helps no one
  await q`DELETE FROM octopus_sessions WHERE expires_at < ${now}`;
}

/**
 * Is this session still one we accept, and note that it was used.
 *
 * Returns false when the row is gone, which is how a single session is cut. The write
 * is throttled to five minutes: "last seen" to the minute is not worth a database write
 * on every request, and a tool that writes on every read is a tool that falls over
 * under the one condition you want it working.
 */
export async function touchSession(sid: string, ip?: string, agent?: string): Promise<boolean> {
  if (!sessionsTracked) return true;
  const q = sql();
  if (!q) return true;
  await build();
  const rows = await q`SELECT last_seen FROM octopus_sessions WHERE sid = ${sid} AND expires_at > ${Date.now()} LIMIT 1`;
  const r = (rows as any[])[0];
  if (!r) return false;
  const now = Date.now();
  if (now - Number(r.last_seen) > 300000) {
    await q`UPDATE octopus_sessions SET last_seen = ${now}, ip = COALESCE(${ip || null}, ip), agent = COALESCE(${(agent || "").slice(0, 300) || null}, agent) WHERE sid = ${sid}`;
  }
  return true;
}

export async function listSessions(userId?: string): Promise<SessionRow[]> {
  if (!sessionsTracked) return [];
  const q = sql();
  if (!q) return [];
  await build();
  const now = Date.now();
  const rows = userId
    ? await q`SELECT * FROM octopus_sessions WHERE user_id = ${userId} AND expires_at > ${now} ORDER BY last_seen DESC LIMIT 100`
    : await q`SELECT * FROM octopus_sessions WHERE expires_at > ${now} ORDER BY last_seen DESC LIMIT 200`;
  return (rows as any[]).map((r) => ({
    sid: r.sid, userId: r.user_id, createdAt: Number(r.created_at), lastSeen: Number(r.last_seen),
    expiresAt: Number(r.expires_at), ip: r.ip || undefined, agent: r.agent || undefined,
  }));
}

/** Cut one session. The others stay open, which is the whole point of it being separate. */
export async function killSession(sid: string): Promise<boolean> {
  if (!sessionsTracked) return false;
  const q = sql();
  if (!q) return false;
  await build();
  const rows = await q`DELETE FROM octopus_sessions WHERE sid = ${sid} RETURNING sid`;
  return (rows as any[]).length > 0;
}

/** Cut all of an account's sessions, alongside the epoch bump that makes it stick. */
export async function killAllSessions(userId: string): Promise<number> {
  if (!sessionsTracked) return 0;
  const q = sql();
  if (!q) return 0;
  await build();
  const rows = await q`DELETE FROM octopus_sessions WHERE user_id = ${userId} RETURNING sid`;
  return (rows as any[]).length;
}
