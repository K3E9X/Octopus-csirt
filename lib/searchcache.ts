// Keeping an answer for a day, so asking twice costs once.
//
// A DELIBERATE REVERSAL, AND IT SHOULD BE SAID OUT LOUD. Everything else here refuses
// to persist breach data: the case tables hold what an analyst pinned and nothing else,
// precisely so the deployment is not a second copy of other people's dumps. This table
// IS that copy, for a day.
//
// It exists because the alternative is worse in practice. Two people on one incident
// search the same address, or the same person searches it again after lunch, and the
// deployment pays twice for an answer that cannot have changed. Breach data is historic
// by definition; nothing new appeared in the index between eleven and two. Paying again
// buys nothing, and the cost lands on the budget that decides how much investigating
// gets done.
//
// So it is bounded in every direction that matters:
//
//   It expires. OCTOPUS_CACHE_HOURS, twenty-four by default, zero turns it off.
//   It is deletable, one answer at a time or all of it.
//   It never suppresses the audit trail. A cache hit is still a search somebody ran,
//   and "who looked at whom" is the one record that must not develop holes. Reading a
//   cached answer writes the same log line as paying for a fresh one.
//   It is keyed on the exact question, so a different depth is a different answer.

import { sql, dbEnabled } from "./db";
import { bootstrap } from "./schema";
import { createHash } from "node:crypto";
import type { LeakDatabase } from "./leakosint";

export const cacheEnabled = dbEnabled;

/** Hours an answer is kept. Zero, blank or nonsense means do not cache at all. */
export function cacheHours(): number {
  const raw = String(process.env.OCTOPUS_CACHE_HOURS ?? "24").trim();
  if (!raw) return 0;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(720, n);
}

const build = bootstrap(async () => {
  const q = sql();
  if (!q) return;
  await q`CREATE TABLE IF NOT EXISTS octopus_search_cache (
    key        text PRIMARY KEY,
    selector   text NOT NULL,
    query      text NOT NULL,
    lim        integer NOT NULL,
    payload    text NOT NULL,
    rows_count integer NOT NULL,
    at         bigint NOT NULL,
    expires_at bigint NOT NULL,
    by_email   text NOT NULL
  )`;
  await q`CREATE INDEX IF NOT EXISTS octopus_cache_exp ON octopus_search_cache (expires_at)`;
});

/**
 * The key: the exact question, not the words somebody typed.
 *
 * The query actually sent, the depth, the region and whether it was quoted. Two
 * operators typing one address differently produce the same canonical query and so the
 * same key, which is the whole saving. A deeper sweep is a different question and is
 * paid for.
 */
export function cacheKey(query: string, limit: number, region: string, exact: boolean): string {
  return createHash("sha256").update(query + " " + limit + " " + region + " " + (exact ? 1 : 0)).digest("hex").slice(0, 32);
}

export interface Cached {
  databases: LeakDatabase[];
  rowCount: number;
  at: number;
  expiresAt: number;
  by: string;
}

export async function readCache(key: string): Promise<Cached | null> {
  if (!cacheEnabled || cacheHours() === 0) return null;
  const q = sql();
  if (!q) return null;
  await build();
  const rows = await q`SELECT * FROM octopus_search_cache WHERE key = ${key} AND expires_at > ${Date.now()} LIMIT 1`;
  const r = (rows as any[])[0];
  if (!r) return null;
  try {
    return {
      databases: JSON.parse(r.payload),
      rowCount: Number(r.rows_count),
      at: Number(r.at),
      expiresAt: Number(r.expires_at),
      by: r.by_email,
    };
  } catch {
    // a row we cannot read is a row that helps nobody
    await q`DELETE FROM octopus_search_cache WHERE key = ${key}`;
    return null;
  }
}

export async function writeCache(
  key: string, selector: string, query: string, limit: number,
  databases: LeakDatabase[], rowCount: number, by: string,
): Promise<void> {
  const hours = cacheHours();
  if (!cacheEnabled || hours === 0) return;
  const q = sql();
  if (!q) return;
  await build();
  const now = Date.now();
  const payload = JSON.stringify(databases);
  // One answer big enough to matter is not worth keeping: it would be read back and
  // parsed on every hit, and the saving is in credits rather than in bytes.
  if (payload.length > 4000000) return;
  await q`INSERT INTO octopus_search_cache (key, selector, query, lim, payload, rows_count, at, expires_at, by_email)
          VALUES (${key}, ${selector.slice(0, 300)}, ${query.slice(0, 300)}, ${limit}, ${payload}, ${rowCount}, ${now}, ${now + hours * 3600000}, ${by})
          ON CONFLICT (key) DO UPDATE SET
            payload = EXCLUDED.payload, rows_count = EXCLUDED.rows_count,
            at = EXCLUDED.at, expires_at = EXCLUDED.expires_at, by_email = EXCLUDED.by_email`;
  // opportunistic, and cheap: an expired row is dead weight and nobody schedules a job
  await q`DELETE FROM octopus_search_cache WHERE expires_at < ${now}`;
}

export interface CacheRow { key: string; selector: string; lim: number; rows: number; at: number; expiresAt: number; by: string }

export async function listCache(limit = 100): Promise<CacheRow[]> {
  if (!cacheEnabled) return [];
  const q = sql();
  if (!q) return [];
  await build();
  const rows = await q`SELECT key, selector, lim, rows_count, at, expires_at, by_email
                       FROM octopus_search_cache WHERE expires_at > ${Date.now()}
                       ORDER BY at DESC LIMIT ${limit}`;
  return (rows as any[]).map((r) => ({
    key: r.key, selector: r.selector, lim: Number(r.lim), rows: Number(r.rows_count),
    at: Number(r.at), expiresAt: Number(r.expires_at), by: r.by_email,
  }));
}

/** Drop one answer, or everything. Returns how many rows went. */
export async function dropCache(key?: string): Promise<number> {
  if (!cacheEnabled) return 0;
  const q = sql();
  if (!q) return 0;
  await build();
  const rows = key
    ? await q`DELETE FROM octopus_search_cache WHERE key = ${key} RETURNING key`
    : await q`DELETE FROM octopus_search_cache RETURNING key`;
  return (rows as any[]).length;
}

/** Everything kept about one selector, however it was spelled or how deep it went. */
export async function dropCacheFor(selector: string): Promise<number> {
  if (!cacheEnabled) return 0;
  const q = sql();
  if (!q) return 0;
  await build();
  const rows = await q`DELETE FROM octopus_search_cache WHERE selector = ${selector} RETURNING key`;
  return (rows as any[]).length;
}
