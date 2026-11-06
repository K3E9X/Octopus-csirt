// Where a case lives between sessions.
//
// Three tables and no cache of anything the index returned. A case holds the selectors
// a hunter chose to look at and the facts they decided were worth keeping, each still
// naming the dump it came from. That boundary is the whole reason this file is short:
// the moment it started caching reports it would become a second copy of other
// people's breach data, held indefinitely, on infrastructure whose legal basis for
// holding it is the search that was already paid for and already logged.
//
// EVERY ROW CARRIES WHO PUT IT THERE AND WHEN. A case file that cannot say which
// analyst pinned which fact is not evidence of anything, and the one question asked
// after an incident is always "who concluded that, and from what".

import { sql, dbEnabled } from "./db";
import { bootstrap } from "./schema";
import type { CaseFile, CaseEntity, CaseFact, EntityKind } from "./casework";

export const casesEnabled = dbEnabled;

const build = bootstrap(async () => {
  const q = sql();
  if (!q) return;
  await q`CREATE TABLE IF NOT EXISTS octopus_cases (
    id         text PRIMARY KEY,
    ref        text NOT NULL,
    title      text NOT NULL,
    status     text NOT NULL DEFAULT 'open',
    opened_by  text NOT NULL,
    opened_at  bigint NOT NULL,
    closed_at  bigint,
    note       text
  )`;
  // The reference is how a case is named out loud, in a ticket or a handover, so two
  // cases must not answer to one. Unique rather than merely indexed.
  await q`CREATE UNIQUE INDEX IF NOT EXISTS octopus_cases_ref ON octopus_cases (ref)`;

  await q`CREATE TABLE IF NOT EXISTS octopus_case_entities (
    id        text PRIMARY KEY,
    case_id   text NOT NULL,
    kind      text NOT NULL,
    value     text NOT NULL,
    label     text,
    added_by  text NOT NULL,
    added_at  bigint NOT NULL
  )`;
  // One selector appears once in a case. Adding it twice is a slip, not a second lead,
  // and two nodes for one address would quietly double every correlation drawn on it.
  await q`CREATE UNIQUE INDEX IF NOT EXISTS octopus_case_entity_once ON octopus_case_entities (case_id, kind, value)`;

  await q`CREATE TABLE IF NOT EXISTS octopus_case_facts (
    id        text PRIMARY KEY,
    case_id   text NOT NULL,
    entity_id text NOT NULL,
    category  text NOT NULL,
    severity  text NOT NULL,
    label     text NOT NULL,
    value     text NOT NULL,
    source    text NOT NULL,
    note      text,
    added_by  text NOT NULL,
    added_at  bigint NOT NULL
  )`;
  await q`CREATE INDEX IF NOT EXISTS octopus_case_facts_case ON octopus_case_facts (case_id)`;
  // the same value pinned twice to one selector from one dump is one fact
  await q`CREATE UNIQUE INDEX IF NOT EXISTS octopus_case_fact_once ON octopus_case_facts (entity_id, label, value, source)`;
});

async function init(): Promise<boolean> {
  if (!sql()) return false;
  await build();
  return true;
}

const id = () => Math.random().toString(36).slice(2, 10) + Date.now().toString(36);

const toCase = (r: any): CaseFile => ({
  id: r.id, ref: r.ref, title: r.title, status: r.status,
  openedBy: r.opened_by, openedAt: Number(r.opened_at),
  closedAt: r.closed_at ? Number(r.closed_at) : undefined,
  note: r.note || undefined,
});
const toEntity = (r: any): CaseEntity => ({
  id: r.id, kind: r.kind as EntityKind, value: r.value,
  label: r.label || undefined, addedAt: Number(r.added_at),
});
const toFact = (r: any): CaseFact => ({
  id: r.id, entityId: r.entity_id, category: r.category, severity: r.severity,
  label: r.label, value: r.value, source: r.source, note: r.note || undefined,
  addedBy: r.added_by, addedAt: Number(r.added_at),
});

export async function listCaseFiles(status?: "open" | "closed"): Promise<(CaseFile & { entities: number; facts: number })[]> {
  const q = sql();
  if (!q || !(await init())) return [];
  const rows = status
    ? await q`SELECT c.*,
        (SELECT count(*) FROM octopus_case_entities e WHERE e.case_id = c.id) AS n_ent,
        (SELECT count(*) FROM octopus_case_facts f WHERE f.case_id = c.id) AS n_fact
        FROM octopus_cases c WHERE c.status = ${status} ORDER BY c.opened_at DESC LIMIT 200`
    : await q`SELECT c.*,
        (SELECT count(*) FROM octopus_case_entities e WHERE e.case_id = c.id) AS n_ent,
        (SELECT count(*) FROM octopus_case_facts f WHERE f.case_id = c.id) AS n_fact
        FROM octopus_cases c ORDER BY c.status, c.opened_at DESC LIMIT 200`;
  return rows.map((r: any) => ({ ...toCase(r), entities: Number(r.n_ent), facts: Number(r.n_fact) }));
}

export async function openCase(ref: string, title: string, by: string): Promise<{ ok: true; id: string } | { ok: false; error: string }> {
  const q = sql();
  if (!q || !(await init())) return { ok: false, error: "no database, cases need one" };
  const r = String(ref || "").trim().slice(0, 64);
  const t = String(title || "").trim().slice(0, 200);
  if (!r) return { ok: false, error: "a case needs a reference" };
  const cid = id();
  try {
    await q`INSERT INTO octopus_cases (id, ref, title, status, opened_by, opened_at)
            VALUES (${cid}, ${r}, ${t || r}, ${"open"}, ${by}, ${Date.now()})`;
  } catch {
    // the unique index did its job
    return { ok: false, error: `a case already answers to ${r}` };
  }
  return { ok: true, id: cid };
}

export async function readCase(cid: string): Promise<{ file: CaseFile; entities: CaseEntity[]; facts: CaseFact[] } | null> {
  const q = sql();
  if (!q || !(await init())) return null;
  const [c] = await q`SELECT * FROM octopus_cases WHERE id = ${cid}`;
  if (!c) return null;
  const ents = await q`SELECT * FROM octopus_case_entities WHERE case_id = ${cid} ORDER BY added_at`;
  const facts = await q`SELECT * FROM octopus_case_facts WHERE case_id = ${cid} ORDER BY added_at`;
  return { file: toCase(c), entities: ents.map(toEntity), facts: facts.map(toFact) };
}

/**
 * A case by the reference a person actually says out loud.
 *
 * Pinning from a report has to work from the string typed into "file under", because
 * that is what the hunter has in front of them; the case id is an implementation
 * detail they never see.
 */
export async function caseByRef(ref: string): Promise<CaseFile | null> {
  const q = sql();
  if (!q || !(await init())) return null;
  const [r] = await q`SELECT * FROM octopus_cases WHERE ref = ${String(ref || "").trim()}`;
  return r ? toCase(r) : null;
}

/**
 * The selector a report is about, as an entity in the case.
 *
 * Find-or-create, because the alternative is making somebody add the selector by hand
 * before they can pin the first thing they found on it. The unique index is what makes
 * this safe under two tabs: the insert either wins or loses, and the loser reads the
 * row that won rather than creating a second node for one address.
 */
export async function entityFor(cid: string, kind: EntityKind, value: string, label: string, by: string): Promise<string | null> {
  const q = sql();
  if (!q || !(await init())) return null;
  const v = String(value || "").trim().slice(0, 300);
  if (!v) return null;
  const [existing] = await q`SELECT id FROM octopus_case_entities WHERE case_id = ${cid} AND kind = ${kind} AND value = ${v}`;
  if (existing) return existing.id;
  const r = await addEntity(cid, kind, v, label, by);
  if (r.ok) return r.id;
  const [raced] = await q`SELECT id FROM octopus_case_entities WHERE case_id = ${cid} AND kind = ${kind} AND value = ${v}`;
  return raced ? raced.id : null;
}

export async function addEntity(cid: string, kind: EntityKind, value: string, label: string, by: string) {
  const q = sql();
  if (!q || !(await init())) return { ok: false as const, error: "no database" };
  const v = String(value || "").trim().slice(0, 300);
  if (!v) return { ok: false as const, error: "nothing to add" };
  const eid = id();
  try {
    await q`INSERT INTO octopus_case_entities (id, case_id, kind, value, label, added_by, added_at)
            VALUES (${eid}, ${cid}, ${kind}, ${v}, ${String(label || "").trim().slice(0, 120) || null}, ${by}, ${Date.now()})`;
  } catch {
    return { ok: false as const, error: "that selector is already in this case" };
  }
  return { ok: true as const, id: eid };
}

export async function pinFact(cid: string, f: Omit<CaseFact, "id" | "addedAt">) {
  const q = sql();
  if (!q || !(await init())) return { ok: false as const, error: "no database" };
  const fid = id();
  try {
    await q`INSERT INTO octopus_case_facts (id, case_id, entity_id, category, severity, label, value, source, note, added_by, added_at)
            VALUES (${fid}, ${cid}, ${f.entityId}, ${f.category}, ${f.severity}, ${f.label.slice(0, 120)},
                    ${f.value.slice(0, 400)}, ${f.source.slice(0, 200)}, ${f.note?.slice(0, 500) || null}, ${f.addedBy}, ${Date.now()})`;
  } catch {
    return { ok: false as const, error: "already pinned" };
  }
  return { ok: true as const, id: fid };
}

/**
 * Taking something back out.
 *
 * A hunter who pins a fact and then decides it was a coincidence has to be able to
 * remove it, or the board keeps drawing a line nobody believes any more. The audit
 * trail records that the case was edited; the case itself is a working document, not
 * an append-only log, and pretending otherwise would just produce cases full of facts
 * annotated "ignore this one".
 */
export async function unpinFact(cid: string, fid: string) {
  const q = sql();
  if (!q || !(await init())) return false;
  await q`DELETE FROM octopus_case_facts WHERE id = ${fid} AND case_id = ${cid}`;
  return true;
}

export async function removeEntity(cid: string, eid: string) {
  const q = sql();
  if (!q || !(await init())) return false;
  // its facts go with it: a fact whose selector is gone belongs to nothing
  await q`DELETE FROM octopus_case_facts WHERE case_id = ${cid} AND entity_id = ${eid}`;
  await q`DELETE FROM octopus_case_entities WHERE case_id = ${cid} AND id = ${eid}`;
  return true;
}

export async function setCaseStatus(cid: string, status: "open" | "closed", note?: string) {
  const q = sql();
  if (!q || !(await init())) return false;
  await q`UPDATE octopus_cases SET status = ${status},
          closed_at = ${status === "closed" ? Date.now() : null},
          note = COALESCE(${note ?? null}, note) WHERE id = ${cid}`;
  return true;
}
