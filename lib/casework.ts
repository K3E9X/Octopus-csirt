// A case: several selectors, the facts a hunter pinned to each, and what they say
// together that none of them says alone.
//
// THE SHAPE OF THE WORK. A CSIRT lead does not arrive as an identity. It arrives as a
// stealer log, an insider's corporate address, an IP out of a proxy line. The hunter
// searches that, finds a second selector inside the results, searches that, and keeps
// going until the thing either closes into one person or splits into two. Everything
// here exists to make that loop visible: which selectors are joined, by what, and what
// would have to be true for them to be the same person.
//
// A CASE HOLDS WHAT SOMEBODY PINNED, NOT WHAT THE INDEX RETURNED. That is a deliberate
// limit and it is worth the sentence. Caching whole reports would make the board
// cheaper to build and would turn the case table into a copy of other people's breach
// data, retained indefinitely, on our infrastructure, with no legal basis separate from
// the search that produced it. What a case stores is the ANALYST'S WORK: the selectors
// they chose to look at and the facts they decided were relevant, each still naming the
// dump it came from so it can be checked or dropped.
//
// THE CORRELATION IS THE ORBIT GRAPH, not a second mechanism. lib/orbit.ts already
// answers "are these one thing or several, and which fact holds them together" over
// databases; a case asks the same question over selectors. Reusing it means the
// load-bearing logic has one implementation and one set of tests, and the board and
// the report agree about what a connection is, which two implementations would
// eventually stop doing.

import { buildGraph, pullThread, type OrbitSource, type OrbitGraph } from "./orbit";
import { parseAgent, agentKey, describeAgent, type Agent } from "./ua";
import { clusterByNetwork, netFact, type NetCluster } from "./netintel";
import { geoClues, describeGeo, type GeoClue } from "./geo";

export type EntityKind = "email" | "phone" | "username" | "name" | "ip" | "machine" | "domain" | "other";

export interface CaseFact {
  id: string;
  entityId: string;
  /** the report's own category, so the board and the report agree about severity */
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  /** the column as the dump named it */
  label: string;
  value: string;
  /** the database it came from, which is what makes it checkable */
  source: string;
  /** why the hunter pinned it */
  note?: string;
  addedBy: string;
  addedAt: number;
}

export interface CaseEntity {
  id: string;
  kind: EntityKind;
  value: string;
  /** what the hunter calls it in this case: "the insider", "stealer log 14" */
  label?: string;
  addedAt: number;
}

export interface CaseFile {
  id: string;
  ref: string;
  title: string;
  status: "open" | "closed";
  openedBy: string;
  openedAt: number;
  closedAt?: number;
  note?: string;
}

// ---- the board ----------------------------------------------------------------------

export interface Sighting {
  /** the entity this was seen on */
  entityId: string;
  when?: number;
  what: string;
  detail?: string;
  source: string;
  kind: "login" | "registration" | "breach" | "pinned";
}

export interface DeviceCluster {
  key: string;
  agent: Agent;
  entities: string[];
  sources: string[];
}

export interface Board {
  /** the connection graph over selectors, from the same code the report's orbit uses */
  graph: OrbitGraph;
  /** which pinned fact, if removed, would split the case into more pieces */
  loadBearing: { value: string; category: string; entities: string[] }[];
  network: { exact: NetCluster[]; blocks: NetCluster[] };
  devices: DeviceCluster[];
  geo: GeoClue[];
  geoLine: string;
  timeline: Sighting[];
  /** what is missing, in the words of the next thing to do */
  gaps: string[];
}

const DATE_LABEL = /last.?(active|seen|login|visit)|sign.?in/i;
const REG_LABEL = /reg(istration)?.?date|sign.?up|joined|created/i;
const UA_LABEL = /user.?agent|\bua\b|browser.?string/i;

/** A date in any of the spellings dumps use, or nothing. Never a guess. */
function whenOf(value: string): number | undefined {
  const v = String(value ?? "").trim();
  if (!v) return undefined;
  // ISO first: it is unambiguous, and the rest are not
  let m = v.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3]);
  // a bare year is a year, and saying "1 January" would be inventing a day
  m = v.match(/^(19|20)\d{2}$/);
  if (m) return Date.UTC(+v, 0, 1);
  // unix seconds, as several dumps store them
  if (/^\d{10}$/.test(v)) return Number(v) * 1000;
  if (/^\d{13}$/.test(v)) return Number(v);
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : undefined;
}

/**
 * Build the board from the case's own contents.
 *
 * Everything in here is derived at read time from pinned facts. Nothing is stored
 * precomputed, because a board that disagreed with the facts under it would be worse
 * than no board, and a cache is how that happens.
 */
export function buildBoard(entities: CaseEntity[], facts: CaseFact[], region = "FR"): Board {
  const nameOf = new Map(entities.map((e) => [e.id, e.label || e.value]));
  const factsOf = new Map<string, CaseFact[]>();
  for (const f of facts) (factsOf.get(f.entityId) || factsOf.set(f.entityId, []).get(f.entityId)!).push(f);

  // ---- the connection graph, over selectors instead of databases ----
  // The entity IS the node, and its pinned facts are what can join it to another. The
  // selector itself is included as a fact about itself, because an address pinned under
  // one entity and typed as another entity's selector is the same join.
  const sources: OrbitSource[] = entities.map((e) => {
    const own = factsOf.get(e.id) || [];
    const worst = own.reduce<CaseFact["severity"]>((acc, f) => (rank(f.severity) > rank(acc) ? f.severity : acc), "low");
    return {
      name: nameOf.get(e.id)!,
      severity: worst,
      findings: [
        { category: kindCategory(e.kind), value: e.value, label: e.kind, severity: "medium" },
        ...own.map((f) => ({ category: f.category, value: f.value, label: f.label, severity: f.severity })),
      ],
    };
  });
  const graph = buildGraph(sources);

  const loadBearing = graph.threads
    .filter((t) => t.loadBearing)
    .map((t) => ({ value: t.value, category: t.category, entities: t.databases }));

  // ---- the machine, not the account ----
  const seenNet: { value: string; owner: string }[] = [];
  const agents = new Map<string, DeviceCluster>();
  const geoIn: { label: string; value: string; source: string }[] = [];
  const timeline: Sighting[] = [];

  for (const e of entities) {
    const who = nameOf.get(e.id)!;
    if (e.kind === "ip") seenNet.push({ value: e.value, owner: who });
    for (const f of factsOf.get(e.id) || []) {
      if (f.category === "ip" || netFact(f.value).kind.startsWith("public")) seenNet.push({ value: f.value, owner: who });
      geoIn.push({ label: f.label, value: f.value, source: f.source });

      if (UA_LABEL.test(f.label)) {
        const a = parseAgent(f.value);
        const k = agentKey(a);
        if (!k) continue;
        const c = agents.get(k) || { key: k, agent: a, entities: [], sources: [] };
        if (!c.entities.includes(who)) c.entities.push(who);
        if (!c.sources.includes(f.source)) c.sources.push(f.source);
        agents.set(k, c);
      }

      const when = whenOf(f.value);
      if (DATE_LABEL.test(f.label)) {
        timeline.push({ entityId: e.id, when, what: "Last seen", detail: f.value, source: f.source, kind: "login" });
      } else if (REG_LABEL.test(f.label)) {
        timeline.push({ entityId: e.id, when, what: "Account created", detail: f.value, source: f.source, kind: "registration" });
      }
    }
  }

  // Undated entries keep their place rather than being dropped: "a login, date unknown"
  // is a fact, and a timeline that silently omits it is a timeline with holes in it
  // that look like absence of activity.
  timeline.sort((a, b) => (a.when ?? Infinity) - (b.when ?? Infinity));

  const geo = geoClues(geoIn, region);
  const board: Board = {
    graph,
    loadBearing,
    network: clusterByNetwork(seenNet),
    devices: [...agents.values()].filter((d) => d.entities.length > 0).sort((a, b) => b.entities.length - a.entities.length),
    geo,
    geoLine: describeGeo(geo),
    timeline,
    gaps: [],
  };
  board.gaps = gapsIn(entities, facts, board);
  return board;
}

const rank = (s: CaseFact["severity"]) => ({ critical: 3, high: 2, medium: 1, low: 0 })[s];

/** What kind of value a selector is, in the report's own vocabulary. */
function kindCategory(k: EntityKind): string {
  if (k === "email") return "email";
  if (k === "phone") return "phone";
  if (k === "username") return "online";
  if (k === "name") return "identity";
  if (k === "ip") return "ip";
  return "other";
}

/**
 * What the case is missing, phrased as the next thing to do.
 *
 * Not a checklist and not a score. Each line is a statement about THIS case that a
 * hunter can act on or dismiss, and the first one is deliberately the one that decides
 * whether the case is about one person at all.
 */
function gapsIn(entities: CaseEntity[], facts: CaseFact[], b: Board): string[] {
  const out: string[] = [];
  if (!entities.length) return ["Nothing in the case yet. Add the selector the lead arrived as."];
  if (entities.length === 1) {
    out.push("One selector. Nothing can corroborate anything until a second one is in the case.");
  }
  if (b.graph.components.length > 1 && entities.length > 1) {
    out.push(`${b.graph.components.length} separate groups. On what is pinned so far these are not one person; find a value that spans them, or treat them as separate.`);
  }
  if (b.loadBearing.length) {
    const t = b.loadBearing[0];
    out.push(`The case rests on "${t.value}". If that turns out to be a coincidence, it falls apart. Corroborate it with a second shared value.`);
  }
  const withoutFacts = entities.filter((e) => !facts.some((f) => f.entityId === e.id));
  if (withoutFacts.length) {
    out.push(`${withoutFacts.length} selector${withoutFacts.length === 1 ? " has" : "s have"} nothing pinned: ${withoutFacts.map((e) => e.label || e.value).join(", ")}.`);
  }
  if (!b.timeline.some((t) => t.when)) {
    out.push("No dated activity. Without a last-seen or a registration date the case has no timeline.");
  }
  if (!b.devices.length && facts.some((f) => f.category === "ip")) {
    out.push("Addresses but no user agent. A browser string would say what the machine was, not just where it connected from.");
  }
  if (b.geo.every((g) => g.weight === "hint")) {
    out.push("No field carries a location. Everything on the map would be a guess.");
  }
  return out;
}

/** What would happen to the case if one pinned fact turned out to be wrong. */
export function testFact(entities: CaseEntity[], facts: CaseFact[], value: string, category: string) {
  const b = buildBoard(entities, facts);
  const id = category + "|" + value.trim().toLowerCase().replace(/\s+/g, " ");
  const sources: OrbitSource[] = entities.map((e) => ({
    name: e.label || e.value,
    severity: "low",
    findings: [
      { category: kindCategory(e.kind), value: e.value, label: e.kind, severity: "medium" },
      ...facts.filter((f) => f.entityId === e.id).map((f) => ({ category: f.category, value: f.value, label: f.label, severity: f.severity })),
    ],
  }));
  return { ...pullThread(sources, id), before: b.graph.components.length };
}

export { describeAgent };
