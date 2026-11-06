// Who, at this organisation, is in breach data.
//
// THE QUESTION THE PRODUCT COULD NOT ANSWER. Searching a domain went through the
// one-subject machinery: every row was tested against "@corp.example" as though it were
// a person, every row failed, and the report came back CLEAR with nothing in it. A
// CSIRT asking the single most obvious question about its own estate got a confident,
// detailed, empty answer, which is the exact failure this codebase is built against.
//
// A domain is not a subject and the answer is not a report about one person. It is a
// ROSTER: the distinct accounts at that domain the index knows about, what leaked for
// each, and which of them are urgent. Nothing is consolidated across accounts, because
// two people at one employer are two people, and the whole value of the view is that
// it does not merge them.
//
// WHAT MAKES ONE ROW URGENT AND ANOTHER NOT. An address in a marketing list is an
// address in a marketing list. The same address in a stealer log means a machine
// somebody in the estate was using was compromised, with whatever that session had
// open; that distinction decides what happens in the next hour, so it is computed
// rather than left for a reader to notice.

import type { LeakDatabase } from "./leakosint";
import { itemsFromRow } from "./leakosint";

export interface DomainAccount {
  address: string;
  local: string;
  /** every database that carried this account */
  sources: string[];
  /** distinct values attributed to it, excluding the address itself */
  fields: number;
  /** plaintext secrets, never the hashes and never the masked ones */
  passwords: string[];
  hashes: number;
  /** the row has the shape of an infostealer capture rather than a leaked table */
  stealer: boolean;
  severity: "critical" | "high" | "medium" | "low";
  /** what leaked, as the dump named it */
  fieldNames: string[];
}

export interface DomainReport {
  domain: string;
  accounts: DomainAccount[];
  counts: { accounts: number; withPlaintext: number; inStealerLogs: number; databases: number };
  databases: { name: string; accounts: number; stealer: boolean }[];
  /** rows the index returned that were NOT at this domain */
  excluded: number;
  summary: string;
  /** what to do first, in the order it should be done */
  actions: string[];
}

/** A domain selector, in the spellings somebody actually types. */
export function domainOf(raw: string): string | null {
  const t = String(raw ?? "").trim().toLowerCase().replace(/^\*?@/, "").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!t || t.includes(" ") || t.includes("@")) return null;
  // a hostname with at least one dot and a plausible TLD; never a bare word, which is
  // far more likely to be a username
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(t)) return null;
  const tld = t.split(".").pop()!;
  if (tld.length < 2 || /^\d+$/.test(tld)) return null;
  return t;
}

/** Did the operator mean a domain? Only when they said so, or when nothing else fits. */
export function looksLikeDomainQuery(raw: string): boolean {
  const t = String(raw ?? "").trim();
  // "@corp.example" and "*@corp.example" are unambiguous: nobody types a leading @ for
  // anything else. A bare "corp.example" is left to the ordinary selector parser,
  // because it is also a perfectly good username and guessing wrong costs a search.
  if (/^\*?@/.test(t)) return !!domainOf(t);
  return false;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HASHISH = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$|^\$[0-9a-z]{1,4}\$/i;
const MASKED = /\*{2,}/;

/**
 * Does this row look like an infostealer capture rather than a leaked table?
 *
 * Stealer logs have a shape no ordinary breach has: the site the credential was for,
 * sitting next to the credential, usually with something about the machine. A leaked
 * customer table has columns about the customer and nothing about where they were
 * standing. Two of the three signals is the threshold, because any one alone appears in
 * ordinary dumps often enough to be noise.
 */
export function looksLikeStealerRow(row: Record<string, string>): boolean {
  const keys = Object.keys(row).map((k) => k.toLowerCase());
  const has = (re: RegExp) => keys.some((k) => re.test(k));
  const signals = [
    has(/^url$|host|domain|application|software|soft$/) && has(/pass|pwd/),
    has(/machine|computer|hwid|device|os$|operating|install.?date|build.?id/),
    has(/user.?agent|browser|profile.?path|cookie/),
  ].filter(Boolean).length;
  // and the one unambiguous case: a dump that says what it is
  return signals >= 2;
}

const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 } as const;

export function buildDomainReport(domain: string, databases: LeakDatabase[]): DomainReport {
  const dom = domain.toLowerCase();
  const byAccount = new Map<string, DomainAccount>();
  const byDb = new Map<string, { accounts: Set<string>; stealer: boolean }>();
  let excluded = 0;

  for (const db of databases) {
    for (const row of db.rows || []) {
      // The account is whichever address in the row is at this domain. A row can carry
      // several addresses; only the ones at the domain make it ours, and a row with
      // none is somebody else's and is counted rather than silently dropped.
      const addresses = Object.values(row)
        .map((v) => String(v ?? "").trim().toLowerCase())
        .filter((v) => EMAIL.test(v) && v.endsWith("@" + dom));
      if (!addresses.length) { excluded++; continue; }

      const stealer = looksLikeStealerRow(row);
      const items = itemsFromRow({ name: db.name }, row);

      for (const address of new Set(addresses)) {
        const acc = byAccount.get(address) || {
          address, local: address.slice(0, address.lastIndexOf("@")),
          sources: [], fields: 0, passwords: [], hashes: 0,
          stealer: false, severity: "low" as DomainAccount["severity"], fieldNames: [],
        };
        if (!acc.sources.includes(db.name)) acc.sources.push(db.name);
        acc.stealer = acc.stealer || stealer;

        const seen = new Set<string>();
        for (const it of items) {
          const v = String(it.value ?? "").trim();
          if (!v || v.toLowerCase() === address) continue;
          if (it.kind === "credential") {
            if (MASKED.test(v)) continue;
            // A hash is a different finding from a password: one needs cracking, the
            // other is already usable, and telling a responder they have plaintext when
            // they have bcrypt wastes the hour that mattered.
            if (HASHISH.test(v)) acc.hashes++;
            else if (!acc.passwords.includes(v)) acc.passwords.push(v);
            continue;
          }
          if (it.kind === "date" || it.kind === "count") continue;
          if (seen.has(v.toLowerCase())) continue;
          seen.add(v.toLowerCase());
          if (!acc.fieldNames.includes(it.label)) acc.fieldNames.push(it.label);
        }
        acc.fields = acc.fieldNames.length;
        byAccount.set(address, acc);
      }

      const d = byDb.get(db.name) || { accounts: new Set<string>(), stealer: false };
      addresses.forEach((a) => d.accounts.add(a));
      d.stealer = d.stealer || stealer;
      byDb.set(db.name, d);
    }
  }

  for (const acc of byAccount.values()) {
    acc.severity = acc.stealer && acc.passwords.length ? "critical"
      : acc.passwords.length ? "critical"
      : acc.stealer ? "high"
      : acc.hashes ? "medium"
      : "low";
  }

  const accounts = [...byAccount.values()].sort(
    (a, b) =>
      SEV_RANK[b.severity] - SEV_RANK[a.severity] ||
      b.sources.length - a.sources.length ||
      b.fields - a.fields ||
      a.address.localeCompare(b.address),
  );

  const withPlaintext = accounts.filter((a) => a.passwords.length).length;
  const inStealer = accounts.filter((a) => a.stealer).length;
  const counts = { accounts: accounts.length, withPlaintext, inStealerLogs: inStealer, databases: byDb.size };

  const databasesOut = [...byDb.entries()]
    .map(([name, v]) => ({ name, accounts: v.accounts.size, stealer: v.stealer }))
    .sort((a, b) => b.accounts - a.accounts || a.name.localeCompare(b.name));

  return {
    domain: dom, accounts, counts, databases: databasesOut, excluded,
    summary: summarise(dom, counts),
    actions: actionsFor(accounts, counts),
  };
}

function summarise(dom: string, c: DomainReport["counts"]): string {
  if (!c.accounts) return `No account at ${dom} appears in the index.`;
  const parts = [`${c.accounts} account${c.accounts === 1 ? "" : "s"} at ${dom}, across ${c.databases} database${c.databases === 1 ? "" : "s"}`];
  if (c.withPlaintext) parts.push(`${c.withPlaintext} with a password in the clear`);
  if (c.inStealerLogs) parts.push(`${c.inStealerLogs} in what looks like a stealer log`);
  return parts.join(". ") + ".";
}

/**
 * What to do first.
 *
 * Ordered by what stops the bleeding rather than by severity label. A stealer log is
 * above a plaintext password even when both are present, because a cleared password
 * does not clear the session cookies that came off the same machine.
 */
function actionsFor(accounts: DomainAccount[], c: DomainReport["counts"]): string[] {
  const out: string[] = [];
  if (!c.accounts) return ["Nothing to do. No account at this domain is in the index."];
  const stealer = accounts.filter((a) => a.stealer);
  if (stealer.length) {
    out.push(`${stealer.length} account${stealer.length === 1 ? " is" : "s are"} in a stealer log: ${stealer.slice(0, 5).map((a) => a.address).join(", ")}${stealer.length > 5 ? ` and ${stealer.length - 5} more` : ""}. Treat the MACHINE as compromised, not just the password: revoke sessions and tokens, because a reset does not invalidate a stolen cookie.`);
  }
  if (c.withPlaintext) {
    out.push(`${c.withPlaintext} password${c.withPlaintext === 1 ? " is" : "s are"} in the clear. Force a reset, and check the same string against anything that does not federate.`);
  }
  const wide = accounts.filter((a) => a.sources.length >= 3);
  if (wide.length) {
    out.push(`${wide.length} account${wide.length === 1 ? " appears" : "s appear"} in three or more databases. Repeated exposure is what makes credential stuffing worth somebody's time.`);
  }
  out.push("Everything here is historic by definition. It says what has already leaked, never whether an account is currently compromised.");
  return out;
}
