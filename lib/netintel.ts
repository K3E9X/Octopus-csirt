// What an address in a breach record can be made to say, and where that stops.
//
// An IP in a stealer log is one of the few fields that is about the MACHINE rather than
// the account, which makes it one of the few that correlates two identities into one
// person. Two accounts seen from one address is a lead. Two accounts in one /24 is a
// weaker lead worth looking at. An account seen from a carrier-grade NAT range is
// almost no lead at all, and saying so is the useful part.
//
// WHERE THIS STOPS, STATED PLAINLY, because the alternative is a case file that reads
// like it knows something it does not. Turning an address into a COUNTRY requires a geo
// database. There is no honest way to infer it from the number: allocations move, the
// RIR that holds a block is not where the host is, and a confident wrong country in an
// incident report is worse than a blank field. So this module does the part that is
// deterministic, and lib/geo.ts handles location from sources that actually carry it.

export type NetKind =
  | "public-v4" | "public-v6"
  | "private" | "cgnat" | "loopback" | "link-local" | "documentation" | "multicast" | "reserved"
  | "invalid";

export interface NetFact {
  raw: string;
  kind: NetKind;
  version?: 4 | 6;
  /** the /24 for v4, the /48 for v6: the block two addresses would share */
  block?: string;
  /** why this address is or is not worth correlating on */
  weight: "strong" | "weak" | "none";
  note?: string;
}

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function v4Kind(o: number[]): NetKind {
  const [a, b] = o;
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";
  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "link-local";
  // RFC 6598: shared address space. An address here belongs to a carrier's NAT, so two
  // subscribers can hold it at once and it correlates almost nothing.
  if (a === 100 && b >= 64 && b <= 127) return "cgnat";
  if (a === 192 && b === 0 && o[2] === 2) return "documentation";
  if (a === 198 && (b === 51) && o[2] === 100) return "documentation";
  if (a === 203 && b === 0 && o[2] === 113) return "documentation";
  if (a >= 224 && a <= 239) return "multicast";
  if (a === 0 || a >= 240) return "reserved";
  return "public-v4";
}

export function netFact(raw: string): NetFact {
  const t = String(raw ?? "").trim();
  if (!t) return { raw: t, kind: "invalid", weight: "none" };

  const m = t.match(V4);
  if (m) {
    const o = m.slice(1, 5).map(Number);
    if (o.some((n) => n > 255)) return { raw: t, kind: "invalid", weight: "none", note: "Not a valid address." };
    const kind = v4Kind(o);
    const block = `${o[0]}.${o[1]}.${o[2]}.0/24`;
    if (kind === "public-v4") return { raw: t, kind, version: 4, block, weight: "strong" };
    if (kind === "cgnat") {
      return { raw: t, kind, version: 4, block, weight: "weak",
        note: "Carrier-grade NAT (RFC 6598). Thousands of subscribers share this range, so two accounts seen here are not evidence of one person." };
    }
    if (kind === "private") {
      return { raw: t, kind, version: 4, block, weight: "weak",
        note: "A private address (RFC 1918). It identifies a position inside some network, not which network, so it only correlates within one estate." };
    }
    return { raw: t, kind, version: 4, block, weight: "none",
      note: kind === "documentation" ? "A documentation range. This is placeholder data, not a real session." : undefined };
  }

  // IPv6, recognised rather than fully parsed: the forms that appear in dumps are
  // normal addresses, and anything exotic should fall through as unreadable rather
  // than be guessed at.
  if (/^[0-9a-f:]+$/i.test(t) && t.includes(":") && t.length >= 3) {
    const low = t.toLowerCase();
    if (low === "::1") return { raw: t, kind: "loopback", version: 6, weight: "none" };
    if (/^fe[89ab]/.test(low)) return { raw: t, kind: "link-local", version: 6, weight: "none" };
    if (/^f[cd]/.test(low)) return { raw: t, kind: "private", version: 6, weight: "weak", note: "A unique local address (RFC 4193)." };
    if (/^2001:0?db8/.test(low)) return { raw: t, kind: "documentation", version: 6, weight: "none", note: "A documentation range." };
    if (/^ff/.test(low)) return { raw: t, kind: "multicast", version: 6, weight: "none" };
    const groups = low.split(":").filter(Boolean);
    const block = groups.length >= 3 ? groups.slice(0, 3).join(":") + "::/48" : undefined;
    return { raw: t, kind: "public-v6", version: 6, block, weight: "strong" };
  }

  return { raw: t, kind: "invalid", weight: "none", note: "Not an address this can read." };
}

export interface Seen { value: string; owner: string }

export interface NetCluster {
  /** the exact address, or the block when it is a block match */
  key: string;
  exact: boolean;
  members: string[];
  weight: NetFact["weight"];
  note?: string;
}

/**
 * Which identities share an address, and which merely share a neighbourhood.
 *
 * Exact matches and block matches are kept APART rather than scored together. They are
 * different claims: one says two accounts were used from the same connection, the other
 * says they were used from the same ISP allocation, which in a residential range can be
 * a street and in a corporate one can be a continent. A product that folds them into a
 * single "related" number is inventing a confidence nobody computed.
 */
export function clusterByNetwork(seen: Seen[]): { exact: NetCluster[]; blocks: NetCluster[] } {
  const byAddr = new Map<string, Set<string>>();
  const byBlock = new Map<string, Set<string>>();
  const factOf = new Map<string, NetFact>();

  for (const s of seen) {
    const f = netFact(s.value);
    if (f.kind === "invalid" || f.weight === "none") continue;
    factOf.set(f.raw, f);
    (byAddr.get(f.raw) || byAddr.set(f.raw, new Set()).get(f.raw)!).add(s.owner);
    if (f.block) (byBlock.get(f.block) || byBlock.set(f.block, new Set()).get(f.block)!).add(s.owner);
  }

  const exact: NetCluster[] = [];
  for (const [addr, owners] of byAddr) {
    if (owners.size < 2) continue;
    const f = factOf.get(addr)!;
    exact.push({ key: addr, exact: true, members: [...owners].sort(), weight: f.weight, note: f.note });
  }

  const blocks: NetCluster[] = [];
  for (const [block, owners] of byBlock) {
    if (owners.size < 2) continue;
    // a block whose members already share an exact address adds nothing
    const covered = exact.some((e) => e.members.length === owners.size && e.members.every((m) => owners.has(m)));
    if (covered) continue;
    blocks.push({
      key: block, exact: false, members: [...owners].sort(), weight: "weak",
      note: "Same allocation, different addresses. Worth a look, not a link.",
    });
  }

  const bySize = (a: NetCluster, b: NetCluster) => b.members.length - a.members.length || a.key.localeCompare(b.key);
  return { exact: exact.sort(bySize), blocks: blocks.sort(bySize) };
}
