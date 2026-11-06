// Where a subject appears to be, and on what basis.
//
// "Geolocation" in this category usually means an IP looked up against a commercial
// database and printed as a city, with no indication that the city is a guess about a
// range that may have been reallocated twice since the dump was assembled. In an
// incident report that line gets read as fact and acted on.
//
// So this does not produce a location. It produces EVIDENCE OF LOCATION, each piece
// carrying where it came from and how much it is worth, and it refuses to collapse them
// into one answer. Three accounts whose phones are French and whose addresses are in
// Lyon is a conclusion a hunter can draw and defend. "France (87%)" is not.
//
// WHAT CARRIES LOCATION, strongest first:
//
//   A country or city column in the record. The dump says it; we cite the dump.
//   A phone number. The country code is part of the number, parsed, not inferred.
//   A postal address. What it says, as it says it, never geocoded.
//   An email domain under a country TLD. A hint about where a domain was registered,
//   which is not where a person is, and is labelled accordingly.
//
// AND WHAT DOES NOT. An IP address cannot be turned into a country here, because doing
// it honestly needs a geo database and there is no honest way to infer it from the
// number itself: allocations move between countries, and the RIR holding a block is a
// registry, not a location. lib/netintel.ts says what an address IS; if a deployment
// wants country attribution it supplies a database, and the hook for it is at the
// bottom of this file rather than a guess in the middle of it.

import { phoneIntel } from "./phone";

export type GeoWeight = "stated" | "derived" | "hint";

export interface GeoClue {
  /** what it says: a country name or code, a city, a region */
  place: string;
  /** "country" | "city" | "address" */
  level: "country" | "city" | "address";
  weight: GeoWeight;
  /** the field and the database it came out of, so it can be checked */
  from: string;
  /** why this is worth what it is worth */
  basis: string;
}

/** Country TLDs worth naming. Anything else is reported as the bare TLD. */
const CCTLD: Record<string, string> = {
  fr: "France", be: "Belgium", ch: "Switzerland", lu: "Luxembourg", mc: "Monaco",
  de: "Germany", at: "Austria", nl: "Netherlands", es: "Spain", pt: "Portugal",
  it: "Italy", uk: "United Kingdom", ie: "Ireland", dk: "Denmark", se: "Sweden",
  no: "Norway", fi: "Finland", pl: "Poland", cz: "Czechia", sk: "Slovakia",
  hu: "Hungary", ro: "Romania", bg: "Bulgaria", gr: "Greece", tr: "Turkey",
  ru: "Russia", ua: "Ukraine", by: "Belarus", kz: "Kazakhstan",
  us: "United States", ca: "Canada", mx: "Mexico", br: "Brazil", ar: "Argentina",
  cn: "China", jp: "Japan", kr: "South Korea", in: "India", au: "Australia",
  nz: "New Zealand", za: "South Africa", ma: "Morocco", dz: "Algeria", tn: "Tunisia",
  sn: "Senegal", ci: "Ivory Coast", il: "Israel", ae: "United Arab Emirates",
};

const COUNTRY_LABEL: Record<string, string> = {
  ...CCTLD,
  gb: "United Kingdom",
};

const countryName = (code: string) => COUNTRY_LABEL[code.toLowerCase()] || code.toUpperCase();

/** Column names that carry a place, and which kind. */
const PLACE_COLUMNS: { re: RegExp; level: GeoClue["level"] }[] = [
  { re: /^country|country.?(code|name)$|\bpays\b|страна/i, level: "country" },
  { re: /^city$|\bcity\b|town|ville|город/i, level: "city" },
  { re: /region|state|province|county|departement/i, level: "city" },
  { re: /address|street|postal|\bzip\b|adresse/i, level: "address" },
];

export interface GeoInput {
  /** the record's own columns, as the dump named them */
  label: string;
  value: string;
  /** the database it came from */
  source: string;
}

/**
 * Every piece of evidence of location in a set of fields.
 *
 * Returns a list, never a single place, and never a score. Two clues that agree are
 * shown agreeing; two that disagree are shown disagreeing, which is itself the finding
 * when it happens, and the thing a collapsed answer would have hidden.
 */
export function geoClues(fields: GeoInput[], region = "FR"): GeoClue[] {
  const out: GeoClue[] = [];
  const seen = new Set<string>();
  const add = (c: GeoClue) => {
    const k = c.level + "|" + c.place.toLowerCase() + "|" + c.from;
    if (seen.has(k)) return;
    seen.add(k);
    out.push(c);
  };

  for (const f of fields) {
    const v = String(f.value ?? "").trim();
    if (!v) continue;
    const label = String(f.label ?? "");

    // 1. the record says so
    for (const p of PLACE_COLUMNS) {
      if (!p.re.test(label)) continue;
      const place = p.level === "country" && /^[a-z]{2}$/i.test(v) ? countryName(v) : v;
      add({
        place, level: p.level, weight: "stated", from: `${label} · ${f.source}`,
        basis: "The record carries this field. It is what the breached service held, not an inference.",
      });
      break;
    }

    // 2. the number carries its own country
    if (/phone|mobile|\btel\b|msisdn|numero/i.test(label) || /^\+\d[\d\s().-]{6,}$/.test(v)) {
      const intel = phoneIntel(v, region);
      if (intel.country) {
        add({
          place: countryName(intel.country), level: "country", weight: "derived",
          from: `${label} · ${f.source}`,
          basis: "Parsed from the number itself. The country code is part of the number, not a lookup.",
        });
      }
    }

    // 3. a domain under a country registry
    const at = v.lastIndexOf("@");
    if (at > 0) {
      const tld = v.slice(at + 1).split(".").pop()!.toLowerCase();
      if (tld.length === 2) {
        add({
          place: CCTLD[tld] || "." + tld, level: "country", weight: "hint",
          from: `${label} · ${f.source}`,
          basis: "The mailbox is under a country registry. That is where a domain was registered, which is not where a person is.",
        });
      }
    }
  }

  // stated before derived before hint, so a reader meets the strongest first
  const rank: Record<GeoWeight, number> = { stated: 0, derived: 1, hint: 2 };
  return out.sort((a, b) => rank[a.weight] - rank[b.weight] || a.level.localeCompare(b.level));
}

/**
 * One line, including the disagreement when there is one.
 *
 * A subject whose record says Poland and whose phone is French is the single most
 * interesting thing this module can report, and it is exactly what a single "location"
 * field would have thrown away.
 */
export function describeGeo(clues: GeoClue[]): string {
  const countries = [...new Set(clues.filter((c) => c.level === "country" && c.weight !== "hint").map((c) => c.place))];
  const cities = [...new Set(clues.filter((c) => c.level === "city").map((c) => c.place))];
  if (!clues.length) return "Nothing in these records carries a location.";
  if (countries.length > 1) {
    return `Sources disagree: ${countries.join(" and ")}. Worth resolving before anything rests on it.`;
  }
  const where = countries[0] || cities[0];
  if (!where) return "Only weak hints, nothing a finding should rest on.";
  const detail = cities.length && countries.length ? `${cities.join(", ")}, ${countries[0]}` : where;
  return `${detail}, from ${clues.filter((c) => c.weight !== "hint").length} field${clues.length === 1 ? "" : "s"} that carry it.`;
}

/**
 * The hook for real IP geolocation, deliberately empty.
 *
 * A deployment that wants country from an address supplies a database: DB-IP and
 * MaxMind both publish a free monthly CSV of start,end,country. Point
 * OCTOPUS_GEOIP_FILE at one and implement the lookup here. Until then this returns
 * null, and a null that the interface renders as "not attempted" is the correct output
 * for a question nobody answered.
 */
export function countryForIp(_ip: string): { country: string; source: string } | null {
  return null;
}
