import { test } from "node:test";
import assert from "node:assert/strict";
import { buildBoard, testFact, type CaseEntity, type CaseFact } from "../lib/casework.ts";

let n = 0;
const ent = (kind: CaseEntity["kind"], value: string, label?: string): CaseEntity =>
  ({ id: "e" + ++n, kind, value, label, addedAt: 0 });
const fact = (e: CaseEntity, category: string, label: string, value: string, source = "Vectra Fitness 2019"): CaseFact =>
  ({ id: "f" + ++n, entityId: e.id, category, severity: "medium", label, value, source, addedBy: "u", addedAt: 0 });

// The shape of a real lead: a stealer log gives a personal address, the insider lead
// gives a corporate one, and the question is whether they are the same person.
function chain() {
  const a = ent("email", "l.marchetti@example.com", "stealer log 14");
  const b = ent("email", "lmarchetti@corp.example", "the insider");
  const c = ent("ip", "92.184.104.57", "proxy line");
  const facts = [
    fact(a, "password", "Password", "Sablon2019!"),
    fact(a, "ip", "OrderIP", "92.184.104.57"),
    fact(b, "password", "Password", "Sablon2019!"),
    fact(b, "identity", "FullName", "Lena Marchetti"),
    fact(c, "ip", "IP", "92.184.104.57"),
  ];
  return { a, b, c, entities: [a, b, c], facts };
}

test("two selectors sharing a pinned value are one group; sharing nothing, they are not", () => {
  const { entities, facts } = chain();
  const b = buildBoard(entities, facts);
  assert.equal(b.graph.components.length, 1, "the shared password and address join all three");

  const alone = buildBoard([entities[0], entities[1]], [facts[1], facts[3]]);
  assert.equal(alone.graph.components.length, 2, "nothing shared, so nothing joined");
});

test("THE QUESTION A CASE ASKS: which pinned fact is the case resting on", () => {
  const { entities, facts } = chain();
  const b = buildBoard(entities, facts);
  const values = b.loadBearing.map((t) => t.value);
  // the password is the only thing joining the corporate address to the rest
  assert.ok(values.includes("Sablon2019!"), values.join(" / "));
});

test("and what happens if that fact turns out to be a coincidence", () => {
  const { entities, facts } = chain();
  const r = testFact(entities, facts, "Sablon2019!", "password");
  assert.equal(r.before, 1);
  assert.equal(r.after, 2, "the insider drops out of the group");
  assert.deepEqual(r.isolates, ["the insider"]);
});

test("an address shared by two selectors clusters; a neighbour does not", () => {
  const { entities, facts } = chain();
  const b = buildBoard(entities, facts);
  assert.equal(b.network.exact.length, 1);
  assert.equal(b.network.exact[0].key, "92.184.104.57");
  assert.ok(b.network.exact[0].members.length >= 2);
});

test("a carrier NAT address is shown, labelled, and never drawn as a link", () => {
  const a = ent("email", "a@example.com", "A"), b2 = ent("email", "b@example.com", "B");
  const board = buildBoard([a, b2], [fact(a, "ip", "IP", "100.70.12.9"), fact(b2, "ip", "IP", "100.70.12.9")]);

  // Reported, because hiding evidence is its own failure: two accounts on one carrier
  // address at one moment is worth a hunter's glance.
  assert.equal(board.network.exact.length, 1);
  assert.equal(board.network.exact[0].weight, "weak");
  assert.match(board.network.exact[0].note!, /Carrier-grade NAT/);

  // But it does NOT join them. RFC 6598 is held by thousands of subscribers at once,
  // and a line on the board is a claim that these are one person.
  assert.equal(board.graph.components.length, 2, "a NAT address is not a connection");
  assert.deepEqual(board.loadBearing, []);
});

test("two selectors seen from the same build cluster as one device", () => {
  const a = ent("email", "a@example.com", "A"), b2 = ent("email", "b@example.com", "B");
  const UA = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36";
  const board = buildBoard([a, b2], [fact(a, "other", "UserAgent", UA), fact(b2, "other", "user_agent", UA)]);
  assert.equal(board.devices.length, 1);
  assert.deepEqual(board.devices[0].entities.sort(), ["A", "B"]);
  assert.equal(board.devices[0].agent.os, "Windows");
  assert.ok(board.devices[0].agent.notes.some((x) => /end of support/i.test(x)));
});

test("the timeline keeps undated entries instead of hiding them", () => {
  const a = ent("email", "a@example.com", "A");
  const board = buildBoard([a], [
    fact(a, "other", "LastLogin", "2021-11-02"),
    fact(a, "other", "RegistrationDate", "not recorded"),
  ]);
  assert.equal(board.timeline.length, 2);
  assert.equal(board.timeline[0].when, Date.UTC(2021, 10, 2));
  // a hole in a timeline reads as absence of activity, which is a different claim
  assert.equal(board.timeline[1].when, undefined);
});

test("location comes from fields that carry it, and disagreement is the finding", () => {
  const a = ent("email", "a@example.com", "A");
  const board = buildBoard([a], [
    fact(a, "location", "Country", "PL"),
    fact(a, "phone", "Phone", "+33 6 39 98 41 02"),
  ]);
  assert.match(board.geoLine, /disagree/i);
});

// The gaps are the part a hunter reads first, so they have to be true of THIS case.
test("the gaps name what this case is actually missing", () => {
  const lone = buildBoard([ent("email", "a@example.com")], []);
  assert.ok(lone.gaps.some((g) => /One selector/.test(g)), lone.gaps.join(" | "));
  assert.ok(lone.gaps.some((g) => /nothing pinned/.test(g)), lone.gaps.join(" | "));

  const { entities, facts } = chain();
  const full = buildBoard(entities, facts);
  assert.ok(full.gaps.some((g) => /rests on/.test(g)), full.gaps.join(" | "));
  assert.ok(!full.gaps.some((g) => /One selector/.test(g)));
});

test("an empty case says so rather than drawing an empty board", () => {
  const b = buildBoard([], []);
  assert.deepEqual(b.gaps, ["Nothing in the case yet. Add the selector the lead arrived as."]);
  assert.equal(b.graph.nodes.length, 0);
});
