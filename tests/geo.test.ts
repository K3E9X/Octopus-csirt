import { test } from "node:test";
import assert from "node:assert/strict";
import { geoClues, describeGeo, countryForIp } from "../lib/geo.ts";

const f = (label: string, value: string, source = "Vectra Fitness 2019") => ({ label, value, source });

test("a country column is stated evidence and cites the dump that held it", () => {
  const [c] = geoClues([f("Country", "FR")]);
  assert.equal(c.place, "France");
  assert.equal(c.weight, "stated");
  assert.match(c.from, /Country · Vectra Fitness 2019/);
});

test("a phone number carries its own country, parsed rather than looked up", () => {
  const clues = geoClues([f("Phone", "+33 6 39 98 41 02")]);
  const c = clues.find((x) => x.weight === "derived")!;
  assert.equal(c.place, "France");
  assert.match(c.basis, /part of the number/);
});

test("a country TLD is a hint about a registry, and is labelled as one", () => {
  const [c] = geoClues([f("Email", "someone@example.fr")]);
  assert.equal(c.weight, "hint");
  assert.match(c.basis, /not where a person is/);
  // and a generic TLD says nothing at all
  assert.deepEqual(geoClues([f("Email", "someone@example.com")]), []);
});

// THE CASE THE MODULE EXISTS FOR. A single "location" field would print one of these
// and silently drop the other, and the contradiction is the most interesting thing in
// the record.
test("sources that disagree are reported as disagreeing, not averaged", () => {
  const clues = geoClues([f("Country", "PL"), f("Phone", "+33 6 39 98 41 02")]);
  const line = describeGeo(clues);
  assert.match(line, /disagree/i);
  assert.match(line, /Poland/);
  assert.match(line, /France/);
});

test("a city and a country that agree read as one place", () => {
  const line = describeGeo(geoClues([f("Country", "FR"), f("City", "Lyon")]));
  assert.match(line, /Lyon, France/);
});

test("nothing is invented when nothing carries a location", () => {
  assert.match(describeGeo(geoClues([f("Password", "Sablon2019!")])), /Nothing in these records/);
  assert.match(describeGeo(geoClues([f("Email", "x@example.fr")])), /Only weak hints/);
});

// The honest limit, asserted so nobody quietly replaces it with a guess.
test("an IP is not turned into a country without a database", () => {
  assert.equal(countryForIp("92.184.104.57"), null);
});
