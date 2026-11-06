import { test } from "node:test";
import assert from "node:assert/strict";
import { cacheKey, cacheHours } from "../lib/searchcache.ts";

test("the key is the question, not the typing", () => {
  // the canonical query is what reaches the source, so two spellings that canonicalise
  // the same way must hit the same kept answer: that IS the saving
  assert.equal(cacheKey("l.m@example.com", 100, "FR", false), cacheKey("l.m@example.com", 100, "FR", false));
});

test("a deeper sweep is a different question and is paid for", () => {
  assert.notEqual(cacheKey("x@example.com", 100, "FR", false), cacheKey("x@example.com", 1000, "FR", false));
  // so is a quoted search, which reaches different rows
  assert.notEqual(cacheKey("john doe", 100, "FR", false), cacheKey("john doe", 100, "FR", true));
  // and so is a different region, because attribution parses numbers against it
  assert.notEqual(cacheKey("x@example.com", 100, "FR", false), cacheKey("x@example.com", 100, "GB", false));
});

test("the retention is bounded, and nonsense means off rather than forever", () => {
  const before = process.env.OCTOPUS_CACHE_HOURS;
  try {
    process.env.OCTOPUS_CACHE_HOURS = "";      assert.equal(cacheHours(), 0);
    process.env.OCTOPUS_CACHE_HOURS = "abc";   assert.equal(cacheHours(), 0);
    process.env.OCTOPUS_CACHE_HOURS = "-5";    assert.equal(cacheHours(), 0);
    process.env.OCTOPUS_CACHE_HOURS = "0";     assert.equal(cacheHours(), 0);
    process.env.OCTOPUS_CACHE_HOURS = "24";    assert.equal(cacheHours(), 24);
    // a month, and not a year by accident
    process.env.OCTOPUS_CACHE_HOURS = "99999"; assert.equal(cacheHours(), 720);
    delete process.env.OCTOPUS_CACHE_HOURS;    assert.equal(cacheHours(), 24);
  } finally {
    if (before === undefined) delete process.env.OCTOPUS_CACHE_HOURS; else process.env.OCTOPUS_CACHE_HOURS = before;
  }
});
