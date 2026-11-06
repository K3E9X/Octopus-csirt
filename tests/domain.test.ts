import { test } from "node:test";
import assert from "node:assert/strict";
import { domainOf, looksLikeDomainQuery, looksLikeStealerRow, buildDomainReport } from "../lib/domain.ts";

test("a domain is recognised in the spellings somebody types", () => {
  assert.equal(domainOf("@corp.example"), "corp.example");
  assert.equal(domainOf("*@corp.example"), "corp.example");
  assert.equal(domainOf("CORP.example"), "corp.example");
  assert.equal(domainOf("https://corp.example/path"), "corp.example");
});

test("and a username is not mistaken for one", () => {
  assert.equal(domainOf("lmarchetti"), null);
  assert.equal(domainOf("a@b.com"), null);          // that is an address, not a domain
  assert.equal(domainOf("two words"), null);
  assert.equal(domainOf("1.2"), null);              // a numeric TLD is not a TLD
  // A bare hostname IS a valid domain, but the query parser is left to decide: it is
  // also a perfectly good handle, and guessing wrong costs a paid search.
  assert.equal(looksLikeDomainQuery("corp.example"), false);
  assert.equal(looksLikeDomainQuery("@corp.example"), true);
});

const db = (name: string, rows: Record<string, string>[]) => ({ name, info: "", rows });

test("THE BUG THIS FIXES: a domain search used to come back empty", () => {
  const r = buildDomainReport("corp.example", [
    db("Corp 2023", [
      { Email: "alice@corp.example", Password: "a-plain-one" },
      { Email: "bob@corp.example", Password: "$2b$10$abcdefghijklmnopqrstuv" },
      { Email: "carol@corp.example", FullName: "Carol" },
    ]),
  ]);
  assert.equal(r.counts.accounts, 3, "three people, not one subject and two rejects");
  assert.equal(r.counts.withPlaintext, 1);
  assert.match(r.summary, /3 accounts at corp.example/);
});

test("two people at one employer stay two people", () => {
  const r = buildDomainReport("corp.example", [
    db("A", [{ Email: "alice@corp.example", City: "Lyon" }]),
    db("B", [{ Email: "bob@corp.example", City: "Lyon" }]),
  ]);
  assert.equal(r.counts.accounts, 2);
  // the shared city must not consolidate them into one subject
  assert.deepEqual(r.accounts.map((a) => a.local).sort(), ["alice", "bob"]);
});

test("a hash is not a password, and a masked value is neither", () => {
  const r = buildDomainReport("corp.example", [
    db("A", [
      { Email: "a@corp.example", Password: "5f4dcc3b5aa765d61d8327deb882cf99" },
      { Email: "b@corp.example", Password: "pa****rd" },
      { Email: "c@corp.example", Password: "actually-plain" },
    ]),
  ]);
  const by = Object.fromEntries(r.accounts.map((a) => [a.local, a]));
  assert.equal(by.a.hashes, 1);
  assert.deepEqual(by.a.passwords, [], "an MD5 is not usable as it stands");
  assert.deepEqual(by.b.passwords, [], "a masked value matches every password of that shape");
  assert.deepEqual(by.c.passwords, ["actually-plain"]);
  assert.equal(r.counts.withPlaintext, 1);
});

// The distinction that decides what happens in the next hour.
test("a stealer log is told apart from a leaked table", () => {
  assert.equal(looksLikeStealerRow({ URL: "https://sso.corp.example", Login: "a@corp.example", Password: "x", Machine: "DESKTOP-9F2", OS: "Windows 10" }), true);
  assert.equal(looksLikeStealerRow({ Email: "a@corp.example", Password: "x", FullName: "A", City: "Lyon" }), false);
  assert.equal(looksLikeStealerRow({ Email: "a@corp.example", FullName: "A" }), false);
});

test("and a stealer account is ranked and acted on differently", () => {
  const r = buildDomainReport("corp.example", [
    db("Stealer logs 2025", [{ URL: "https://sso.corp.example", Login: "victim@corp.example", Password: "x", UserAgent: "Mozilla/5.0", Machine: "DESKTOP-9F2" }]),
    db("Newsletter 2019", [{ Email: "quiet@corp.example", FullName: "Quiet" }]),
  ]);
  assert.equal(r.counts.inStealerLogs, 1);
  assert.equal(r.accounts[0].address, "victim@corp.example", "worst first");
  assert.equal(r.accounts[0].severity, "critical");
  // the session, not only the password: a reset does not invalidate a stolen cookie
  assert.ok(r.actions.some((a) => /revoke sessions/i.test(a)), r.actions.join(" | "));
});

test("rows at other domains are counted, never silently dropped", () => {
  const r = buildDomainReport("corp.example", [
    db("Mixed", [
      { Email: "a@corp.example" },
      { Email: "someone@other.example" },
      { Email: "another@other.example" },
    ]),
  ]);
  assert.equal(r.counts.accounts, 1);
  assert.equal(r.excluded, 2);
});

test("a row carrying two of our addresses counts as two accounts", () => {
  const r = buildDomainReport("corp.example", [
    db("A", [{ Email: "a@corp.example", AltEmail: "b@corp.example", Password: "x" }]),
  ]);
  assert.equal(r.counts.accounts, 2);
  assert.equal(r.counts.withPlaintext, 2);
});

test("an empty answer says so instead of looking like a clean bill of health", () => {
  const r = buildDomainReport("corp.example", [db("A", [{ Email: "nobody@other.example" }])]);
  assert.equal(r.counts.accounts, 0);
  assert.match(r.summary, /No account at corp.example appears in the index/);
  assert.match(r.actions[0], /Nothing to do/);
});

test("the databases are listed by how much of the estate each holds", () => {
  const r = buildDomainReport("corp.example", [
    db("Small", [{ Email: "a@corp.example" }]),
    db("Big", [{ Email: "a@corp.example" }, { Email: "b@corp.example" }, { Email: "c@corp.example" }]),
  ]);
  assert.equal(r.databases[0].name, "Big");
  assert.equal(r.databases[0].accounts, 3);
});

test("the report never claims an account is compromised today", () => {
  const r = buildDomainReport("corp.example", [db("A", [{ Email: "a@corp.example", Password: "x" }])]);
  assert.ok(r.actions.some((a) => /historic by definition/i.test(a)), r.actions.join(" | "));
});
