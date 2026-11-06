import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAgent, describeAgent, agentKey } from "../lib/ua.ts";

const UA = {
  chromeWin11: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  edge: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
  opera: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 OPR/96.0.4693.80",
  yandex: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 YaBrowser/23.1.0 Safari/537.36",
  win7old: "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
  safari: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  iphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
  android: "Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36",
  firefox: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
  curl: "curl/8.4.0",
  python: "python-requests/2.31.0",
  headless: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
};

// EVERY CHROMIUM BROWSER CLAIMS TO BE CHROME, AND SAFARI, AND MOZILLA. The order of
// the checks is the whole correctness of this module, and reversing any two of them
// still produces plausible-looking output, which is how the error would survive.

test("Edge is not Chrome, Opera is not Chrome, Yandex is not Chrome", () => {
  assert.equal(parseAgent(UA.edge).browser, "Edge");
  assert.equal(parseAgent(UA.opera).browser, "Opera");
  assert.equal(parseAgent(UA.yandex).browser, "Yandex Browser");
  // and the one that really is Chrome still is
  assert.equal(parseAgent(UA.chromeWin11).browser, "Chrome");
});

test("Safari is only Safari when nothing more specific claimed the string", () => {
  assert.equal(parseAgent(UA.safari).browser, "Safari");
  assert.equal(parseAgent(UA.safari).os, "macOS");
  // the Chrome string also contains "Safari/537.36" and must not be read as Safari
  assert.notEqual(parseAgent(UA.chromeWin11).browser, "Safari");
});

test("the operating system and its version come back as a person would say them", () => {
  const w = parseAgent(UA.chromeWin11);
  assert.equal(w.os, "Windows");
  assert.equal(w.osVersion, "10 or 11");      // NT 10.0 is both, and saying "10" is a guess
  assert.equal(w.device, "desktop");
  assert.equal(parseAgent(UA.iphone).os, "iOS");
  assert.equal(parseAgent(UA.iphone).device, "mobile");
  assert.equal(parseAgent(UA.android).os, "Android");
  assert.equal(parseAgent(UA.firefox).browser, "Firefox");
});

test("an end-of-life OS is a finding, not trivia", () => {
  const a = parseAgent(UA.win7old);
  assert.equal(a.osVersion, "7");
  assert.ok(a.notes.some((n) => /end of support/i.test(n)), a.notes.join(" / "));
  // and so is a browser years behind: that is the machine a stealer lands on
  assert.ok(a.notes.some((n) => /versions behind/i.test(n)), a.notes.join(" / "));
  assert.ok(parseAgent(UA.android).notes.some((n) => /security updates/i.test(n)));
});

test("a script is not a browser and says so", () => {
  for (const [k, v] of [["curl", UA.curl], ["python", UA.python], ["headless", UA.headless]] as const) {
    const a = parseAgent(v);
    assert.equal(a.automated, true, k);
    assert.equal(a.device, "server", k);
  }
});

test("a missing or unreadable agent never invents an OS", () => {
  assert.equal(parseAgent("").os, undefined);
  assert.equal(parseAgent("").device, "unknown");
  const junk = parseAgent("????");
  assert.equal(junk.os, undefined);
  assert.equal(junk.browser, undefined);
  assert.ok(junk.notes.length > 0, "it should say it could not read it");
});

test("the correlation key is coarse: one machine a week apart is still one machine", () => {
  const a = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36";
  const b = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36";
  assert.equal(agentKey(parseAgent(a)), agentKey(parseAgent(b)));
  // but a different major version is a different build and should not merge
  assert.notEqual(agentKey(parseAgent(a)), agentKey(parseAgent(UA.win7old)));
  assert.equal(agentKey(parseAgent("")), "");
});

test("the one-line description reads like a sentence", () => {
  assert.equal(describeAgent(parseAgent(UA.edge)), "Edge 124 on Windows 10 or 11");
  assert.equal(describeAgent(parseAgent("")), "no agent");
});
