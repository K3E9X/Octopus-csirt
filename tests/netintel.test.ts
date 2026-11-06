import { test } from "node:test";
import assert from "node:assert/strict";
import { netFact, clusterByNetwork } from "../lib/netintel.ts";

test("a public address is worth correlating on; a NAT range is not", () => {
  assert.equal(netFact("92.184.104.57").weight, "strong");
  // RFC 6598. Thousands of subscribers hold one of these at a time, so two accounts
  // seen on the same one is not two accounts belonging to one person.
  const cg = netFact("100.70.12.9");
  assert.equal(cg.kind, "cgnat");
  assert.equal(cg.weight, "weak");
  assert.match(cg.note!, /Carrier-grade NAT/);
});

test("private, loopback, link-local and documentation ranges are told apart", () => {
  assert.equal(netFact("10.1.2.3").kind, "private");
  assert.equal(netFact("172.16.0.1").kind, "private");
  assert.equal(netFact("172.32.0.1").kind, "public-v4");   // just outside 172.16/12
  assert.equal(netFact("192.168.1.1").kind, "private");
  assert.equal(netFact("127.0.0.1").kind, "loopback");
  assert.equal(netFact("169.254.1.1").kind, "link-local");
  assert.equal(netFact("192.0.2.5").kind, "documentation");
  assert.equal(netFact("203.0.113.9").kind, "documentation");
  assert.equal(netFact("224.0.0.1").kind, "multicast");
});

test("an octet over 255 is not an address, however much it looks like one", () => {
  assert.equal(netFact("999.1.1.1").kind, "invalid");
  assert.equal(netFact("256.0.0.1").kind, "invalid");
  assert.equal(netFact("not an ip").kind, "invalid");
  assert.equal(netFact("").kind, "invalid");
});

test("IPv6 is recognised, and its special ranges too", () => {
  assert.equal(netFact("2a01:cb00:1234::1").kind, "public-v6");
  assert.equal(netFact("::1").kind, "loopback");
  assert.equal(netFact("fe80::1").kind, "link-local");
  assert.equal(netFact("fd00::1").kind, "private");
  assert.equal(netFact("2001:db8::1").kind, "documentation");
});

test("the block is the neighbourhood two addresses would share", () => {
  assert.equal(netFact("92.184.104.57").block, "92.184.104.0/24");
  assert.equal(netFact("2a01:cb00:1234:5678::1").block, "2a01:cb00:1234::/48");
});

// THE POINT OF THE MODULE: sharing an address and sharing an allocation are different
// claims, and a product that folds them into one "related" score has invented a
// confidence nobody computed.

test("identities on one address cluster; identities merely nearby are kept separate", () => {
  const { exact, blocks } = clusterByNetwork([
    { value: "92.184.104.57", owner: "alpha@example.com" },
    { value: "92.184.104.57", owner: "beta@example.com" },
    { value: "92.184.104.90", owner: "gamma@example.com" },
  ]);
  assert.equal(exact.length, 1);
  assert.deepEqual(exact[0].members, ["alpha@example.com", "beta@example.com"]);
  assert.equal(exact[0].exact, true);
  // gamma is in the same /24 and must appear as a neighbourhood, never as a link
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].key, "92.184.104.0/24");
  assert.equal(blocks[0].members.length, 3);
  assert.equal(blocks[0].weight, "weak");
});

test("a block that adds nothing over the exact match it contains is dropped", () => {
  const { exact, blocks } = clusterByNetwork([
    { value: "92.184.104.57", owner: "a" },
    { value: "92.184.104.57", owner: "b" },
  ]);
  assert.equal(exact.length, 1);
  assert.deepEqual(blocks, []);
});

test("one identity on an address is not a cluster", () => {
  const { exact, blocks } = clusterByNetwork([
    { value: "92.184.104.57", owner: "a" },
    { value: "8.8.8.8", owner: "b" },
  ]);
  assert.deepEqual(exact, []);
  assert.deepEqual(blocks, []);
});

test("addresses that cannot correlate never form a cluster at all", () => {
  const { exact, blocks } = clusterByNetwork([
    { value: "127.0.0.1", owner: "a" },
    { value: "127.0.0.1", owner: "b" },
    { value: "192.0.2.1", owner: "c" },
    { value: "192.0.2.1", owner: "d" },
  ]);
  assert.deepEqual(exact, [], "loopback and documentation ranges are not evidence");
  assert.deepEqual(blocks, []);
});
