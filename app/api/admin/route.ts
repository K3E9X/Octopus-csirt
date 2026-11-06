// The administration surface. Every handler re-checks the caller's role: a UI that
// hides a button is not access control.

import { NextRequest, NextResponse } from "next/server";
import { listUsers, setRole, adminGrantCap, outranks, deleteUser, revokeSessions, getUser, type Role } from "@/lib/auth";
import { listCache, dropCache, dropCacheFor, cacheHours, cacheEnabled } from "@/lib/searchcache";
import { purgeAuditBefore } from "@/lib/audit";
import { listSessions, killSession, killAllSessions } from "@/lib/sessions";
import { requireAdmin, requireOwner, authEnabled } from "@/lib/session-server";
import { listAudit, verifyAuditChain, auditEnabled } from "@/lib/audit";
import { grant, balanceOf, ledgerOf, creditsToMicro, balanceCredits, creditsEnabled, trialNote } from "@/lib/credits";
import { sourceFingerprint, setSourceToken, clearSourceToken, sourceToken, storedKeyAvailable } from "@/lib/sourcekey";
import { leakOsint, estimateCost, formatCost } from "@/lib/leakosint";
import { dbReachable } from "@/lib/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  if (!authEnabled) return NextResponse.json({ configured: false });
  const caller = await requireAdmin();
  if (!caller) return NextResponse.json({ error: "administrator only" }, { status: 403 });
  const [users, activity, chain, source] = await Promise.all([
    listUsers(),
    auditEnabled ? listAudit(60) : Promise.resolve([]),
    auditEnabled ? verifyAuditChain() : Promise.resolve(null),
    // a FINGERPRINT, never the token: an admin screen that re-displays a secret is a
    // secret that leaks through a screenshot or a support ticket
    sourceFingerprint(),
  ]);
  // A connection string is a configuration, not a connection, and this screen is
  // exactly where that difference should be visible rather than inferred from a page
  // that half-loads.
  const database = await dbReachable();
  // balance per user, so the admin sees who is low without clicking into each
  const withBalance = creditsEnabled
    ? await Promise.all(users.map(async (u) => ({ ...u, credits: balanceCredits(await balanceOf(u.id)) })))
    : users;
  return NextResponse.json({
    configured: true, metered: creditsEnabled, users: withBalance, activity, chain,
    cache: cacheEnabled ? await listCache(60) : [], cacheHours: cacheHours(),
    sessions: await listSessions().catch(() => []),
    source, storable: storedKeyAvailable, database, trial: creditsEnabled ? trialNote() : "",
    // what THIS caller is allowed to do, so the screen offers nothing it cannot deliver
    me: { id: caller.id, role: caller.role },
    build: process.env.OCTOPUS_BUILD || "unknown",
    grantCap: adminGrantCap(),
  });
}

export async function POST(req: NextRequest) {
  if (!authEnabled) return NextResponse.json({ configured: false }, { status: 501 });
  const admin = await requireAdmin();
  if (!admin) return NextResponse.json({ error: "administrator only" }, { status: 403 });
  const body = await req.json().catch(() => null);
  const id = String(body?.id || "");

  // ---- cutting access, and removing an account -------------------------------------
  // A leaver, a laptop left on a train, a password somebody else has seen: the account
  // has to stop working NOW, and its queries have to stay in the audit trail. Those are
  // two different actions and they are kept apart.

  // ---- the kept answers --------------------------------------------------------
  // Visible and emptiable, because a store of other people's breach data that nobody
  // can see the contents of is the thing this product spends its time arguing against.
  // Retention on the trail. OWNER ONLY, and only from the beginning: removing a row
  // from the middle is the one thing a hash-chained log exists to make impossible, and
  // the only reason to want it is to remove a specific query somebody ran.
  if (body?.action === "audit-purge") {
    if (!(await requireOwner())) return NextResponse.json({ error: "owner only" }, { status: 403 });
    const days = Math.max(1, Math.floor(Number(body?.days) || 0));
    if (!days) return NextResponse.json({ error: "how many days should be kept?" }, { status: 400 });
    const r = await purgeAuditBefore(Date.now() - days * 86400000, admin.email);
    if (!r.ok) return NextResponse.json({ error: r.error || "could not purge" }, { status: 500 });
    return NextResponse.json({
      ok: true, removed: r.removed,
      note: `${r.removed} entr${r.removed === 1 ? "y" : "ies"} older than ${days} days removed. The purge itself is in the trail, and the chain verifies from the cut forward.`,
    });
  }

  if (body?.action === "cache-drop") {
    const n = body?.key ? await dropCache(String(body.key))
      : body?.selector ? await dropCacheFor(String(body.selector))
      : await dropCache();
    return NextResponse.json({ ok: true, dropped: n, note: `${n} kept answer${n === 1 ? "" : "s"} deleted. The audit trail is untouched.` });
  }

  if (body?.action === "revoke") {
    const target = await getUser(id);
    if (!target) return NextResponse.json({ error: "no such account" }, { status: 404 });
    if (target.id !== admin.id && !outranks(admin.role, target.role)) {
      return NextResponse.json({ error: `a ${admin.role} cannot act on a ${target.role}` }, { status: 403 });
    }
    // Both halves. The epoch is what makes a cookie stop being accepted; the rows are
    // what the list is drawn from, and leaving them behind would show sessions as open
    // that nothing will honour.
    const n = await killAllSessions(id);
    await revokeSessions(id);
    return NextResponse.json({ ok: true, note: `Signed out of ${n} session${n === 1 ? "" : "s"}. Any cookie for that account is refused from now on.` });
  }

  // Cutting ONE session and leaving the others open, which is the reason the rows
  // exist at all: an account open from somewhere nobody recognises does not justify
  // locking the person out of their own desk.
  if (body?.action === "session-kill") {
    const sid = String(body?.sid || "");
    const all = await listSessions();
    const row = all.find((x) => x.sid === sid);
    if (!row) return NextResponse.json({ error: "no such session" }, { status: 404 });
    const target = await getUser(row.userId);
    if (target && target.id !== admin.id && !outranks(admin.role, target.role)) {
      return NextResponse.json({ error: `a ${admin.role} cannot act on a ${target.role}` }, { status: 403 });
    }
    await killSession(sid);
    return NextResponse.json({ ok: true, note: "That session is signed out. The others stay open." });
  }

  if (body?.action === "delete") {
    if (id === admin.id) return NextResponse.json({ error: "you cannot remove your own account" }, { status: 400 });
    const r = await deleteUser(id, admin.role);
    if (!r.ok) return NextResponse.json({ error: r.error }, { status: 403 });
    // Said back rather than left to be assumed: the trail outlives the account.
    return NextResponse.json({ ok: true, note: "Account removed. Its queries stay in the audit trail and its pinned facts stay in their cases." });
  }

  // ---- the source token ------------------------------------------------------------
  // Stored once by an administrator and used by every search on the deployment, so
  // changing it is a paste rather than a redeploy. The value is never echoed back.

  if (body?.action === "source-set") {
    // The token spends the upstream balance; only whoever pays it holds it.
    if (!(await requireOwner())) return NextResponse.json({ error: "owner only" }, { status: 403 });
    const r = await setSourceToken(String(body?.token || ""), admin.email);
    if (!r.ok) return NextResponse.json({ error: r.error }, { status: 400 });
    return NextResponse.json({ ok: true, source: await sourceFingerprint() });
  }

  if (body?.action === "source-clear") {
    // The token spends the upstream balance; only whoever pays it holds it.
    if (!(await requireOwner())) return NextResponse.json({ error: "owner only" }, { status: 403 });
    const r = await clearSourceToken();
    if (!r.ok) return NextResponse.json({ error: r.error }, { status: 400 });
    return NextResponse.json({ ok: true, source: await sourceFingerprint() });
  }

  /**
   * Prove the token works, by using it.
   *
   * There is no free way to do this. A malformed request would be free and is exactly
   * what must not be sent: the endpoint answers repeated invalid data by blocking the
   * caller's IP for ~30 seconds, which would take the whole deployment down rather than
   * test anything. So the check is one real, well-formed query at the minimum limit, * about $0.003, and the UI says so before the button is pressed.
   *
   * The term is a fixed, deliberately meaningless string: it has to be a valid query,
   * and it must not be anybody's identifier.
   */
  if (body?.action === "source-test") {
    // The token spends the upstream balance; only whoever pays it holds it.
    if (!(await requireOwner())) return NextResponse.json({ error: "owner only" }, { status: 403 });
    const { token, from } = await sourceToken();
    if (!token) return NextResponse.json({ error: "no token is configured to test" }, { status: 400 });
    const term = "octopusleak-connectivity-probe";
    const cost = estimateCost(term, 100);
    try {
      const res = await leakOsint({ token, request: term, limit: 100, lang: "en", timeoutMs: 20000 });
      if (res.error) {
        return NextResponse.json({ ok: false, from, spent: formatCost(0), reason: res.error });
      }
      // The query ran. Whether it matched anything is irrelevant, reaching the index
      // at all is the entire question a connectivity test asks.
      return NextResponse.json({
        ok: true, from, spent: formatCost(cost),
        detail: `The index answered. ${res.databases.length} database(s) matched the probe term, which is expected to be none.`,
      });
    } catch {
      return NextResponse.json({ ok: false, from, spent: formatCost(0), reason: "the endpoint could not be reached" });
    }
  }

  // ---- balances --------------------------------------------------------------------
  // Granted in CREDITS, one credit, one search. Dollars were never the unit anybody
  // administering this thinks in: the question is "how many more searches should they
  // get", and the answer should be the number you type. Negative claws back.
  if (body?.action === "grant") {
    if (!creditsEnabled) return NextResponse.json({ error: "no database, the tool runs unmetered" }, { status: 400 });
    const n = Math.trunc(Number(body?.credits ?? body?.usd));
    if (!id || !Number.isFinite(n) || n === 0) {
      return NextResponse.json({ error: "a user and a non-zero whole number of credits are required" }, { status: 400 });
    }

    // Creating credit is spending the upstream balance, so it is the owner's power.
    // An admin may pass some on, to SOMEBODY ELSE, and only up to a bound. An
    // administrator who can top up their own account is an audit trail that proves
    // nothing, because the same hand signs the spending and the budget.
    if (admin.role !== "owner") {
      if (id === admin.id) {
        return NextResponse.json({ error: "an administrator cannot credit their own account. Ask an owner." }, { status: 403 });
      }
      const cap = adminGrantCap();
      if (Math.abs(n) > cap) {
        return NextResponse.json({ error: `an administrator may move at most ${cap} credits at a time. Ask an owner.`, cap }, { status: 403 });
      }
    }

    const r = await grant(id, creditsToMicro(n), `${admin.role} ${n > 0 ? "grant" : "clawback"} of ${Math.abs(n)} credit(s) by ${admin.email}`);
    if (!r.ok) return NextResponse.json({ error: r.error }, { status: 400 });
    return NextResponse.json({ ok: true, balance: balanceCredits(r.balance ?? 0) });
  }

  if (body?.action === "ledger") {
    if (!id) return NextResponse.json({ error: "a user is required" }, { status: 400 });
    return NextResponse.json({ ok: true, ledger: await ledgerOf(id) });
  }

  const role = String(body?.role || "") as Role;
  if (!id || !["owner", "admin", "hunter", "pending", "disabled"].includes(role)) {
    return NextResponse.json({ error: "id and a valid role are required" }, { status: 400 });
  }
  // Seniority is enforced in setRole, which knows who is asking, nobody may act on a
  // role at or above their own, in either direction.
  const r = await setRole(id, role, admin);
  if (!r.ok) return NextResponse.json({ error: r.error }, { status: 400 });
  return NextResponse.json({ ok: true });
}
