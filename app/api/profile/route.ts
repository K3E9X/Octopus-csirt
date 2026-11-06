// Your own account: what it is, and the one thing you can change about it.
//
// Separate from /api/admin on purpose. That endpoint is about OTHER people and is gated
// on rank; this one is about yourself and is gated on being signed in, because every
// account holder has to be able to see what they are and rotate their own password
// without asking anybody. A pending account can reach it too: being told "you are
// waiting for approval" is exactly what somebody in that state needs to see.
//
// It cannot change a role, a balance, or anybody else's anything. Those are decisions
// made about you, not by you, and putting them behind the same endpoint is how a
// self-service form becomes a privilege escalation.

import { NextRequest, NextResponse } from "next/server";
import { currentUser, authEnabled } from "@/lib/session-server";
import { changePassword } from "@/lib/auth";
import { balanceOf, balanceCredits, creditsEnabled } from "@/lib/credits";
import { listAudit, auditEnabled } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  if (!authEnabled) return NextResponse.json({ configured: false, note: "No database, so there are no accounts." });
  const me = await currentUser();
  if (!me) return NextResponse.json({ error: "Sign in.", needsAuth: true }, { status: 401 });

  const [micro, recent] = await Promise.all([
    creditsEnabled ? balanceOf(me.id) : Promise.resolve(0),
    auditEnabled ? listAudit(5, { operator: me.email }) : Promise.resolve([]),
  ]);

  return NextResponse.json({
    configured: true,
    me: { email: me.email, name: me.name, role: me.role, createdAt: me.createdAt, lastSeen: (me as any).lastSeen ?? null },
    metered: creditsEnabled,
    balance: creditsEnabled ? balanceCredits(micro) : null,
    // their own last few queries, so "what have I been doing" does not need the audit
    // screen, which is oversight and is not theirs
    recent: recent.map((e: { at: number; selector: string; caseId?: string }) => ({ at: e.at, selector: e.selector, caseId: e.caseId })),
  });
}

export async function POST(req: NextRequest) {
  if (!authEnabled) return NextResponse.json({ error: "no database" }, { status: 400 });
  const me = await currentUser();
  if (!me) return NextResponse.json({ error: "Sign in.", needsAuth: true }, { status: 401 });

  const body = await req.json().catch(() => ({} as any));
  if (body?.action !== "password") return NextResponse.json({ error: "unknown action" }, { status: 400 });

  const r = await changePassword(me.id, String(body?.current || ""), String(body?.next || ""));
  if (!r.ok) return NextResponse.json({ error: r.error }, { status: 400 });

  // Every other session is now dead. The cookie carries the account's session
  // generation and the change moved it, so a cookie issued under the old password is
  // refused on its next request, in every browser. That is the reason most people
  // change a password, and a form that quietly did not do it would be worse than one
  // that refused to.
  //
  // Including this browser: the caller is signed out too and has to sign in again,
  // which is the honest outcome rather than a special case carved out for whoever
  // happened to submit the form.
  return NextResponse.json({
    ok: true,
    note: "Password changed. Every session is signed out, including this one. Sign in again.",
    signedOut: true,
  });
}
