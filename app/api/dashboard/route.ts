// Everything the front page needs, in one round trip.
//
// The dashboard wants open cases, the operator's own recent queries, their balance and,
// for an administrator, whether the audit chain still verifies. Four endpoints already
// answer four of those, and the page could call all four. It does not, for a reason
// that is about the screen rather than the network: four independent fetches means four
// independent moments of arrival, and a dashboard that assembles itself in front of
// somebody is a dashboard they cannot read until it stops moving.
//
// Nothing here widens any existing gate. The history filters on the SESSION, exactly as
// /api/history does, and the chain verdict is withheld from anyone below admin.

import { NextResponse } from "next/server";
import { currentUser, authEnabled } from "@/lib/session-server";
import { isAtLeast } from "@/lib/auth";
import { balanceOf, creditsEnabled, CREDIT_MICRO } from "@/lib/credits";
import { listCaseFiles, casesEnabled } from "@/lib/casestore";
import { listAudit, verifyAuditChain, auditEnabled } from "@/lib/audit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  if (!authEnabled) {
    return NextResponse.json({
      configured: false,
      note: "No database, so there are no accounts and nothing to file. The search still works, unmetered and unlogged, which is fine for one operator and not fine for a team.",
    });
  }
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "Sign in.", needsAuth: true }, { status: 401 });

  const admin = isAtLeast(user.role, "admin");
  const [cases, recent, micro, chain] = await Promise.all([
    casesEnabled ? listCaseFiles("open") : Promise.resolve([]),
    auditEnabled ? listAudit(8, { operator: user.email }) : Promise.resolve([]),
    creditsEnabled ? balanceOf(user.id) : Promise.resolve(0),
    // Oversight, and only for the people who hold it. A hunter being told the chain is
    // broken is being told something they cannot act on about other people's queries.
    admin && auditEnabled ? verifyAuditChain(2000).catch(() => null) : Promise.resolve(null),
  ]);

  return NextResponse.json({
    configured: true,
    me: { email: user.email, name: user.name, role: user.role },
    metered: creditsEnabled,
    balance: creditsEnabled ? Math.floor(micro / CREDIT_MICRO) : null,
    cases,
    // the selector and the case, never the hash or the chain position: that is
    // oversight's business and this is the operator's own view
    recent: recent.map((e: { at: number; selector: string; caseId?: string; kind: string }) => ({ at: e.at, selector: e.selector, caseId: e.caseId, kind: e.kind })),
    chain: chain ? { intact: chain.intact, checked: chain.checked, brokenAt: chain.brokenAt ?? null } : null,
  });
}
