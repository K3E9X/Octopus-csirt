// Is this process serving, and separately, is everything it depends on reachable.
//
// TWO QUESTIONS, AND KUBERNETES ONLY GETS TO ASK THE FIRST. A liveness probe that fails
// when the database is unreachable restarts the pod, which does not reach the database
// either, so the deployment rolls itself into a crash loop in response to an outage it
// cannot fix and takes down the part that still worked. The default answer here is
// therefore about THIS PROCESS: if it can serve this route it is alive, and it stays
// alive through a database outage, degraded and saying so.
//
// `?deep=1` asks the second question and answers 503 when a dependency is down. That is
// for monitoring and for a human looking at it, never for the kubelet.
//
// It says nothing a stranger could use: which features are configured, not any value
// that configures them.

import { NextRequest, NextResponse } from "next/server";
import { dbEnabled, dbReachable, driverName } from "@/lib/db";
import { auditKeyed } from "@/lib/audit";
import { sourceToken } from "@/lib/sourcekey";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const shallow = {
    ok: true,
    service: "octopus-csirt",
    database: dbEnabled ? driverName() : "none",
    audit: auditKeyed() ? "signed" : "unsigned",
    sessions: (process.env.OCTOPUS_SESSION_SECRET || "").length >= 16 ? "configured" : "missing",
  };

  if (req.nextUrl.searchParams.get("deep") !== "1") return NextResponse.json(shallow);

  const [db, src] = await Promise.all([
    dbEnabled ? dbReachable() : Promise.resolve({ ok: true, driver: "none", error: undefined as string | undefined }),
    sourceToken().catch(() => ({ from: "none" as const })),
  ]);
  return NextResponse.json(
    // WHERE the token came from, never the token. "stored" means an owner pasted one
    // into /admin, "environment" means it is in the pod's env, "none" means searches
    // return nothing and say so.
    { ...shallow, deep: true, dbReachable: db.ok, dbError: db.error, leakSource: src.from },
    { status: db.ok ? 200 : 503 },
  );
}
