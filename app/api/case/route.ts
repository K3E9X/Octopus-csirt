// Cases: the hunter's own working file, and the board built from it.
//
// WHO MAY SEE WHAT, decided here and not in the interface. A CSIRT case is shared work
// by design, so any signed-in hunter can read and contribute to any open case: the
// alternative is four people investigating one incident in four private files, which
// is how the correlation that mattered gets missed. What stays attributable is every
// individual act, because the row carries who did it.
//
// Two things a hunter may NOT do, and both are deliberate. Closing a case is an
// administrator's act, because a closed case is a statement that the incident is
// finished. And removing a selector takes its pinned facts with it, so it belongs to
// whoever owns the case rather than to anyone who can reach the endpoint.

import { NextRequest, NextResponse } from "next/server";
import { currentUser, authEnabled } from "@/lib/session-server";
import { isAtLeast } from "@/lib/auth";
import {
  casesEnabled, listCaseFiles, openCase, readCase, caseByRef, entityFor, deleteCase,
  addEntity, pinFact, unpinFact, removeEntity, setCaseStatus,
} from "@/lib/casestore";
import { buildBoard, testFact, type EntityKind } from "@/lib/casework";
import { caseToCSV, caseToJSON, caseExportName } from "@/lib/export";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const KINDS: EntityKind[] = ["email", "phone", "username", "name", "ip", "machine", "domain", "other"];
const SEVERITIES = ["critical", "high", "medium", "low"];

const off = () =>
  NextResponse.json({
    configured: false,
    note: "Cases need a database. Set POSTGRES_URL. Without one the tool still searches, but nothing can be filed.",
    cases: [],
  });

export async function GET(req: NextRequest) {
  if (!authEnabled || !casesEnabled) return off();
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "Sign in to open a case.", needsAuth: true }, { status: 401 });

  const cid = req.nextUrl.searchParams.get("id");
  if (!cid) {
    const status = req.nextUrl.searchParams.get("status");
    const cases = await listCaseFiles(status === "open" || status === "closed" ? status : undefined);
    return NextResponse.json({ configured: true, cases });
  }

  const found = await readCase(cid);
  if (!found) return NextResponse.json({ error: "No such case." }, { status: 404 });

  // ---- out of the tool ----
  // A case file that cannot leave is not an incident record. Served as a download
  // rather than as JSON the interface has to turn into a file, so the filename and the
  // content type come from the server and a responder gets something they can attach.
  const format = req.nextUrl.searchParams.get("format");
  if (format === "csv" || format === "json") {
    const board = buildBoard(found.entities, found.facts);
    const body = format === "csv"
      ? caseToCSV(found.file, found.entities, found.facts)
      : caseToJSON(found.file, found.entities, found.facts, board, user.email);
    return new NextResponse(body, {
      headers: {
        "content-type": format === "csv" ? "text/csv; charset=utf-8" : "application/json; charset=utf-8",
        "content-disposition": `attachment; filename="${caseExportName(found.file, format)}"`,
        // an export is a point in time and must never be served from a cache
        "cache-control": "no-store",
      },
    });
  }

  // The board is derived on read, never stored. A cached board that disagreed with the
  // facts under it would be worse than no board, and that is what a cache becomes the
  // first time somebody unpins something.
  const board = buildBoard(found.entities, found.facts);
  return NextResponse.json({ configured: true, ...found, board });
}

export async function POST(req: NextRequest) {
  if (!authEnabled || !casesEnabled) return off();
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "Sign in to work a case.", needsAuth: true }, { status: 401 });
  if (!isAtLeast(user.role, "hunter")) {
    return NextResponse.json({ error: "This account is disabled." }, { status: 403 });
  }

  const body = await req.json().catch(() => ({} as any));
  const action = String(body?.action || "");
  const cid = String(body?.caseId || "");

  // ---- pinning straight off a report ----
  // Addressed by REFERENCE, not id: that is the string the hunter typed into "file
  // under" and the one they have in front of them. The selector the report is about
  // becomes an entity if it is not one yet, because making somebody add it by hand
  // before they can pin the first thing they found on it is how a feature goes unused.
  if (action === "pin-ref") {
    const ref = String(body?.ref || "").trim();
    if (!ref) return NextResponse.json({ error: "no case reference" }, { status: 400 });
    const file = await caseByRef(ref);
    // No silent creation. A typo would quietly open a case and file evidence into it,
    // and nobody would find it again; the interface offers to create it instead.
    if (!file) return NextResponse.json({ error: `No case answers to ${ref}.`, canCreate: true }, { status: 404 });
    if (file.status === "closed") return NextResponse.json({ error: `${ref} is closed. Reopen it first.` }, { status: 409 });

    const kind = KINDS.includes(body?.subjectKind) ? (body.subjectKind as EntityKind) : "other";
    const eid = await entityFor(file.id, kind, String(body?.subject || ""), String(body?.subjectLabel || ""), user.email);
    if (!eid) return NextResponse.json({ error: "could not file that selector" }, { status: 400 });

    const sev = SEVERITIES.includes(body?.severity) ? body.severity : "medium";
    const r = await pinFact(file.id, {
      entityId: eid,
      category: String(body?.category || "other"),
      severity: sev,
      label: String(body?.label || "value"),
      value: String(body?.value || ""),
      source: String(body?.source || "unstated"),
      addedBy: user.email,
    });
    // Already pinned is not a failure the hunter needs to see as one: the fact is in
    // the case, which is what they asked for.
    return NextResponse.json({ ok: true, caseId: file.id, ref, already: !r.ok });
  }

  if (action === "open") {
    const r = await openCase(String(body?.ref || ""), String(body?.title || ""), user.email);
    return r.ok ? NextResponse.json(r) : NextResponse.json({ error: r.error }, { status: 400 });
  }

  if (!cid) return NextResponse.json({ error: "which case?" }, { status: 400 });
  const found = await readCase(cid);
  if (!found) return NextResponse.json({ error: "No such case." }, { status: 404 });
  if (found.file.status === "closed" && action !== "reopen" && action !== "delete-case") {
    return NextResponse.json({ error: "That case is closed. Reopen it first." }, { status: 409 });
  }

  switch (action) {
    case "entity": {
      const kind = KINDS.includes(body?.kind) ? (body.kind as EntityKind) : "other";
      const r = await addEntity(cid, kind, String(body?.value || ""), String(body?.label || ""), user.email);
      return r.ok ? NextResponse.json(r) : NextResponse.json({ error: r.error }, { status: 400 });
    }
    case "pin": {
      const entityId = String(body?.entityId || "");
      if (!found.entities.some((e) => e.id === entityId)) {
        return NextResponse.json({ error: "That selector is not in this case." }, { status: 400 });
      }
      const sev = SEVERITIES.includes(body?.severity) ? body.severity : "medium";
      const r = await pinFact(cid, {
        entityId,
        category: String(body?.category || "other"),
        severity: sev,
        label: String(body?.label || "value"),
        value: String(body?.value || ""),
        source: String(body?.source || "unstated"),
        note: body?.note ? String(body.note) : undefined,
        addedBy: user.email,
      });
      return r.ok ? NextResponse.json(r) : NextResponse.json({ error: r.error }, { status: 409 });
    }
    case "unpin":
      await unpinFact(cid, String(body?.factId || ""));
      return NextResponse.json({ ok: true });
    case "remove-entity": {
      // takes its facts with it, so it is the case owner's call or an administrator's
      if (found.file.openedBy !== user.email && !isAtLeast(user.role, "admin")) {
        return NextResponse.json({ error: "Only the case owner or an administrator can remove a selector." }, { status: 403 });
      }
      await removeEntity(cid, String(body?.entityId || ""));
      return NextResponse.json({ ok: true });
    }
    case "test": {
      // the counterfactual: what the case looks like if one pinned fact is wrong
      const r = testFact(found.entities, found.facts, String(body?.value || ""), String(body?.category || "other"));
      return NextResponse.json({ ok: true, ...r });
    }
    case "delete-case": {
      // Whoever opened it, or an administrator. A case is shared work, and shared work
      // that anybody can delete is work nobody will put in it.
      if (found.file.openedBy !== user.email && !isAtLeast(user.role, "admin")) {
        return NextResponse.json({ error: "Only whoever opened this case, or an administrator, can remove it." }, { status: 403 });
      }
      const r = await deleteCase(cid);
      return NextResponse.json({
        ok: r.ok,
        note: `Case removed with ${r.entities} selector${r.entities === 1 ? "" : "s"} and ${r.facts} pinned fact${r.facts === 1 ? "" : "s"}. The queries filed under it stay in the audit trail.`,
      });
    }
    case "close":
    case "reopen": {
      if (!isAtLeast(user.role, "admin")) {
        return NextResponse.json({ error: "Closing a case is an administrator's call." }, { status: 403 });
      }
      await setCaseStatus(cid, action === "close" ? "closed" : "open", body?.note ? String(body.note) : undefined);
      return NextResponse.json({ ok: true });
    }
  }
  return NextResponse.json({ error: "unknown action" }, { status: 400 });
}
