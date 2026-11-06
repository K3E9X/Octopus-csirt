// Sign in, register, sign out. One route, three intents.

import { NextRequest, NextResponse } from "next/server";
import { createUser, verifyUser, countUsers, bootstrapClaimed, signSession, readSession, SESSION_COOKIE, SESSION_MAX_AGE, authEnabled, sessionsUsable, newSid, sessionExpiry } from "@/lib/auth";
import { currentUser } from "@/lib/session-server";
import { seedStarter, balanceOf, balanceCredits, creditsEnabled } from "@/lib/credits";
import { openSession, killSession } from "@/lib/sessions";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function setCookie(res: NextResponse, token: string) {
  res.cookies.set(SESSION_COOKIE, token, {
    httpOnly: true, sameSite: "lax", path: "/",
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_MAX_AGE,
  });
}

/**
 * The address the request came from, as far as it can be known.
 *
 * Behind an ingress this is the forwarded header and nothing else is available. It is
 * recorded so an administrator can see an account open from somewhere nobody
 * recognises; it is NOT treated as identity, because a header a client sends is a
 * header a client chooses.
 */
function clientIp(req: NextRequest): string | undefined {
  const fwd = req.headers.get("x-forwarded-for") || "";
  return fwd.split(",")[0].trim() || req.headers.get("x-real-ip") || undefined;
}

export async function POST(req: NextRequest) {
  if (!authEnabled) {
    return NextResponse.json({ error: "This deployment has no database, so it has no accounts. It runs in single-operator mode and the tool is open." }, { status: 501 });
  }
  if (!sessionsUsable()) {
    return NextResponse.json({ error: "Set OCTOPUS_SESSION_SECRET (16+ characters). Without it sessions cannot be signed, and a shared fallback secret would let any deployment forge another's." }, { status: 501 });
  }
  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "bad request" }, { status: 400 }); }
  const action = String(body?.action || "signin");

  if (action === "signout") {
    // Close the row too. A cookie cleared in one browser with the row left behind
    // leaves a session an administrator can still see as open, which is a list that
    // lies rather than a list.
    const claim = readSession(req.cookies.get(SESSION_COOKIE)?.value);
    if (claim?.sid) await killSession(claim.sid).catch(() => {});
    const res = NextResponse.json({ ok: true });
    res.cookies.set(SESSION_COOKIE, "", { httpOnly: true, path: "/", maxAge: 0 });
    return res;
  }

  const email = String(body?.email || "");
  const password = String(body?.password || "");

  if (action === "register") {
    const r = await createUser(email, password, body?.name ? String(body.name).slice(0, 80) : undefined);
    if (r.error || !r.user) return NextResponse.json({ error: r.error || "could not create the account" }, { status: 400 });
    await seedStarter(r.user.id);   // a welcome balance so the first search needs no admin round-trip
    const res = NextResponse.json({ ok: true, user: r.user, firstAccount: r.user.role === "admin" });
    // The row is what an administrator can delete to cut this one session while the
  // others stay open; the signature alone cannot be taken back.
  { const sid = newSid();
    setCookie(res, signSession(r.user.id, r.user.sessEpoch, sid));
    await openSession(sid, r.user.id, sessionExpiry(), clientIp(req), req.headers.get("user-agent") || undefined).catch(() => {}); }
    return res;
  }

  const user = await verifyUser(email, password);
  // one message for both failures: telling an attacker which half was wrong is free
  // help, and telling a disabled account it is disabled is the same leak
  if (!user) return NextResponse.json({ error: "wrong address or password, or the account is disabled" }, { status: 401 });
  const res = NextResponse.json({ ok: true, user });
  { const sid = newSid();
    setCookie(res, signSession(user.id, user.sessEpoch, sid));
    await openSession(sid, user.id, sessionExpiry(), clientIp(req), req.headers.get("user-agent") || undefined).catch(() => {}); }
  return res;
}

// GET → what the sign-in page needs to render itself honestly
export async function GET() {
  const me = authEnabled ? await currentUser() : null;
  return NextResponse.json({
    authEnabled,
    sessionsUsable: sessionsUsable(),
    // Whether the administrator seat is still open, NOT whether the table is empty.
    // The old answer was both a race and an advertisement: an unauthenticated caller
    // was told, by a freshly deployed instance, that admin was there for the taking.
    // It is now claimed atomically at registration, so this is only ever a hint for
    // the form's wording.
    firstAccount: authEnabled ? !(await bootstrapClaimed()) : false,
    metered: creditsEnabled,
    me: me ? { id: me.id, email: me.email, name: me.name, role: me.role } : null,
    // IN WHOLE CREDITS, which is what every other endpoint returns and what the header
    // renders. This returned micro-dollars, so the balance read "357,150 credits" for an
    // account holding fifty until the first search of the session replaced it with the
    // real figure. Every other display path already converted; this one was the
    // exception, which is why it survived.
    balance: me ? balanceCredits(await balanceOf(me.id)) : undefined,
  });
}
