"use client";

// Your own account.
//
// Small on purpose. There is exactly one thing a person can change about themselves
// here, and everything else on the screen is a statement about what they are: the role
// somebody else decided, the balance somebody else granted, the queries they ran. A
// profile page that lets you edit your own role is not a profile page.
//
// IT IS REACHABLE BY A PENDING ACCOUNT, and that is the point of it existing for them:
// somebody who has just registered and cannot do anything needs a screen that says what
// state they are in and that nothing is broken.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { OctoMark } from "./OctoMark";
import { passwordProblem, strength, STRENGTH_LABEL } from "@/lib/pwrule";

interface Me { email: string; name?: string; role: string; createdAt: number; lastSeen?: number | null }

const day = (t?: number | null) => (t ? new Date(t).toISOString().slice(0, 10) : "never");

export default function Profile() {
  const router = useRouter();
  const [d, setD] = useState<any>(null);
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const r = await fetch("/api/profile");
    if (r.status === 401) { router.replace("/signin?next=/profile"); return; }
    setD(await r.json().catch(() => null));
  }, [router]);
  useEffect(() => { load(); }, [load]);

  const problem = next ? passwordProblem(next) : null;
  const s = strength(next);

  async function change(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(""); setMsg("");
    const r = await fetch("/api/profile", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "password", current: cur, next }),
    });
    const j = await r.json().catch(() => ({}));
    setBusy(false);
    if (!r.ok) return setErr(j?.error || "that did not work");
    setMsg(j.note || "changed");
    // Every session is gone, including this one. Sending them to the door immediately
    // is honest; leaving them on a page whose next request will 401 is not.
    setTimeout(() => router.replace("/signin?next=/"), 2200);
  }

  async function signOut() {
    await fetch("/api/auth", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "signout" }),
    });
    router.replace("/signin");
  }

  if (!d) return <Shell onSignOut={signOut}><p className="dsh-off">Loading…</p></Shell>;
  if (!d.configured) return <Shell onSignOut={signOut}><p className="dsh-off">{d.note}</p></Shell>;
  const me: Me = d.me;

  return (
    <Shell me={me} onSignOut={signOut}>
      {me.role === "pending" && (
        <p className="dsh-warn">
          This account is waiting to be approved. Your password works and nothing is
          broken: an owner or an administrator has to let you in before you can search
          or open a case.
        </p>
      )}

      <section className="dsh-sec">
        <h2>Account</h2>
        <dl className="prf-dl">
          <dt>Address</dt><dd><code>{me.email}</code></dd>
          <dt>Name</dt><dd>{me.name || <em>not set</em>}</dd>
          <dt>Role</dt><dd><b>{me.role}</b> <span className="prf-note">decided by an owner, not here</span></dd>
          {d.metered && <><dt>Credits</dt><dd>{d.balance ?? 0} <span className="prf-note">granted by an owner</span></dd></>}
          <dt>Account opened</dt><dd>{day(me.createdAt)}</dd>
          <dt>Last seen</dt><dd>{day(me.lastSeen)}</dd>
        </dl>
      </section>

      <section className="dsh-sec">
        <h2>Change your password</h2>
        <p className="csr-lead">
          Changing it signs out every session, including this one. That is the point: if
          the reason for changing it is that somebody else has the old one, a password
          that left their browser signed in would not have fixed anything.
        </p>
        <form className="prf-form" onSubmit={change}>
          <label htmlFor="p-cur">Current password</label>
          <input id="p-cur" type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" />
          <label htmlFor="p-new">New password</label>
          <input id="p-new" type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
          {next && (
            <p className="prf-strength">
              {problem ? problem : `${STRENGTH_LABEL[s] || ""}`}
            </p>
          )}
          <button disabled={busy || !cur || !next || !!problem}>Change it</button>
        </form>
        {err && <p className="csr-err">{err}</p>}
        {msg && <p className="dsh-warn">{msg}</p>}
      </section>

      {d.recent?.length > 0 && (
        <section className="dsh-sec">
          <h2>Your last queries</h2>
          <ul className="dsh-recent">
            {d.recent.map((r: any, i: number) => (
              <li key={i}><code>{r.selector}</code>{r.caseId && <span className="dsh-case">{r.caseId}</span>}<em>{day(r.at)}</em></li>
            ))}
          </ul>
          <p className="prf-note">Yours alone. Nobody else can read them from here, whatever their role.</p>
        </section>
      )}
    </Shell>
  );
}

function Shell({ children, me, onSignOut }: { children: React.ReactNode; me?: Me; onSignOut: () => void }) {
  const admin = me?.role === "owner" || me?.role === "admin";
  return (
    <div className="lk2">
      <header className="lk2-top">
        <Link className="lk2-brand" href="/"><OctoMark size={30} /><span><b>OCTOPUS</b><small>CSIRT</small></span></Link>
        <nav>
          <Link href="/">Dashboard</Link>
          <Link href="/cases">Cases</Link>
          {admin && <Link href="/admin">Admin</Link>}
          <button className="lk2-link" onClick={onSignOut}>Sign out</button>
        </nav>
      </header>
      <main className="dsh-main">
        <h1 className="csr-h1">Your account</h1>
        {children}
      </main>
    </div>
  );
}
