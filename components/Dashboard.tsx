"use client";

// The front page, for people who work here.
//
// It used to be the marketing landing: a hero, a demo report, a features grid and a
// pricing-adjacent pitch. That page exists to persuade a stranger, and there are no
// strangers here. Somebody opening this tool at nine in the morning has one of three
// questions, and the page answers them in that order: what am I in the middle of, what
// did I do last, and can I start something now.
//
// WHAT IS NOT ON IT. No counters of total searches, no graph of activity over time, no
// "cases closed this month". A dashboard made of numbers that nobody acts on trains
// people to stop reading it, and the first thing that gets skipped once that happens is
// the one line that mattered. Everything here is either something to pick up or
// something that is wrong.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { OctoMark } from "./OctoMark";

interface CaseRow {
  id: string; ref: string; title: string; status: string;
  openedBy: string; openedAt: number; entities: number; facts: number;
}
interface Data {
  configured: boolean;
  note?: string;
  me?: { email: string; name?: string; role: string };
  metered?: boolean;
  balance?: number | null;
  cases?: CaseRow[];
  recent?: { at: number; selector: string; caseId?: string; kind: string }[];
  chain?: { intact: boolean; checked: number; brokenAt: number | null } | null;
}

const DAY = 86_400_000;
const ago = (t: number) => {
  const d = Math.floor((Date.now() - t) / DAY);
  if (d <= 0) return "today";
  if (d === 1) return "yesterday";
  if (d < 30) return `${d} days ago`;
  return new Date(t).toISOString().slice(0, 10);
};

export default function Dashboard() {
  const router = useRouter();
  const [d, setD] = useState<Data | null>(null);
  const [q, setQ] = useState("");
  const [ref, setRef] = useState("");
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    const r = await fetch("/api/dashboard");
    if (r.status === 401) { router.replace("/signin?next=/"); return; }
    setD(await r.json().catch(() => null));
  }, [router]);
  useEffect(() => { load(); }, [load]);

  async function openCase(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    const r = await fetch("/api/case", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "open", ref: ref.trim(), title: ref.trim() }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return setErr(j?.error || "could not open it");
    router.push(`/cases?id=${encodeURIComponent(j.id)}`);
  }

  if (!d) return <Shell><p className="dsh-off">Loading…</p></Shell>;
  if (!d.configured) return <Shell><p className="dsh-off">{d.note}</p><Link className="dsh-go" href="/search">Open the search</Link></Shell>;

  const cases = d.cases || [];
  // A case nobody has touched in a fortnight is either finished and not closed, or
  // forgotten. Both are worth seeing; neither is worth a notification.
  const stale = cases.filter((c) => Date.now() - c.openedAt > 14 * DAY);
  const noBalance = d.metered && (d.balance ?? 0) <= 0;

  return (
    <Shell me={d.me} balance={d.balance} metered={d.metered}>
      {/* Before anything else: an account nobody has let in yet. Everything below it
          would otherwise read as a tool that is broken rather than one that is waiting. */}
      {d.me?.role === "pending" && (
        <p className="dsh-warn">
          This account is waiting to be approved. Your password works and nothing is
          broken: an owner or an administrator has to let you in before you can search or
          open a case. <Link href="/profile">Your account</Link>
        </p>
      )}

      {/* The two things that stop work, if either is true. */}
      {d.me?.role !== "pending" && noBalance && (
        <p className="dsh-warn">
          No credits. Searches will be refused until an owner grants some.
          {d.me?.role === "owner" && <> <Link href="/admin">Grant them.</Link></>}
        </p>
      )}
      {d.chain && !d.chain.intact && (
        <p className="dsh-warn">
          The audit chain does not verify from entry {d.chain.brokenAt ?? "?"} of {d.chain.checked}.
          Something edited or deleted a row. <Link href="/admin">Look at it.</Link>
        </p>
      )}

      <div className="dsh-start">
        <form onSubmit={(e) => { e.preventDefault(); if (q.trim()) router.push(`/search?q=${encodeURIComponent(q.trim())}`); }}>
          <label htmlFor="dsh-q">Start from a selector</label>
          <div>
            <input id="dsh-q" value={q} onChange={(e) => setQ(e.target.value)}
              placeholder="email, phone, handle, name, or a domain" />
            <button disabled={!q.trim()}>Search</button>
          </div>
        </form>
        <form onSubmit={openCase}>
          <label htmlFor="dsh-ref">Or open a case</label>
          <div>
            <input id="dsh-ref" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="INC-2026-114" />
            <button disabled={!ref.trim()}>Open</button>
          </div>
          {err && <em className="dsh-err">{err}</em>}
        </form>
      </div>

      <section className="dsh-sec">
        <h2>Open cases <em>{cases.length}</em></h2>
        {cases.length === 0 ? (
          <p className="dsh-off">Nothing open. A case is where a lead goes before it is an identity.</p>
        ) : (
          <ul className="dsh-cases">
            {cases.map((c) => (
              <li key={c.id} className={stale.includes(c) ? "stale" : ""}>
                <Link href={`/cases?id=${encodeURIComponent(c.id)}`}>
                  <code>{c.ref}</code>
                  <b>{c.title}</b>
                  <span>{c.entities} selector{c.entities === 1 ? "" : "s"} · {c.facts} pinned</span>
                  <em>{ago(c.openedAt)}{c.openedBy !== d.me?.email ? ` · ${c.openedBy}` : ""}</em>
                </Link>
              </li>
            ))}
          </ul>
        )}
        {stale.length > 0 && (
          <p className="dsh-note">
            {stale.length} of these {stale.length === 1 ? "has" : "have"} been open more than a fortnight.
            Either finished and not closed, or forgotten.
          </p>
        )}
      </section>

      <section className="dsh-sec">
        <h2>What you searched</h2>
        {!d.recent?.length ? (
          <p className="dsh-off">Nothing yet. Your queries are yours to re-read; nobody else&rsquo;s are.</p>
        ) : (
          <ul className="dsh-recent">
            {d.recent.map((r, i) => (
              <li key={i}>
                <button onClick={() => router.push(`/search?q=${encodeURIComponent(r.selector)}${r.caseId ? `&case=${encodeURIComponent(r.caseId)}` : ""}`)}>
                  <code>{r.selector}</code>
                </button>
                {r.caseId && <span className="dsh-case">{r.caseId}</span>}
                <em>{ago(r.at)}</em>
              </li>
            ))}
          </ul>
        )}
      </section>
    </Shell>
  );
}

function Shell({ children, me, balance, metered }: {
  children: React.ReactNode;
  me?: { email: string; name?: string; role: string };
  balance?: number | null;
  metered?: boolean;
}) {
  return (
    <div className="lk2 dsh">
      <header className="lk2-top">
        <Link className="lk2-brand" href="/"><OctoMark size={30} /><span><b>OCTOPUS</b><small>CSIRT</small></span></Link>
        <nav>
          {metered && typeof balance === "number" && (
            <span className={"lk2-bal" + (balance <= 0 ? " empty" : "")} title="one credit is one standard search">
              {balance.toLocaleString("en-US")} credit{balance === 1 ? "" : "s"}
            </span>
          )}
          <Link href="/search">Search</Link>
          <Link href="/cases">Cases</Link>
          {me && (me.role === "owner" || me.role === "admin") && <Link href="/admin">Admin</Link>}
          <Link href="/profile">{me?.name || me?.email?.split("@")[0] || "Account"}</Link>
        </nav>
      </header>
      <main className="dsh-main">
        {me && <p className="dsh-who">{me.name || me.email} · <span>{me.role}</span></p>}
        {children}
      </main>
    </div>
  );
}
