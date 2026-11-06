"use client";

// The case screen: the lead, what has been pinned to it, and what that says together.
//
// A hunt does not start as an identity. It starts as a stealer log, an insider's
// corporate address, an IP out of a proxy line. The hunter searches that, finds a
// second selector inside the results, pins what matters, searches that, and keeps going
// until the thing either closes into one person or splits into two. This screen is that
// loop: the selectors on the left, the correlation in the middle, and a list of what the
// case is still missing at the top, because the gap is more useful than the summary.
//
// THE GRAPH IS THE REPORT'S GRAPH. The same component the Orbit view uses, fed
// selectors instead of databases. That is not thrift: it means a line on a case board
// and a line in a report are the same claim, computed by the same code, and that "pull
// a thread" works here too. Two implementations of "what counts as a connection" would
// drift, and the first anyone would know about it is two screens disagreeing in front
// of somebody who has to decide something.

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import dynamic from "next/dynamic";
import { OctoMark } from "./OctoMark";
import { parseAgent, describeAgent } from "@/lib/ua";
import type { CaseFile, CaseEntity, CaseFact, Board, EntityKind } from "@/lib/casework";

const LeakOrbit = dynamic(() => import("./LeakOrbit"), { ssr: false });

const KINDS: EntityKind[] = ["email", "phone", "username", "name", "ip", "machine", "domain", "other"];

const CATEGORIES = [
  "password", "financial", "document", "identity", "location",
  "email", "phone", "online", "professional", "ip", "other",
];

const when = (t?: number) => (t ? new Date(t).toISOString().slice(0, 10) : "date unknown");

interface Loaded {
  file: CaseFile;
  entities: CaseEntity[];
  facts: CaseFact[];
  board: Board;
}

export default function Cases({ initialId }: { initialId?: string }) {
  const [me, setMe] = useState<{ email: string; role: string } | null>(null);
  useEffect(() => { fetch("/api/dashboard").then((r) => r.json()).then((d) => setMe(d?.me || null)).catch(() => {}); }, []);
  const [list, setList] = useState<(CaseFile & { entities: number; facts: number })[] | null>(null);
  const [configured, setConfigured] = useState(true);
  const [note, setNote] = useState("");
  const [open, setOpen] = useState<string | null>(initialId || null);
  const [data, setData] = useState<Loaded | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const loadList = useCallback(async () => {
    const r = await fetch("/api/case").then((x) => x.json()).catch(() => null);
    if (!r) return setErr("network unavailable");
    setConfigured(!!r.configured);
    setNote(r.note || "");
    setList(r.cases || []);
  }, []);

  const loadCase = useCallback(async (id: string) => {
    setErr("");
    const r = await fetch(`/api/case?id=${encodeURIComponent(id)}`).then((x) => x.json()).catch(() => null);
    if (!r || r.error) return setErr(r?.error || "could not read the case");
    setData(r);
  }, []);

  useEffect(() => { loadList(); }, [loadList]);
  useEffect(() => { if (open) loadCase(open); else setData(null); }, [open, loadCase]);

  const post = useCallback(async (body: Record<string, unknown>) => {
    setBusy(true); setErr("");
    const r = await fetch("/api/case", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const d = await r.json().catch(() => ({}));
    setBusy(false);
    if (!r.ok) { setErr(d?.error || "that did not work"); return null; }
    return d;
  }, []);

  return (
    <div className="lk2 csr">
      <header className="lk2-top">
        <Link className="lk2-brand" href="/"><OctoMark size={30} /><span><b>OCTOPUS</b><small>CSIRT</small></span></Link>
        <nav>
          <Link href="/">Dashboard</Link>
          <Link href="/search">Search</Link>
          {/* Offered only to somebody it will not refuse. A link that bounces you is
              indistinguishable from an account that does not work. */}
          {(me?.role === "owner" || me?.role === "admin") && <Link href="/admin">Admin</Link>}<Link href="/profile">Account</Link>
        </nav>
      </header>

      <main className="csr-main">
        {!configured && <p className="csr-off">{note}</p>}
        {err && <p className="csr-err">{err}</p>}

        {!open ? (
          <CaseList list={list} onOpen={setOpen} onNew={async (ref, title) => {
            const d = await post({ action: "open", ref, title });
            if (d?.id) { await loadList(); setOpen(d.id); }
          }} busy={busy} />
        ) : !data ? (
          <p className="csr-off">Reading the case…</p>
        ) : (
          <CaseBoard
            data={data}
            busy={busy}
            back={() => { setOpen(null); loadList(); }}
            act={async (body) => { const d = await post({ ...body, caseId: data.file.id }); if (d) await loadCase(data.file.id); return d; }}
          />
        )}
      </main>
    </div>
  );
}

// ---- the list -------------------------------------------------------------------------

function CaseList({ list, onOpen, onNew, busy }: {
  list: (CaseFile & { entities: number; facts: number })[] | null;
  onOpen: (id: string) => void;
  onNew: (ref: string, title: string) => void;
  busy: boolean;
}) {
  const [ref, setRef] = useState("");
  const [title, setTitle] = useState("");
  return (
    <>
      <h1 className="csr-h1">Cases</h1>
      <form className="csr-new" onSubmit={(e) => { e.preventDefault(); if (ref.trim()) onNew(ref, title); }}>
        <input value={ref} onChange={(e) => setRef(e.target.value)} placeholder="reference, e.g. INC-2026-114" aria-label="case reference" />
        <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="what this is about" aria-label="case title" />
        <button disabled={busy || !ref.trim()}>Open a case</button>
      </form>

      {list === null ? <p className="csr-off">Loading…</p> : list.length === 0 ? (
        <p className="csr-off">No cases yet. A case is where a lead goes before it is an identity.</p>
      ) : (
        <table className="csr-table">
          <thead><tr><th>Reference</th><th>About</th><th>Selectors</th><th>Pinned</th><th>Opened</th><th /></tr></thead>
          <tbody>
            {list.map((c) => (
              <tr key={c.id} className={c.status === "closed" ? "shut" : ""}>
                <td><code>{c.ref}</code>{c.status === "closed" && <em className="csr-shut">closed</em>}</td>
                <td>{c.title}</td>
                <td className="num">{c.entities}</td>
                <td className="num">{c.facts}</td>
                <td className="num">{when(c.openedAt)}</td>
                <td><button className="csr-link" onClick={() => onOpen(c.id)}>Open</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

// ---- the board ------------------------------------------------------------------------

function CaseBoard({ data, act, back, busy }: {
  data: Loaded;
  act: (body: Record<string, unknown>) => Promise<any>;
  back: () => void;
  busy: boolean;
}) {
  const { file, entities, facts, board } = data;
  const [testing, setTesting] = useState<{ value: string; after: number; before: number; isolates: string[] } | null>(null);
  const nameOf = useMemo(() => new Map(entities.map((e) => [e.id, e.label || e.value])), [entities]);

  // The same shape the Orbit view takes, with selectors standing in for databases.
  const orbitReport = useMemo(() => ({
    subject: file.ref,
    breachCount: entities.length,
    dataPoints: facts.length,
    sources: entities.map((e) => ({
      name: e.label || e.value,
      info: `${e.kind}: ${e.value}`,
      sortDate: e.addedAt,
      severity: (facts.filter((f) => f.entityId === e.id).some((f) => f.severity === "critical") ? "critical" : "medium") as "critical" | "medium",
      findings: [
        { category: e.kind === "username" ? "online" : e.kind, severity: "medium" as const, label: e.kind, value: e.value, source: "the case" },
        ...facts.filter((f) => f.entityId === e.id).map((f) => ({
          category: f.category, severity: f.severity, label: f.label, value: f.value, source: f.source,
        })),
      ],
    })),
  }), [entities, facts, file.ref]);

  return (
    <>
      <div className="csr-head">
        <button className="csr-link" onClick={back}>← all cases</button>
        <h1 className="csr-h1"><code>{file.ref}</code> {file.title}</h1>
        <span className="csr-meta">opened by {file.openedBy} on {when(file.openedAt)}{file.status === "closed" ? " · closed" : ""}</span>
        {/* Plain links, so the browser does the download and the server names the file. */}
        <span className="csr-exports">
          <a href={`/api/case?id=${encodeURIComponent(file.id)}&format=csv`}>export CSV</a>
          <a href={`/api/case?id=${encodeURIComponent(file.id)}&format=json`}>export JSON</a>
        </span>
      </div>

      {/* The gaps come FIRST. A summary of what is known reads as progress; the list of
          what is missing is the thing that decides what to do in the next ten minutes. */}
      <section className="csr-gaps">
        <h2>Where this case stands</h2>
        <ul>{board.gaps.map((g) => <li key={g}>{g}</li>)}</ul>
      </section>

      <section className="csr-sec">
        <h2>Correlation</h2>
        <p className="csr-lead">
          Selectors, and the values two or more of them share. The same graph the report
          draws over databases: pull a thread to see whether the case survives without it.
        </p>
        {entities.length ? <LeakOrbit report={orbitReport} noun={{ one: "selector", many: "selectors" }} /> : <p className="csr-off">Add a selector to start.</p>}
      </section>

      <div className="csr-cols">
        <section className="csr-sec">
          <h2>Selectors</h2>
          <AddEntity onAdd={(kind, value, label) => act({ action: "entity", kind, value, label })} busy={busy} />
          {entities.map((e) => (
            <EntityCard
              key={e.id} entity={e} ref_={file.ref}
              facts={facts.filter((f) => f.entityId === e.id)}
              onPin={(f) => act({ action: "pin", entityId: e.id, ...f })}
              onUnpin={(factId) => act({ action: "unpin", factId })}
              onTest={async (value, category) => {
                const r = await act({ action: "test", value, category });
                if (r) setTesting({ value, before: r.before, after: r.after, isolates: r.isolates });
              }}
              busy={busy}
            />
          ))}
        </section>

        <div className="csr-side">
          {testing && (
            <div className={"csr-test" + (testing.after > testing.before ? " broke" : "")}>
              <h3>If &ldquo;{testing.value}&rdquo; is wrong</h3>
              <p>
                {testing.after > testing.before
                  ? <>the case falls into <b>{testing.after} groups</b>{testing.isolates.length ? <>, and {testing.isolates.join(", ")} connect to nothing else</> : null}.</>
                  : <>nothing changes. Other pinned values still join the same selectors, so the case does not rest on this one.</>}
              </p>
              <button className="csr-link" onClick={() => setTesting(null)}>dismiss</button>
            </div>
          )}

          <Panel title="Addresses" empty="No address pinned yet.">
            {board.network.exact.map((c) => (
              <div className={"csr-net" + (c.weight === "weak" ? " weak" : "")} key={c.key}>
                <code>{c.key}</code>
                <span>{c.members.join(", ")}</span>
                {c.note && <em>{c.note}</em>}
              </div>
            ))}
            {board.network.blocks.map((c) => (
              <div className="csr-net weak" key={c.key}>
                <code>{c.key}</code>
                <span>{c.members.join(", ")}</span>
                <em>{c.note}</em>
              </div>
            ))}
          </Panel>

          <Panel title="Machines" empty="No browser string pinned yet.">
            {board.devices.map((d) => (
              <div className="csr-dev" key={d.key}>
                <b>{describeAgent(d.agent)}</b>
                <span>{d.entities.join(", ")}</span>
                {d.agent.notes.map((n) => <em key={n}>{n}</em>)}
              </div>
            ))}
          </Panel>

          <Panel title="Location" empty="Nothing pinned carries a location.">
            <p className="csr-geoline">{board.geoLine}</p>
            {board.geo.map((g, i) => (
              <div className={"csr-geo w-" + g.weight} key={i}>
                <b>{g.place}</b><span>{g.weight}</span>
                <em>{g.from}</em>
                <small>{g.basis}</small>
              </div>
            ))}
          </Panel>

          <Panel title="Timeline" empty="No dated activity pinned yet.">
            {board.timeline.map((t, i) => (
              <div className={"csr-when" + (t.when ? "" : " undated")} key={i}>
                <code>{when(t.when)}</code>
                <span>{t.what} · {nameOf.get(t.entityId)}</span>
                <em>{t.detail} · {t.source}</em>
              </div>
            ))}
          </Panel>
        </div>
      </div>
    </>
  );
}

function Panel({ title, empty, children }: { title: string; empty: string; children: React.ReactNode }) {
  const has = Array.isArray(children) ? children.flat().filter(Boolean).length > 0 : !!children;
  return (
    <section className="csr-panel">
      <h3>{title}</h3>
      {has ? children : <p className="csr-off">{empty}</p>}
    </section>
  );
}

function AddEntity({ onAdd, busy }: { onAdd: (k: EntityKind, v: string, l: string) => void; busy: boolean }) {
  const [kind, setKind] = useState<EntityKind>("email");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  return (
    <form className="csr-add" onSubmit={(e) => { e.preventDefault(); if (value.trim()) { onAdd(kind, value, label); setValue(""); setLabel(""); } }}>
      <select value={kind} onChange={(e) => setKind(e.target.value as EntityKind)} aria-label="kind">
        {KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
      </select>
      <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="the selector" aria-label="selector" />
      <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="call it something" aria-label="label" />
      <button disabled={busy || !value.trim()}>Add</button>
    </form>
  );
}

function EntityCard({ entity, facts, ref_, onPin, onUnpin, onTest, busy }: {
  entity: CaseEntity;
  facts: CaseFact[];
  ref_: string;
  onPin: (f: { category: string; severity: string; label: string; value: string; source: string; note?: string }) => void;
  onUnpin: (id: string) => void;
  onTest: (value: string, category: string) => void;
  busy: boolean;
}) {
  const [adding, setAdding] = useState(false);
  return (
    <div className="csr-ent">
      <div className="csr-ent-h">
        <b>{entity.label || entity.value}</b>
        <span className="csr-kind">{entity.kind}</span>
        {/* straight into a search, carrying the case reference so the audit trail files
            the query under this case without anybody retyping it */}
        <Link className="csr-link" href={`/search?q=${encodeURIComponent(entity.value)}&case=${encodeURIComponent(ref_)}`}>search</Link>
      </div>
      {entity.label && <code className="csr-ent-v">{entity.value}</code>}

      <ul className="csr-facts">
        {facts.map((f) => (
          <li key={f.id} className={"s-" + f.severity}>
            <span className="csr-fl">{f.label}</span>
            <code>{f.value}</code>
            <em>{f.source}</em>
            <button className="csr-link" onClick={() => onTest(f.value, f.category)} title="what if this is wrong">test</button>
            <button className="csr-link" onClick={() => onUnpin(f.id)} title="remove">unpin</button>
          </li>
        ))}
      </ul>

      {adding ? (
        <PinForm onCancel={() => setAdding(false)} onPin={(f) => { onPin(f); setAdding(false); }} busy={busy} />
      ) : (
        <button className="csr-link" onClick={() => setAdding(true)}>+ pin a fact</button>
      )}
    </div>
  );
}

function PinForm({ onPin, onCancel, busy }: {
  onPin: (f: { category: string; severity: string; label: string; value: string; source: string; note?: string }) => void;
  onCancel: () => void;
  busy: boolean;
}) {
  const [label, setLabel] = useState("");
  const [value, setValue] = useState("");
  const [source, setSource] = useState("");
  const [category, setCategory] = useState("other");
  const [severity, setSeverity] = useState("medium");
  const agent = useMemo(() => (/user.?agent|\bua\b/i.test(label) && value ? parseAgent(value) : null), [label, value]);

  return (
    <form className="csr-pin" onSubmit={(e) => { e.preventDefault(); if (value.trim()) onPin({ label: label || "value", value, source: source || "unstated", category, severity }); }}>
      <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="field, as the dump named it" aria-label="field" />
      <input value={value} onChange={(e) => setValue(e.target.value)} placeholder="the value" aria-label="value" />
      {/* The source is not optional in spirit: a pinned fact that cannot name the dump
          it came from cannot be checked, and an unverifiable fact in a case file is
          worse than a missing one. */}
      <input value={source} onChange={(e) => setSource(e.target.value)} placeholder="which database it came from" aria-label="source" />
      <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="category">
        {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
      <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="severity">
        {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
      {agent && <p className="csr-read">read as: {describeAgent(agent)}</p>}
      <div className="csr-pin-a">
        <button disabled={busy || !value.trim()}>Pin</button>
        <button type="button" className="csr-link" onClick={onCancel}>cancel</button>
      </div>
    </form>
  );
}
