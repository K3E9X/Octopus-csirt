# Octopus CSIRT

**Breach data, turned into a case.**

Internal fork of Octopus Leak for the CSIRT. Same index, same attribution, no pricing:
this one is not sold to anybody, it is worked in.

Give it an email address, a phone number, a handle or a name. It searches
[LeakOSINT](docs/leakosint-api.md), the one source here, and the only one that returns
the records themselves rather than a verdict, and gives back more than a list of hits:
the rows that are genuinely about that subject, consolidated into one person, with the
database behind every single fact.

The hard part is not the search. It is everything between the response and the report,
and then everything between the report and a conclusion somebody can defend.

## The problem this exists to solve

The index searches **every permutation of the words in a query**. A result set is
therefore rows that matched *something*, not rows about the person asked for. Hand
those to a reader as one profile and you have produced a detailed, confident, wrong
document, which is worse than producing nothing.

Three things stand between the API and a claim:

**Attribution.** Every row is judged before it contributes anything, `direct`,
`partial`, or `none`. Only `direct` rows become facts about the subject. Partial and
unrelated rows are counted and shown as what they are: other people. They are never
merged, and never silently dropped either, because the operator paid for them and a
count of what was set aside is the only way to tell *nothing was found* apart from
*everything found belonged to someone else*.

**Matching that survives how dumps actually store things.** An address is canonicalised
on both sides, so a search for `johndoe@gmail.com` still matches a dump holding
`john.doe+shop@gmail.com`. A number is compared past the national trunk prefix, in most
of Europe the leading `0` is *replaced* by the country code rather than appended, so
`+33612345678` and `0612345678` share neither prefix nor suffix until that is handled,
and missing it loses the single most relevant row in a result set.

**Consolidation.** The subject's rows become one person, each value naming the databases
that carried it and ranked by how many **independent** dumps agree. Corroboration is
reported as *"2 of 5 facets confirmed by more than one database"*, a count, never a
percentage. Nobody calibrated a percentage, and a number out of 100 gets read as a
probability it has not earned.

## What a search costs, before it runs

The upstream API bills per request on a published formula and says nothing about the
price until the money is gone. The formula is reimplemented here and pinned by tests, so
every query is quoted first:

| Query at `limit=100` | Complexity | Cost |
|---|---|---|
| `example@gmail.com` | 1 | **$0.0030** |
| `Petya Ivanov` | 5 | $0.0055 |
| `Elon Reeve Musk` | 16 | $0.0090 |
| `"Elon Reeve Musk"` | 1 | **$0.0030** |

Quoting a name is a third of the price, and it is also **narrower**, matching the
phrase as written instead of every word order. That is a choice with two axes, so the
interface prices both and says which one buys what. Full contract, including where the
documentation and the live endpoint disagree, in [`docs/leakosint-api.md`](docs/leakosint-api.md).

## Selectors

An **email**, a **phone** and a **handle** designate someone, so their rows can be
presented as one person's report.

A **name** does not: thousands of people share one. A name search is still run, because
the index supports it and it is often the only thing an investigation has, but its
results are rendered as candidates grouped by who they appear to be. The interface says
so at the point of entry, not in a footnote under the results.

## Accountability instead of a gate

Any search runs against a real person's data, so the record of **why** exists before the
data does. Every query carries a declared basis from a closed list (own data, consent,
investigation, legal request, security research) and is written to an **append-only,
hash-chained** log *before* it runs, so a refused or failed attempt leaves a trace too. A
trail that records only successes hides the interesting half.

`GET /api/audit?verify=1` re-walks the chain. A break means a row was altered or removed.
This is tamper-**evident**, not tamper-proof: it survives challenge, it does not survive
an attacker with database write access and time.

## Run it

```bash
npm install
npm run dev            # http://localhost:3000
npm test               # unit tests over the lib layer
npm run build && npm start
```

```bash
docker compose up --build                 # unmetered, no accounts
docker compose --profile db up --build    # + Postgres: accounts, credits, audit trail
```

Configuration is env vars, all optional; see [`.env.example`](.env.example). The app
always runs and **says what is missing** rather than faking it:

| Variable | Absent |
|---|---|
| `LEAKOSINT_TOKEN` | No leak data, stated as such, never an empty report |
| `POSTGRES_URL` | Single-operator: no accounts, no metering, **no audit trail**. Fine for one analyst, never for anything public |
| `OCTOPUS_SESSION_SECRET` | Sessions are refused rather than signed with a shared constant |
| `OCTOPUS_MARKUP` | Dollar valuation of a credit, as a multiple of the raw API cost (default `1.6`). **Not the margin**; see below |

## Credits, and why they stayed

Nothing is sold here, and credits stayed anyway. Two reasons, and neither is revenue.

Every query has a real upstream cost, so a typo in a name search at depth 1000 spends
actual money; a balance is the only thing between that and the bill. And a search that
costs something is a search somebody decided to run, which is what makes the audit
trail worth keeping.

**A credit is one search.** A plain address at the default depth costs one; a
multi-word name costs more because it genuinely is more work upstream, and so does a
deeper sweep. Charges round up to a whole credit. The ledger underneath is in
micro-dollars (integers), because floating-point dollars drift and a balance that
drifts leaks money in one direction.

A new account starts at **zero**. Signing in is not the gate; spending is, and the
owner opens it per person. That is also the answer to self-registration on an internal
tool: an account nobody has funded cannot run a single query.

The balance check and the deduction are **one statement**, so two requests racing on the
same account cannot both pass against a balance that covers one. A query the API refuses
is refunded, because it did not run.

## Roles

| Role | What it can do |
| --- | --- |
| `owner` | Holds the source token and the budget. Grants credit without limit. Claimed once, atomically, by the first registration. |
| `admin` | Users, roles below owner, the audit trail, closing cases. Grants credit **to others**, bounded, never to itself. |
| `hunter` | Investigates: cases, searches, pivots, exports. Sees its own queries and nobody else's. |
| `disabled` | Nothing. |

The split between owner and admin is the point rather than a tidier set of labels: an
audit trail signed by someone who can also create the budget proves nothing.

## The front page

`/` is the dashboard, not a pitch. Three questions in the order somebody has them at
nine in the morning: what am I in the middle of, what did I do last, can I start
something now. No counters nobody acts on, because a dashboard made of numbers trains
people to stop reading it and the first thing skipped is the line that mattered.

Two things get a banner, and only two: no credits, and an audit chain that does not
verify.

## Domains

Searching `@corp.example` answers the question a CSIRT actually asks about its own
estate: **who here is in breach data**.

It used to answer nothing. A domain went through the one-subject machinery, every row
failed attribution against "@corp.example", and the report came back **clear** with
zero data points: a confident, detailed, empty answer. It returns a roster now, and
nothing is consolidated across accounts, because two people at one employer are two
people.

The distinction that decides the next hour is computed rather than left for a reader to
spot: an address in a marketing list is an address in a marketing list, while the same
address in a **stealer log** means a machine somebody was using was compromised, with
whatever that session had open. A reset does not invalidate a stolen cookie, and the
report says so.

A hash is not a password. Telling a responder they have plaintext when they have bcrypt
wastes the hour that mattered.

## Kept answers

A search is kept for `OCTOPUS_CACHE_HOURS` (24 by default, 0 turns it off) so asking the
same question twice costs one credit. Breach data is historic: nothing appeared in the
index between eleven and two, and paying again buys nothing.

This is the one place the deployment stores breach data, which everything else here
refuses to do, so it is bounded in every direction that matters. It expires. Every kept
answer is listed in `/admin` with a button to drop it. A report built from one says so,
with its age and a button to pay for a fresh one, because a cache nobody can bypass is a
trap the first time the index gains a database. And **a cache hit still writes the audit
entry**: a cached answer is still somebody looking at somebody, and "who looked at whom"
is the record that must not develop holes.

## Cases

A hunt does not start as an identity. It starts as a stealer log, an insider's corporate
address, an IP out of a proxy line. `/cases` is that loop: selectors on the left, the
correlation in the middle, and what the case is still **missing** at the top, because
the gap decides the next ten minutes and the summary does not.

**A case holds what somebody pinned, never a cached report.** Caching would be cheaper
and would turn the case table into a second copy of other people's breach data, held
indefinitely, with no legal basis separate from the search that produced it. What a case
stores is the analyst's work: the selectors they chose and the facts they judged
relevant, each still naming the dump it came from so it can be checked or dropped. Every
row carries who put it there and when, because the question after an incident is always
"who concluded that, and from what".

The board derives, at read time:

- **Correlation.** The same graph the report's Orbit draws, over selectors instead of
  databases, so a line means the same thing on both screens. Pull a thread and it
  recomputes without it: if the case falls into pieces, that fact was carrying the
  conclusion.
- **Addresses.** Sharing an address and sharing an allocation are different claims and
  are kept apart. A carrier-grade NAT range is held by thousands of subscribers at once,
  so it is shown, labelled, and **never drawn as a link**.
- **Machines.** The browser string read into OS, browser and device, with an
  end-of-life OS or a browser years behind reported as a finding: that is the machine an
  infostealer lands on. Two selectors on one build cluster as one device.
- **Location.** Not a location: **evidence** of location, each piece naming its field,
  its dump, and what it is worth. Sources that disagree are reported as disagreeing.
  An IP is **not** turned into a country, because that needs a geo database and there is
  no honest way to infer it from the number. The hook is in `lib/geo.ts`.
- **Timeline.** Dated activity, with undated entries kept rather than dropped: a hole in
  a timeline reads as absence of activity, which is a different claim.

A case leaves as CSV or JSON, carrying who pinned what out of which database. Values are
neutralised against spreadsheet formula injection on the way out, and the reason is
sharper here than on a report: every pinned value was written by whoever assembled the
dump, and a case export is opened by a responder under time pressure. The JSON includes
the board, marked as **derived**: a conclusion, not evidence.

## Structure

```
app/search/        the search
app/cases/         the investigation board
app/page.tsx       the dashboard
app/api/search/    GET quotes · POST runs
lib/leakosint.ts   the source: cost, rate limit, parsing, refusals
lib/subject.ts     what was asked for, and what to match rows against
lib/attribution.ts is this row about the subject?
lib/identity.ts    rows → a person, every value citing its databases
lib/report.ts      the report, built from attributed rows
lib/views.ts       the views a report has, one list, so nothing can disagree about it
lib/credits.ts     the credit ledger
lib/casework.ts    a case: correlation, devices, location, timeline, gaps
lib/casestore.ts   where a case lives: three tables, no cached reports
lib/ua.ts          the browser string, read
lib/netintel.ts    what an address is, and whether it can carry a link
lib/geo.ts         evidence of location, and where that stops
lib/domain.ts      who at an organisation is in breach data
lib/audit.ts       the hash-chained query log
docs/              the API contract
```

## Legal note

Internal CSIRT use: incident response, insider investigation, threat intelligence. Processing personal data means GDPR applies, legal
basis, minimisation, limited retention, audit, and data-subject rights. The declared basis and the query log exist so those obligations can
actually be met rather than asserted.

**Retention.** The audit trail holds every selector anybody typed. Keeping that forever
is not a lawful answer and neither is deleting whatever is inconvenient, so `/admin` can
remove everything older than a cutoff, **from the beginning only**, and the purge writes
itself into the trail it just shortened. A row cannot be taken out of the middle: that is
the one thing a hash-chained log exists to prevent, and the only reason to want it is to
remove a particular query somebody ran. The chain keeps verifying across a purge because
the hash of the last removed row is recorded as the new floor.

**Cases hold personal data.** Pinned facts are breach data about identifiable people,
kept on our infrastructure for as long as the case exists. That is a processing activity
in its own right: it needs a basis, a retention period and somebody who owns the
decision to delete. Nothing here purges automatically, on purpose, because silently
deleting case files destroys incident records; closing a case and emptying it are
deliberate acts and should stay that way.
