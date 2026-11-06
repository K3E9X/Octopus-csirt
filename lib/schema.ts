// Creating the schema when more than one copy of the application starts at once.
//
// Every module that owns tables creates them on first use with CREATE TABLE IF NOT
// EXISTS, which reads as safe and is not: run concurrently, Postgres raises a unique
// violation on pg_type, because the existence check and the insert into the catalogue
// are not one operation. Measured on a real database, six simultaneous attempts gave
// one CREATE TABLE and five failures.
//
// One replica never saw it. Two do, every cold start, and the deployment this is going
// into runs two.
//
// THE SECOND HALF IS WORSE THAN THE RACE. The bootstraps cached their promise to run
// once: `ready = ready || doIt()`. A rejected promise is still a promise, so the pod
// that lost the race cached the REJECTION and every later call rejected against it for
// as long as the process lived. A transient collision at startup became one permanently
// broken replica, serving errors to half the traffic, with a healthy pod next to it.
//
// So: a benign collision is a success, because the table exists, which is the whole
// point of asking. Anything else clears the cache so the next request tries again
// instead of inheriting a failure nobody can clear without a restart.

/** Postgres says the object is already there, in the several ways it says it. */
function alreadyExists(e: unknown): boolean {
  const err = e as { code?: string; message?: string };
  // 42P07 duplicate_table · 42710 duplicate_object · 42P16 invalid_table_definition
  // 23505 unique_violation, which is what the pg_type race actually raises
  if (err?.code && ["42P07", "42710", "42P16", "23505"].includes(err.code)) return true;
  const m = String(err?.message || "").toLowerCase();
  return m.includes("already exists") || m.includes("duplicate key value") || m.includes("pg_type");
}

/**
 * Run a schema bootstrap once per process, retrying after a real failure.
 *
 * The returned function is what callers await. While it is in flight they share the one
 * promise; once it succeeds they share the resolved one; if it fails for a reason that
 * is not a collision, the cache is cleared and the next caller tries again.
 */
export function bootstrap(run: () => Promise<void>): () => Promise<void> {
  let ready: Promise<void> | null = null;
  return () => {
    if (!ready) {
      ready = run().catch((e) => {
        if (alreadyExists(e)) return;      // another copy got there first, which is fine
        ready = null;                      // never cache a failure nobody can clear
        throw e;
      });
    }
    return ready;
  };
}


