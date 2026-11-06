import Admin from "@/components/Admin";
import { currentUser, authEnabled } from "@/lib/session-server";
import { isAtLeast } from "@/lib/auth";
import { redirect } from "next/navigation";
import Link from "next/link";
import { OctoMark } from "@/components/OctoMark";

export const dynamic = "force-dynamic";

// NOT SIGNED IN AND NOT PERMITTED ARE DIFFERENT ANSWERS, and this page used to give
// both of them the sign-in screen. A hunter who clicked "Admin" was sent to /signin,
// signed in correctly, was returned to /admin, and was sent to /signin again: a loop no
// amount of signing in could ever satisfy, which reads from the outside as "my account
// does not work". It was reported as exactly that.
//
// 401 sends you to the door. 403 tells you it is not your door.
export default async function Page() {
  if (!authEnabled) {
    return <Admin disabledReason="This deployment has no database, so it has no accounts to administer and nowhere to store the LeakOSINT token. Set POSTGRES_URL to enable accounts, metering and the audit trail; until then the token must come from LEAKOSINT_TOKEN in the environment." />;
  }
  const me = await currentUser();
  if (!me) redirect("/signin?next=/admin");

  if (!isAtLeast(me.role, "admin")) {
    return (
      <div className="lk2">
        <header className="lk2-top">
          <Link className="lk2-brand" href="/"><OctoMark size={30} /><span><b>OCTOPUS</b><small>CSIRT</small></span></Link>
          <nav><Link href="/">Dashboard</Link><Link href="/cases">Cases</Link><Link href="/search">Search</Link></nav>
        </header>
        <main className="dsh-main">
          <h1 className="csr-h1">Not your screen</h1>
          <p className="dsh-off">
            You are signed in as <code>{me.email}</code>, which is a <b>{me.role}</b>.
            This screen is for administrators: accounts, roles, credit and the audit
            trail. Nothing is wrong with your account.
          </p>
          <Link className="dsh-go" href="/">Back to the dashboard</Link>
        </main>
      </div>
    );
  }
  return <Admin me={{ id: me.id, email: me.email }} />;
}
