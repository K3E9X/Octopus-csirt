import Dashboard from "@/components/Dashboard";
import { authEnabled } from "@/lib/session-server";
import { redirect } from "next/navigation";
import { currentUser } from "@/lib/session-server";

export const dynamic = "force-dynamic";

// The front page is the dashboard, not a pitch. A visitor who is not signed in has
// nothing to see here, so they are sent to the door rather than shown an empty shell
// that waits for a fetch to tell them the same thing.
export default async function Page() {
  if (authEnabled && !(await currentUser())) redirect("/signin?next=/");
  return <Dashboard />;
}
