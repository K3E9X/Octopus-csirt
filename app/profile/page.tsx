import Profile from "@/components/Profile";
import { authEnabled, currentUser } from "@/lib/session-server";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

// Reachable by any signed-in account including a pending one, which is the only screen
// that is: somebody who has just registered needs to be told what state they are in.
export default async function Page() {
  if (authEnabled && !(await currentUser())) redirect("/signin?next=/profile");
  return <Profile />;
}
