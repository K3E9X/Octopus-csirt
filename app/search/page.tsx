import SearchApp from "@/components/SearchApp";
import { currentUser, authEnabled } from "@/lib/session-server";
import { balanceOf, balanceCredits, creditsEnabled } from "@/lib/credits";

// The product. Anyone can open it; running a search needs an account, a declared basis
// and, where the deployment meters, credits. The component and /api/search enforce it.
//
// WHO YOU ARE IS RESOLVED HERE, not by a fetch after the page has painted. The header
// used to render from client state that started empty, so a signed-in operator saw
// "Sign in" in the corner for as long as the round trip took, and permanently if it
// failed. That is indistinguishable from being signed out, and it is what somebody
// reports as "it will not connect".
export const dynamic = "force-dynamic";

export default async function Page() {
  const me = authEnabled ? await currentUser() : null;
  const micro = me && creditsEnabled ? await balanceOf(me.id).catch(() => 0) : 0;
  return (
    <SearchApp
      initialAccount={{
        authed: !!me || !authEnabled,
        email: me?.email,
        role: me?.role,
        metered: creditsEnabled && !!me,
        balance: me && creditsEnabled ? balanceCredits(micro) : undefined,
      }}
    />
  );
}
