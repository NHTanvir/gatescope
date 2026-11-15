"use server";

import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

// A server action is a POST endpoint, so it checks for itself. The subject is
// always the session user: an id in the arguments would be a request, not a claim.

export async function deleteAccount() {
  const session = await auth();
  if (!session?.user) throw new Error("unauthorised");

  await db.user.delete({ where: { id: session.user.id } });
}

export async function updatePlan(plan: "free" | "pro") {
  const session = await auth();
  if (!session?.user) throw new Error("unauthorised");

  await db.subscription.update({
    where: { userId: session.user.id },
    data: { plan },
  });
}
