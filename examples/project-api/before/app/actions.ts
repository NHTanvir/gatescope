"use server";

import { db } from "@/lib/db";

// A server action is a POST endpoint. Anyone who can read the page can call it.
export async function deleteAccount(userId: string) {
  await db.user.delete({ where: { id: userId } });
}

export async function updatePlan(userId: string, plan: string) {
  await db.subscription.update({ where: { userId }, data: { plan } });
}
