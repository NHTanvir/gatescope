import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { CreateInvoice } from "@/schemas/invoice";

export async function GET(request: Request) {
  const session = await auth();
  if (!session?.user) return new Response(null, { status: 401 });

  const invoices = await db.invoice.findMany({
    where: { userId: session.user.id },
    select: { id: true, total: true, issuedAt: true, status: true },
  });
  return Response.json(invoices);
}

export async function POST(request: Request) {
  const session = await auth();
  if (!session?.user) return new Response(null, { status: 401 });

  const { amount, description } = CreateInvoice.parse(await request.json());
  const invoice = await db.invoice.create({
    data: { amount, description, userId: session.user.id },
  });
  return Response.json(invoice);
}
