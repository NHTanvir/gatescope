import { db } from "@/lib/db";

// A Next.js route handler. Exported, routable, and guarding nothing.
export async function GET(request: Request) {
  const invoices = await db.invoice.findMany();
  return Response.json(invoices);
}

export async function POST(request: Request) {
  const body = await request.json();
  const invoice = await db.invoice.create({ data: { ...body } });
  return Response.json(invoice);
}
