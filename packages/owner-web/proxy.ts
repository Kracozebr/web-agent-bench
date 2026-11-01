import { NextRequest, NextResponse } from "next/server";

// AICODE-NOTE: Reject before rendering so streaming cannot turn a concealed page into HTTP 200.
export async function proxy(request: NextRequest) {
  let admin = false;
  try {
    const response = await fetch(new URL("/api/owner", process.env.OID_API_URL ?? "http://127.0.0.1:8784"), {
      headers: { cookie: request.headers.get("cookie") ?? "" }, cache: "no-store",
    });
    if (response.ok) admin = (await response.json()).owner?.isAdmin === true;
  } catch { /* unavailable verification conceals the administration surface */ }
  const response = admin ? NextResponse.next() : new NextResponse("Not Found", { status: 404 });
  response.headers.set("Cache-Control", "private, no-store, max-age=0");
  response.headers.set("Vary", "Cookie");
  return response;
}

export const config = { matcher: ["/admin/:path*"] };
