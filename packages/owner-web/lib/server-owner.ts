import "server-only";
import { headers } from "next/headers";
import type { OwnerResponse } from "./api";

export async function serverOwner() {
  try {
    const incoming = await headers();
    const response = await fetch(new URL("/api/owner", process.env.OID_API_URL ?? "http://127.0.0.1:8784"), {
      headers: { cookie: incoming.get("cookie") ?? "" }, cache: "no-store",
    });
    if (!response.ok) return null;
    return (await response.json() as OwnerResponse).owner;
  } catch { return null; }
}
