"use client";

import { createAuthClient } from "better-auth/react";
import { siweClient } from "better-auth/client/plugins";

function createOwnerAuthClient() {
  return createAuthClient({
    baseURL: window.location.origin,
    plugins: [siweClient()],
  });
}

type OwnerAuthClient = ReturnType<typeof createOwnerAuthClient>;
let client: OwnerAuthClient | undefined;

export function getAuthClient() {
  if (!client) {
    client = createOwnerAuthClient();
  }
  return client;
}
