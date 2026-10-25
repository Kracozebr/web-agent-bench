"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { createSiweMessage } from "viem/siwe";
import { ApiError, apiRequest, errorText, getCurrentOwner, IdentityConfig } from "@/lib/api";
import { getAuthClient } from "@/lib/auth-client";
import { injectedWallet, stringResult } from "@/lib/wallet";

type ActionState = { kind: "idle" | "busy" | "error"; message: string };

export function SignInPanel() {
  const router = useRouter();
  const [state, setState] = useState<ActionState>({ kind: "idle", message: "" });
  const [sessionReady, setSessionReady] = useState(false);
  const [identityConfig, setIdentityConfig] = useState<IdentityConfig | null>(null);
  const [configReady, setConfigReady] = useState(false);

  useEffect(() => {
    let active = true;
    void getCurrentOwner().then((owner) => {
      if (!active) return;
      if (owner?.admissionStatus === "admitted") router.replace("/account");
      else if (owner?.admissionStatus === "pending") router.replace("/activate");
      else setSessionReady(true);
    }).catch(() => {
      if (active) {
        setState({ kind: "error", message: "The owner API is unavailable. Sign-in cannot be confirmed until it responds." });
      }
    });
    void apiRequest<IdentityConfig>("/api/identity/config").then((config) => {
      if (active) {
        setIdentityConfig(config);
        setConfigReady(true);
      }
    }).catch(() => {
      if (active) {
        setConfigReady(true);
        setState({ kind: "error", message: "The identity configuration is unavailable. Sign-in cannot start until the API provides its verified provider settings." });
      }
    });
    return () => { active = false; };
  }, [router]);

  async function signInWithGoogle() {
    if (!identityConfig?.googleEnabled) {
      setState({ kind: "error", message: "Google sign-in is not enabled in the server identity configuration." });
      return;
    }
    setState({ kind: "busy", message: "Starting verified Google sign-in…" });
    try {
      const result = await getAuthClient().signIn.social({
        provider: "google",
        callbackURL: `${window.location.origin}/auth/complete`,
      });
      if (result.error) throw new ApiError(result.error.status ?? 400, "Google sign-in did not complete. Check the provider response and try again.", result.error.code);
      if (result.data?.url && !result.data.redirect) window.location.assign(result.data.url);
      if (!result.data?.redirect && !result.data?.url) throw new Error("Google did not return an authorization redirect.");
      setState({ kind: "busy", message: "Continue in the Google sign-in window. The server will verify the callback." });
    } catch (error) {
      setState({ kind: "error", message: errorText(error) });
    }
  }

  async function signInWithWallet() {
    setState({ kind: "busy", message: "Requesting a wallet signature for owner sign-in…" });
    try {
      const siwe = identityConfig?.siwe;
      if (!siwe?.enabled || !Number.isSafeInteger(siwe.chainId) || !Number.isSafeInteger(siwe.nonceTtlSeconds) || siwe.nonceTtlSeconds <= 0) {
        throw new Error("The server has not provided a usable SIWE profile. No wallet signature was requested.");
      }
      if (siwe.domain !== window.location.host || siwe.uri !== window.location.origin) {
        throw new Error("This page origin does not match the SIWE domain configured by the server. No wallet signature was requested.");
      }
      const wallet = injectedWallet();
      const rawAccounts = await wallet.request({ method: "eth_requestAccounts" });
      if (!Array.isArray(rawAccounts) || typeof rawAccounts[0] !== "string") {
        throw new Error("The selected wallet did not return an account.");
      }
      const address = rawAccounts[0] as `0x${string}`;
      if (!/^0x[0-9a-fA-F]{40}$/.test(address)) throw new Error("The selected wallet returned an unsupported account format.");

      const rawChainId = stringResult(await wallet.request({ method: "eth_chainId" }), "the active chain");
      if (!/^0x[0-9a-fA-F]+$/.test(rawChainId)) throw new Error("The selected wallet returned an invalid chain identifier.");
      const chainId = Number.parseInt(rawChainId, 16);
      if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error("The selected wallet returned an invalid chain identifier.");
      if (chainId !== siwe.chainId) throw new Error(`Switch the selected wallet to chain ${siwe.chainId} and retry. No signature was requested.`);

      const auth = getAuthClient();
      const nonceResult = await auth.siwe.nonce();
      if (nonceResult.error || !nonceResult.data?.nonce) {
        throw new Error("The server did not issue a sign-in nonce. No wallet signature was requested.");
      }

      const message = createSiweMessage({
        address,
        chainId: siwe.chainId,
        domain: siwe.domain,
        nonce: nonceResult.data.nonce,
        uri: siwe.uri,
        version: "1",
        issuedAt: new Date(),
        expirationTime: new Date(Date.now() + siwe.nonceTtlSeconds * 1000),
        statement: siwe.statement,
      });
      const rawSignature = await wallet.request({ method: "personal_sign", params: [message, address] });
      const signature = stringResult(rawSignature, "the SIWE signature");
      const verifyResult = await auth.siwe.verify({ message, signature });
      if (verifyResult.error) throw new Error("The server could not verify this wallet signature. Check the wallet network and retry sign-in.");
      router.replace("/auth/complete");
    } catch (error) {
      setState({ kind: "error", message: errorText(error) });
    }
  }

  return (
    <section className="card auth-card" aria-labelledby="sign-in-title">
      <div className="page-heading">
        <p className="eyebrow">Owner identity</p>
        <h1 id="sign-in-title">Sign in to your owner account</h1>
        <p className="lede">Choose a verified sign-in method. New owners in the closed pilot will need an invitation after sign-in.</p>
      </div>
      <div className="stack">
        <div className="notice">
          Wallet sign-in uses the server-configured SIWE domain and chain, then asks the connected EOA wallet to sign a one-time message. It does not send a transaction, prove Google ownership, or authorize a withdrawal.
        </div>
        {identityConfig?.googleMode === "provider-fixture" && <div className="notice notice-warning">Google is using a local provider fixture. This supports contract testing only and does not establish actual Google compatibility.</div>}
        {identityConfig?.googleMode === "google" && <p className="fine">Google is configured for this deployment. Actual account compatibility is established only by the separate provider acceptance gate.</p>}
        {identityConfig?.googleMode === "disabled" && <p className="fine">Google sign-in is disabled by the server configuration.</p>}
        {configReady && identityConfig?.siwe.enabled === false && <p className="fine">Wallet sign-in is disabled by the server configuration.</p>}
        <div className="auth-actions">
          <button
            className="button button-primary"
            type="button"
            data-testid="sign-in-google"
            onClick={() => void signInWithGoogle()}
            disabled={!sessionReady || !configReady || !identityConfig?.googleEnabled || state.kind === "busy"}
          >
            Continue with Google
          </button>
          <button
            className="button"
            type="button"
            data-testid="sign-in-wallet"
            onClick={() => void signInWithWallet()}
            disabled={!sessionReady || !configReady || !identityConfig?.siwe.enabled || state.kind === "busy"}
          >
            Sign in with browser wallet
          </button>
        </div>
        <p className={`status-box ${state.kind === "error" ? "status-error" : ""}`} role={state.kind === "error" ? "alert" : "status"} aria-live="polite">
          {state.message || (sessionReady && configReady ? "Your sign-in will be checked by the owner API." : "Checking your server session and identity configuration…")}
        </p>
        {state.kind === "error" && <button className="button button-small" type="button" onClick={() => window.location.reload()}>Retry server check</button>}
        <p className="fine">The server checks provider responses and SIWE signatures before it creates an owner session. The browser does not determine admission or administrator access.</p>
      </div>
    </section>
  );
}
