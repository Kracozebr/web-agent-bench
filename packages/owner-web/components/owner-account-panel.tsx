"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { createSiweMessage } from "viem/siwe";
import { ApiError, apiRequest, errorText, getCurrentOwner, IdentityConfig, newOperationId, OwnerProjection } from "@/lib/api";
import { getAuthClient } from "@/lib/auth-client";
import { injectedWallet, stringResult } from "@/lib/wallet";

export function OwnerAccountPanel() {
  const router = useRouter();
  const [owner, setOwner] = useState<OwnerProjection | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const [identityConfig, setIdentityConfig] = useState<IdentityConfig | null>(null);
  const [identityConfigUnavailable, setIdentityConfigUnavailable] = useState(false);

  const refreshOwner = useCallback(async () => {
    try {
      const current = await getCurrentOwner();
      if (!current) {
        router.replace("/sign-in");
        return;
      }
      if (current.admissionStatus !== "admitted") {
        router.replace("/activate");
        return;
      }
      setOwner(current);
    } catch (reason) {
      setMessage(errorText(reason));
      setError(true);
    }
  }, [router]);

  useEffect(() => {
    let active = true;
    void apiRequest<IdentityConfig>("/api/identity/config").then((config) => {
      if (active) setIdentityConfig(config);
    }).catch(() => {
      if (active) setIdentityConfigUnavailable(true);
    });
    void getCurrentOwner().then((current) => {
      if (!active) return;
      if (!current) router.replace("/sign-in");
      else if (current.admissionStatus !== "admitted") router.replace("/activate");
      else {
        setOwner(current);
        setLoading(false);
      }
    }).catch((reason: unknown) => {
      if (active) {
        setMessage(errorText(reason));
        setError(true);
        setLoading(false);
      }
    });
    return () => { active = false; };
  }, [router]);

  async function linkGoogle() {
    if (!identityConfig?.googleEnabled || identityConfig.googleMode === "disabled") {
      setError(true);
      setMessage("Google identity linking is not enabled in the server configuration.");
      return;
    }
    setBusy(true);
    setError(false);
    setMessage("Starting a fresh Google proof for this owner account…");
    try {
      const result = await getAuthClient().linkSocial({
        provider: "google",
        callbackURL: `${window.location.origin}/auth/complete?link=google`,
      });
      if (result.error) {
        const code = result.error.code?.toUpperCase();
        const message = code === "IDENTITY_ALREADY_LINKED"
          ? "This Google identity is already bound to another owner. No account or asset merge was performed."
          : "Google did not confirm the explicit identity-link flow. No link was confirmed.";
        throw new ApiError(result.error.status ?? 400, message, code);
      }
      if (result.data?.url && !result.data.redirect) window.location.assign(result.data.url);
      if (!result.data?.redirect && !result.data?.url) throw new Error("Google did not return an authorization redirect.");
      setMessage("Continue through Google. The account page will show the link only after the server confirms it.");
    } catch (reason) {
      setMessage(errorText(reason));
      setError(true);
      setBusy(false);
    }
  }

  async function linkWallet() {
    if (!identityConfig?.siwe.enabled) {
      setError(true);
      setMessage("Wallet identity linking is not enabled in the server configuration.");
      return;
    }
    setBusy(true);
    setError(false);
    setMessage("Requesting a fresh wallet proof bound to this owner session…");
    let linkCommitted = false;
    try {
      const wallet = injectedWallet();
      const rawAccounts = await wallet.request({ method: "eth_requestAccounts" });
      if (!Array.isArray(rawAccounts) || typeof rawAccounts[0] !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(rawAccounts[0])) {
        throw new Error("The selected wallet did not return a supported EOA account.");
      }
      const address = rawAccounts[0] as `0x${string}`;
      const challenge = await apiRequest<{
        operationId: string;
        nonce: string;
        domain: string;
        uri: string;
        chainId: number;
        statement: string;
        issuedAt: string;
        expiresAt: string;
      }>("/api/owner/links/siwe/nonce", { method: "POST", body: JSON.stringify({ operationId: newOperationId() }) });

      if (challenge.domain !== window.location.host || challenge.uri !== window.location.origin) {
        throw new Error("This page origin does not match the server's wallet-link profile. No wallet signature was requested.");
      }
      const rawChainId = stringResult(await wallet.request({ method: "eth_chainId" }), "the active chain");
      if (!/^0x[0-9a-fA-F]+$/.test(rawChainId)) throw new Error("The selected wallet returned an invalid chain identifier.");
      const chainId = Number.parseInt(rawChainId, 16);
      if (!Number.isSafeInteger(chainId) || chainId !== challenge.chainId) {
        throw new Error(`Switch the selected wallet to chain ${challenge.chainId} and retry. No signature was requested.`);
      }

      const message = createSiweMessage({
        address,
        chainId: challenge.chainId,
        domain: challenge.domain,
        nonce: challenge.nonce,
        uri: challenge.uri,
        version: "1",
        statement: challenge.statement,
        issuedAt: new Date(challenge.issuedAt),
        expirationTime: new Date(challenge.expiresAt),
      });
      const signature = stringResult(await wallet.request({ method: "personal_sign", params: [message, address] }), "the SIWE signature");
      const verification = await apiRequest<{ identity: { provider: "wallet" } }>("/api/owner/links/siwe/verify", {
        method: "POST",
        body: JSON.stringify({ operationId: challenge.operationId, message, signature }),
      });
      if (verification.identity.provider !== "wallet") throw new Error("The server response did not confirm a wallet identity link.");
      linkCommitted = true;
      const confirmedOwner = await getCurrentOwner();
      if (!confirmedOwner?.identities.some((identity) => identity.provider === "wallet")) {
        setMessage("The server confirmed the wallet-link operation, but the current owner projection did not show it. Refresh owner settings before retrying.");
        setError(true);
        return;
      }
      setOwner(confirmedOwner);
      setMessage("The server confirmed the wallet identity is linked to this owner.");
    } catch (reason) {
      setMessage(linkCommitted
        ? "The server confirmed the wallet-link operation, but owner state could not be refreshed. Reload owner settings before retrying."
        : errorText(reason));
      setError(true);
    } finally {
      setBusy(false);
    }
  }

  async function signOut() {
    setBusy(true);
    setError(false);
    setMessage("Ending this browser owner session…");
    try {
      const result = await getAuthClient().signOut();
      if (result.error) throw new Error("The server did not confirm sign-out.");
      router.replace("/sign-in");
      router.refresh();
    } catch (reason) {
      setMessage(errorText(reason));
      setError(true);
      setBusy(false);
    }
  }

  if (loading) return <p className="loading" role="status">Checking your admitted owner session…</p>;

  if (!owner) return (
    <section className="card auth-card">
      <h1>Owner session unavailable</h1>
      <p className={`status-box ${error ? "status-error" : ""}`} role="alert">{message || "The server has not returned an admitted owner."}</p>
      <button className="button" type="button" onClick={() => void refreshOwner()}>Check server session again</button>
    </section>
  );

  const hasGoogle = owner.identities.some((identity) => identity.provider === "google");
  const hasWallet = owner.identities.some((identity) => identity.provider === "wallet");
  const walletIdentity = owner.identities.find((identity) => identity.provider === "wallet");

  return (
    <div className="stack">
      <div className="page-heading">
        <p className="eyebrow">Private owner settings</p>
        <h1>Owner account</h1>
        <p className="lede">Review the verified sign-in methods bound to this owner. Adding another method requires a fresh proof.</p>
      </div>
      <div className="content-grid">
        <section className="card span-6" aria-labelledby="identity-title">
          <div className="section-heading">
            <div>
              <h2 id="identity-title">Verified identities</h2>
              <p className="fine">The server projection is the source of truth for linked methods.</p>
            </div>
            <span className="pill pill-success">Admitted</span>
          </div>
          {identityConfig?.googleMode === "provider-fixture" && <div className="notice notice-warning">Google is using a local provider fixture. This is contract evidence only and does not establish actual Google compatibility.</div>}
          {identityConfig?.googleMode === "google" && <p className="fine">Google is configured. Actual account compatibility is established only by the separate provider acceptance gate.</p>}
          {identityConfig?.googleMode === "disabled" && <p className="fine">Google identity linking is disabled by the server configuration.</p>}
          {identityConfig?.siwe.enabled === false && <p className="fine">Wallet identity linking is disabled by the server configuration.</p>}
          {identityConfigUnavailable && <p className="fine">Identity linking is unavailable because the server configuration could not be loaded.</p>}
          <div data-testid="identity-google" className="identity-row">
            <span className="identity-mark" aria-hidden="true">G</span>
            <span className="identity-copy"><strong>Google</strong><small>{owner.identities.find((identity) => identity.provider === "google")?.displayLabel ?? (hasGoogle ? "Verified and linked" : "Not linked")}</small></span>
            <span className={`pill ${hasGoogle ? "pill-success" : ""}`}>{hasGoogle ? "Linked" : "Not linked"}</span>
          </div>
          <div data-testid="identity-siwe" className="identity-row">
            <span className="identity-mark" aria-hidden="true">W</span>
            <span className="identity-copy"><strong>Wallet (SIWE)</strong><small>{walletIdentity?.displayLabel ?? (walletIdentity?.subject ? `${walletIdentity.subject.slice(0, 6)}…${walletIdentity.subject.slice(-4)}` : hasWallet ? "Verified and linked" : "Not linked")}</small></span>
            <span className={`pill ${hasWallet ? "pill-success" : ""}`}>{hasWallet ? "Linked" : "Not linked"}</span>
          </div>
          <hr className="divider" />
          <div className="stack-sm">
            {!hasGoogle && <button className="button" data-testid="link-google" type="button" onClick={() => void linkGoogle()} disabled={busy || !identityConfig?.googleEnabled || identityConfig.googleMode === "disabled"}>Link Google identity</button>}
            {!hasWallet && <button className="button" data-testid="link-wallet" type="button" onClick={() => void linkWallet()} disabled={busy || !identityConfig?.siwe.enabled}>Link browser wallet</button>}
            {hasGoogle && hasWallet && <p className="fine">Both methods resolve to this owner. Linking does not issue a bonus or authorize a payment or withdrawal.</p>}
          </div>
          <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite">{message}</p>
        </section>
        <section className="card span-6" aria-labelledby="owner-info-title">
          <h2 id="owner-info-title">Owner status</h2>
          <dl className="kv-list">
            <dt>Owner reference</dt><dd data-testid="owner-id">{owner.id}</dd>
            <dt>Admission</dt><dd>Admitted</dd>
            <dt>Administration role</dt><dd>{owner.isAdmin ? "Configured administrator" : "Owner"}</dd>
          </dl>
          <hr className="divider" />
          <div className="stack-sm">
            <p className="fine">Sign-out ends this browser session. It does not revoke delegated agent access or prove authorization for a withdrawal.</p>
            <div className="button-row">
              <button className="button" data-testid="sign-out" type="button" onClick={() => void signOut()} disabled={busy}>Sign out</button>
              <button className="button button-small" type="button" onClick={() => void refreshOwner()} disabled={busy}>Refresh server state</button>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
