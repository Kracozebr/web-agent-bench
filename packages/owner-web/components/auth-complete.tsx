"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { errorText, getCurrentOwner } from "@/lib/api";

export function AuthComplete() {
  const router = useRouter();
  const [message, setMessage] = useState("Checking the verified owner session…");
  const [error, setError] = useState(false);

  useEffect(() => {
    let active = true;
    const parameters = new URLSearchParams(window.location.search);
    const queryError = parameters.get("error");
    const expectedLink = parameters.get("link");
    if (queryError) {
      const code = queryError.toUpperCase();
      const identityConflict = code.includes("IDENTITY_ALREADY_LINKED") || code.includes("ACCOUNT_ALREADY_LINKED");
      setMessage(expectedLink
        ? identityConflict
          ? "This identity is already bound to another owner. It was not moved or merged."
          : "The identity provider did not complete the link proof. No identity link was confirmed."
        : "The identity provider did not complete verification. No owner session was confirmed.");
      setError(true);
      return () => { active = false; };
    }

    void getCurrentOwner().then((owner) => {
      if (!active) return;
      if (!owner) {
        setMessage("The server did not confirm a sign-in session. Return to sign-in and try again.");
        setError(true);
      } else if (expectedLink && !owner.identities.some((identity) => identity.provider === expectedLink)) {
        setMessage("The owner API did not show the requested identity as linked. Refresh owner settings before trying again.");
        setError(true);
      } else if (owner.admissionStatus === "pending") {
        router.replace("/activate");
      } else {
        router.replace("/account");
      }
    }).catch((reason: unknown) => {
      if (!active) return;
      setMessage(errorText(reason));
      setError(true);
    });

    return () => { active = false; };
  }, [router]);

  return (
    <section className="card auth-card" aria-labelledby="complete-title">
      <p className="eyebrow">Authentication check</p>
      <h1 id="complete-title">Confirming your sign-in</h1>
      <p className={`status-box ${error ? "status-error" : ""}`} role={error ? "alert" : "status"} aria-live="polite">{message}</p>
      {error && <a className="button button-primary" href="/sign-in">Return to sign-in</a>}
    </section>
  );
}
