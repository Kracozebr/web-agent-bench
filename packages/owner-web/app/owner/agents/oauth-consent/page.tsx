import type { Metadata } from "next";
import { OAuthConsentPanel } from "@/components/oauth-consent-panel";

export const metadata: Metadata = {
  title: "Review agent access",
  referrer: "no-referrer",
};

export default function OAuthConsentPage() {
  return <OAuthConsentPanel />;
}
