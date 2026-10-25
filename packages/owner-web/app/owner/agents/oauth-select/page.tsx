import type { Metadata } from "next";
import { OAuthAgentSelectPanel } from "@/components/oauth-agent-select-panel";

export const metadata: Metadata = {
  title: "Select an agent",
  referrer: "no-referrer",
};

export default function OAuthAgentSelectPage() {
  return <OAuthAgentSelectPanel />;
}
