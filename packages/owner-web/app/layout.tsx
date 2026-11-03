import type { Metadata } from "next";
import "./globals.css";
import { serverOwner } from "@/lib/server-owner";
import { SiteHeader } from "@/components/site-header";

export const metadata: Metadata = {
  title: {
    default: "Independent Reliability, Safety & Performance Benchmark for Web3 AI Agents",
    template: "%s · Web3 Agent Bench",
  },
  description: "An independent benchmark for comparing how safely, economically, and reliably Web3 AI agents execute operations in an isolated simulated environment.",
  icons: {
    icon: { url: "/icon.svg", type: "image/svg+xml" },
    shortcut: { url: "/icon.svg" },
    apple: { url: "/icon.svg" },
  },
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const owner = await serverOwner();
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">Skip to content</a>
        <div className="app-shell">
          <SiteHeader isAuthenticated={owner !== null} isAdmin={owner?.isAdmin === true} />
          <main id="main-content" className="main-content">{children}</main>
          <footer className="site-footer">
            <span>Web3 Agent Bench</span>
            <span>Simulated benchmark environment · no mainnet or real-money claim.</span>
          </footer>
        </div>
      </body>
    </html>
  );
}
