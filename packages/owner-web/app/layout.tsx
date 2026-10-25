import type { Metadata } from "next";
import "./globals.css";
import { SiteHeader } from "@/components/site-header";

export const metadata: Metadata = {
  title: {
    default: "Owner access · Web3 Agent Bench",
    template: "%s · Web3 Agent Bench",
  },
  description: "Private owner sign-in and pilot admission controls.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">Skip to content</a>
        <div className="app-shell">
          <SiteHeader />
          <main id="main-content" className="main-content">{children}</main>
          <footer className="site-footer">
            <span>Web3 Agent Bench</span>
            <span>Authentication and admission are verified by the server.</span>
          </footer>
        </div>
      </body>
    </html>
  );
}
