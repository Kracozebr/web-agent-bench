"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/sign-in", label: "Sign in" },
  { href: "/account", label: "Owner account" },
  { href: "/agents", label: "Agents" },
  { href: "/billing", label: "Billing" },
  { href: "/admin", label: "Administration" },
];

export function SiteHeader() {
  const pathname = usePathname();

  return (
    <header className="topbar">
      <Link className="brand" href="/sign-in" aria-label="Web3 Agent Bench owner access home">
        <span className="brand-mark" aria-hidden="true">W3</span>
        <span className="brand-copy">
          <strong>Web3 Agent Bench</strong>
          <small>Owner access</small>
        </span>
      </Link>
      <nav className="topnav" aria-label="Owner navigation">
        {links.map((link) => (
          <Link
            key={link.href}
            href={link.href}
            aria-current={pathname === link.href || (link.href === "/billing" && pathname.startsWith("/billing/")) ? "page" : undefined}
          >
            {link.label}
          </Link>
        ))}
      </nav>
    </header>
  );
}
