"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const publicLinks = [
  { href: "/benchmark", label: "Benchmark" },
  { href: "/connect", label: "Connect an agent" },
  { href: "/public", label: "Published results" },
];
const ownerLinks = [
  { href: "/account", label: "Owner account" },
  { href: "/agents", label: "Agents" },
  { href: "/runs", label: "Runs" },
  { href: "/billing", label: "Billing" },
  { href: "/reports", label: "Reports / Support" },
  { href: "/admin", label: "Administration" },
];

export function SiteHeader({ isAuthenticated = false, isAdmin = false }: { isAuthenticated?: boolean; isAdmin?: boolean }) {
  const pathname = usePathname();
  const links = [
    ...publicLinks,
    ...(isAuthenticated ? ownerLinks : [{ href: "/sign-in", label: "Sign in" }]),
  ];

  return (
    <header className="topbar">
      <Link className="brand" href="/" aria-label="Web3 Agent Bench home">
        <span className="brand-mark" aria-hidden="true">W3</span>
        <span className="brand-copy">
          <strong>Web3 Agent Bench</strong>
          <small>Independent Web3 agent benchmark</small>
        </span>
      </Link>
      <nav className="topnav" aria-label="Main navigation">
        {links.filter((link) => link.href !== "/admin" || isAdmin).map((link) => (
          <Link
            key={link.href}
            href={link.href}
            aria-current={pathname === link.href || (link.href === "/billing" && pathname.startsWith("/billing/")) ||
              (link.href === "/public" && pathname.startsWith("/public/agents/")) ||
              (link.href === "/benchmark" && pathname.startsWith("/benchmark/")) ||
              (link.href === "/reports" && (pathname.startsWith("/reports/") || pathname.startsWith("/diagnostics"))) ||
              (link.href === "/admin" && pathname.startsWith("/admin/")) ? "page" : undefined}
          >
            {link.label}
          </Link>
        ))}
      </nav>
    </header>
  );
}
