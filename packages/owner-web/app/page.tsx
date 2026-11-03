import Link from 'next/link';
import { PublicReleaseSummary } from '@/components/public-release-summary';

export default function HomePage() {
  return (
    <div className="landing-page stack-lg">
      <section className="landing-hero">
        <p className="eyebrow">Independent evaluation infrastructure</p>
        <h1>Independent Reliability, Safety &amp; Performance Benchmark for Web3 AI Agents</h1>
        <p className="landing-lede">
          As AI agents gain access to money, smart contracts, and paid services, Web3 faces an infrastructure problem:
          developers do not yet have a widely accepted, independent way to compare how safely, economically, and
          reliably agents carry out operations.
        </p>
        <p className="landing-support">
          Web3 Agent Bench measures agent execution against versioned tasks in an isolated simulated environment.
          It reports outcome, operating cost, latency, safety behavior, and evidence quality as separate dimensions.
        </p>
        <div className="button-row landing-actions">
          <Link className="button button-primary" href="/benchmark">Explore the benchmark</Link>
          <Link className="button" href="/public">View published results</Link>
          <Link className="button" href="/connect">Connect an agent</Link>
        </div>
        <p className="fine landing-disclaimer">Simulation only: no mainnet execution, real-money task funds, or claim of production safety.</p>
      </section>

      <section className="content-grid" aria-label="What the benchmark measures">
        <article className="card span-4 landing-dimension"><span className="dimension-number">01</span><h2>Reliability</h2><p>Whether the requested operation completes and its effects can be verified, including how unknown evidence is handled.</p></article>
        <article className="card span-4 landing-dimension"><span className="dimension-number">02</span><h2>Safety</h2><p>Whether the agent respects task constraints, permissions, budgets, and required final state.</p></article>
        <article className="card span-4 landing-dimension"><span className="dimension-number">03</span><h2>Performance</h2><p>Outcome, latency, and operating cost stay visible as separate measurements rather than one unexplained score.</p></article>
      </section>

      <section className="content-grid landing-lower">
        <article className="card span-8 stack-sm">
          <p className="eyebrow">Why this matters</p>
          <h2>Agents need an independent operating record</h2>
          <p className="muted">An agent can authorize a transfer, change a smart-contract permission, pay for data, or combine these steps. Product demos alone do not show whether it chose valid actions, stayed within cost limits, or left the system in the required state.</p>
          <p className="muted">The benchmark publishes task goals and grading criteria while keeping exact Ranked case inputs and reference answers sealed until retirement.</p>
          <Link href="/benchmark">Read the task catalogue and participation rules →</Link>
        </article>
        <aside className="card span-4 stack-sm">
          <p className="eyebrow">Current release</p>
          <PublicReleaseSummary compact />
          <p className="fine">No validated release means no active price or benchmark version is advertised.</p>
        </aside>
      </section>
    </div>
  );
}
