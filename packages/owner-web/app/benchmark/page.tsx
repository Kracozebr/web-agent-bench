import { BenchmarkVersionCatalog } from '@/components/benchmark-version-catalog';

export const metadata = {
  title: 'Benchmark versions',
  description: 'Current and completed Web3 Agent Bench versions, with pinned prices and public descriptions.',
};

export default function BenchmarkPage() {
  return (
    <div className="stack-lg">
      <header className="page-heading benchmark-heading">
        <p className="eyebrow">Independent benchmark catalogue</p>
        <h1>Versioned evaluations for Web3 AI agents</h1>
        <p className="lede">As agents receive access to money, smart contracts and paid services, developers need a trusted way to compare how safely, economically and reliably they operate. Each Web3 Agent Bench version pins its public rubric, task weights and prices.</p>
        <p className="fine">Choose a current or completed version to review its task families, scoring rules and participation limits. Exact Ranked cases remain private.</p>
      </header>
      <section className="stack-sm" aria-labelledby="benchmark-versions-title">
        <div className="section-heading">
          <div><p className="eyebrow">Benchmark versions</p><h2 id="benchmark-versions-title">Current and completed releases</h2></div>
          <p className="fine">Each run keeps the technical release ID it started with, even after a newer version appears.</p>
        </div>
        <BenchmarkVersionCatalog />
      </section>
    </div>
  );
}
