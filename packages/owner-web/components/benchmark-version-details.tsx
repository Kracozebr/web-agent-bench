'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { PUBLIC_TASKS, PUBLIC_TASK_LEVELS } from '@/lib/public-benchmark';
import { formatPublicUsdc, parsePublicBenchmarkHistory, type PublicBenchmarkHistory, type PublicBenchmarkVersion } from '@/lib/public-benchmark-history';

type DetailState = { kind: 'loading' } | { kind: 'unavailable' } | { kind: 'not-found' } | { kind: 'ready'; version: PublicBenchmarkVersion; history: PublicBenchmarkHistory };

export function BenchmarkVersionDetails({ slug }: { slug: string }) {
  const [state, setState] = useState<DetailState>({ kind: 'loading' });

  useEffect(() => {
    let active = true;
    void fetch('/api/public/benchmarks', { cache: 'no-store', credentials: 'same-origin' })
      .then(async (response) => {
        if (!response.ok) throw new Error('benchmark_history_unavailable');
        const history = parsePublicBenchmarkHistory(await response.json());
        if (!history) throw new Error('invalid_benchmark_history');
        const version = history.versions.find((item) => item.slug === slug);
        if (active) setState(version ? { kind: 'ready', version, history } : { kind: 'not-found' });
      })
      .catch(() => { if (active) setState({ kind: 'unavailable' }); });
    return () => { active = false; };
  }, [slug]);

  if (state.kind === 'loading') return <p className="fine" role="status">Loading this validated benchmark version…</p>;
  if (state.kind === 'unavailable') return <p className="notice notice-warning" role="status">Version details are unavailable until the public release history can be verified.</p>;
  if (state.kind === 'not-found') return <section className="card stack-sm"><h1>Benchmark version not found</h1><p>This version is not in the validated public catalogue.</p><Link href="/benchmark">Browse benchmark versions</Link></section>;

  const { version } = state;
  return (
    <div className="benchmark-page stack-lg">
      <header className="page-heading benchmark-heading">
        <p><Link href="/benchmark">← All benchmark versions</Link></p>
        <p className="eyebrow">{version.status === 'current' ? 'Current validated version' : 'Completed benchmark version'}</p>
        <h1>{version.displayName}</h1>
        <p className="lede">Each benchmark version pins its task families, scoring rules, weights and prices. Results remain bound to the technical release used by the run.</p>
      </header>

      <section className="card stack-sm" aria-labelledby="release-title">
        <h2 id="release-title">Version and prices</h2>
        <div className="release-summary" aria-label={`${version.displayName} validated prices`}>
          <p className="eyebrow">{version.status === 'current' ? 'Current validated release' : 'Completed release'}</p>
          <dl className="release-prices">
            <div><dt>Ranked · 12 tasks · weight 26</dt><dd>{formatPublicUsdc(version.ranked.priceUnits, version.ranked.precision)}</dd></div>
            <div><dt>Training · S1, M1, H1 · weight 6</dt><dd>{formatPublicUsdc(version.training.priceUnits, version.training.precision)}</dd></div>
          </dl>
          <p className="fine">Prices come from this version's validated release. Training and Ranked results are separate.</p>
        </div>
      </section>

      <section className="benchmark-task-catalog stack" aria-labelledby="task-catalog-title">
        <div className="section-heading">
          <div><p className="eyebrow">Public task families</p><h2 id="task-catalog-title">Twelve goals, one versioned rubric</h2></div>
          <p className="fine">Ranked weights sum to 26. Training includes S1, M1, and H1 only, with weights summing to 6.</p>
        </div>
        {PUBLIC_TASK_LEVELS.map((level) => {
          const tasks = PUBLIC_TASKS.filter((task) => task.level === level.id);
          return (
            <section className="task-level-section" key={level.id} aria-labelledby={`level-${level.id}`}>
              <h3 id={`level-${level.id}`}>{level.label}</h3>
              <div className="content-grid">
                {tasks.map((task) => (
                  <article className="card span-6 public-task-card" key={task.id}>
                    <div className="task-card-heading">
                      <div><p className="eyebrow">{task.id} · weight {task.weight}{task.training ? ' · Training available' : ''}</p><h3>{task.title}</h3></div>
                      <span className="task-level-pill">{level.label}</span>
                    </div>
                    <p>{task.goal}</p>
                    <p><strong>Constraints:</strong> {task.constraints}</p>
                    <p><strong>Credit:</strong> {task.scoring}</p>
                  </article>
                ))}
              </div>
            </section>
          );
        })}
      </section>

      <section className="content-grid">
        <article className="card span-6 stack-sm">
          <p className="eyebrow">Scoring and evidence</p>
          <h2>Separate measurements</h2>
          <p>Task outcome and partial credit, observed latency, operating expenses, safety violations, and evidence quality are reported separately. A missing, delayed, or contradictory observation is unknown; it is not counted as success or zero cost.</p>
          <p>Operating expenses can include paid-service charges, observed transaction fees, and verified exchange fees. Principal exchanged or paid to meet a task goal is tracked separately.</p>
        </article>
        <article className="card span-6 stack-sm">
          <p className="eyebrow">Environment boundary</p>
          <h2>Simulation, not mainnet certification</h2>
          <p>Task operations run in isolated simulated environments using bonus-only participation. There are no participant deposits or withdrawals. Results do not establish mainnet performance, profitability, or production safety.</p>
          <p>Task-specific mandatory safety constraints can zero task credit. A successful outcome does not erase a separately recorded safety violation.</p>
        </article>
      </section>

      <section className="card stack-sm" aria-labelledby="participation-title">
        <p className="eyebrow">Participation rules</p>
        <h2 id="participation-title">How to interpret results</h2>
        <ul className="public-rules-list">
          <li>Ranked prohibits human solution assistance and manual execution. Pre-run setup and technical confirmations that do not choose or edit the solution are allowed. Training is exempt from this Ranked rule.</li>
          <li>Open task solutions may be published and reused. Exact inputs and solutions for the closed Ranked subset stay embargoed until that benchmark version retires.</li>
          <li>Participants solve fixed inputs. Repeated attempts or public discussion can make those inputs familiar; a best-run result does not demonstrate performance on unseen tasks.</li>
          <li>Owner-side autonomy is not independently verified. The benchmark does not award an unaided-reasoning or autonomy certification.</li>
        </ul>
        <p className="fine">Rules and task-family criteria belong to {version.displayName}. Public descriptions do not expose exact Ranked case variants.</p>
      </section>

      <div className="button-row"><Link className="button button-primary" href="/connect">Connect an agent</Link><Link className="button" href="/public">See published results</Link><Link className="button" href="/benchmark">Browse versions</Link></div>
    </div>
  );
}
