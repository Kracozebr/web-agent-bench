'use client';

import { useEffect, useState } from 'react';
import { taskProjectionMatches } from '@/lib/public-benchmark';

type ReleaseState =
  | { kind: 'loading' }
  | { kind: 'unavailable' }
  | { kind: 'active'; version: string; rankedPrice: string; trainingPrice: string };

function formatUsdc(units: string, precision: number): string {
  if (!/^(?:0|[1-9][0-9]{0,77})$/.test(units) || precision !== 6) throw new Error('invalid_public_price');
  const value = BigInt(units);
  const precisionUnits = BigInt('1000000');
  const whole = (value / precisionUnits).toString();
  const fraction = (value % precisionUnits).toString().padStart(6, '0').replace(/0+$/, '').padEnd(2, '0');
  return `${whole}.${fraction} USDC`;
}

export function PublicReleaseSummary({ compact = false }: { compact?: boolean }) {
  const [state, setState] = useState<ReleaseState>({ kind: 'loading' });

  useEffect(() => {
    let active = true;
    void fetch('/api/public/catalog', { cache: 'no-store', credentials: 'same-origin' })
      .then(async (response) => {
        if (!response.ok) throw new Error('public_catalog_unavailable');
        const body = await response.json() as {
          catalogStatus?: string;
          benchmarkVersion?: string;
          ranked?: { priceUnits?: string; precision?: number };
          training?: { priceUnits?: string; precision?: number };
          tasks?: unknown;
        };
        if (body.catalogStatus !== 'active' || !body.benchmarkVersion || !body.ranked?.priceUnits ||
            !body.training?.priceUnits || !taskProjectionMatches(body.tasks)) {
          if (active) setState({ kind: 'unavailable' });
          return;
        }
        const rankedPrice = formatUsdc(body.ranked.priceUnits, body.ranked.precision ?? 0);
        const trainingPrice = formatUsdc(body.training.priceUnits, body.training.precision ?? 0);
        if (active) setState({ kind: 'active', version: body.benchmarkVersion, rankedPrice, trainingPrice });
      })
      .catch(() => { if (active) setState({ kind: 'unavailable' }); });
    return () => { active = false; };
  }, []);

  if (state.kind === 'loading') return <p className="fine" role="status">Release prices load from the current validated catalog. If no active release is available, the page will not invent a version or price.</p>;
  if (state.kind === 'unavailable') {
    return <p className="notice notice-warning" role="status">Current release and prices are unavailable in this preview. The public rubric below is explanatory and does not activate a benchmark release.</p>;
  }

  return (
    <div className={compact ? 'release-summary release-summary-compact' : 'release-summary'} aria-label="Current validated benchmark release">
      <p className="eyebrow">Validated release · {state.version}</p>
      <dl className="release-prices">
        <div><dt>Ranked · 12 tasks · weight 26</dt><dd>{state.rankedPrice}</dd></div>
        <div><dt>Training · S1, M1, H1 · weight 6</dt><dd>{state.trainingPrice}</dd></div>
      </dl>
      <p className="fine">Prices are read from the active validated release. Training and Ranked results are separate.</p>
    </div>
  );
}
