'use client';

import { useParams } from 'next/navigation';
import { BenchmarkVersionDetails } from '@/components/benchmark-version-details';

export default function BenchmarkVersionPage() {
  const params = useParams<{ version: string }>();
  return <BenchmarkVersionDetails slug={params.version} />;
}
