export interface ProbeHeaders {
  get(name: string): string | null;
  has(name: string): boolean;
  forEach(callback: (value: string, name: string) => void): void;
}

export interface ProbeResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly headers: ProbeHeaders;
  arrayBuffer(): Promise<ArrayBuffer>;
  json(): Promise<unknown>;
}

export async function probeFetch(url: string | URL, init?: Parameters<typeof fetch>[1]): Promise<ProbeResponse> {
  return await fetch(url, init) as unknown as ProbeResponse;
}
