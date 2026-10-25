export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] | object }): Promise<unknown>;
}

declare global {
  interface Window {
    ethereum?: Eip1193Provider;
  }
}

export function injectedWallet(): Eip1193Provider {
  if (!window.ethereum) {
    throw new Error("No EIP-1193 browser wallet is available. Install or enable the selected wallet, then reload this page.");
  }
  return window.ethereum;
}

export function stringResult(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`The wallet did not return ${label}.`);
  return value;
}
