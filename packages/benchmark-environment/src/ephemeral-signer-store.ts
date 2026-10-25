/**
 * This store never returns private-key bytes; callers receive a short-lived
 * viem account only inside a scoped callback.
 */
import type { Address, Hex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

export type SignerScope = { envId: string; generationId: string };
type Entry = { keyBytes: Buffer; address: Address; expiresAtMs: number; timer: ReturnType<typeof setTimeout> };
type EphemeralAccount = ReturnType<typeof privateKeyToAccount>;

const KEY_PATTERN = /^0x[0-9a-f]{64}$/i;
const MAX_TIMER_MS = 2_147_000_000;

function scopeKey(scope: SignerScope): string {
  return `${scope.envId.length}:${scope.envId}${scope.generationId}`;
}

/**
 * AICODE-NOTE: Generation keys exist only in this process. The admin route must
 * derive/validate the address and complete input checks before calling put().
 * Reset, fence, setup failure, expiry, and shutdown must erase the matching
 * scope. A restart naturally starts with an empty map and cannot recover keys.
 */
export class EphemeralSignerStore {
  private readonly entries = new Map<string, Entry>();

  put(scope: SignerScope, privateKey: Hex, expectedAddress: Address, expiresAtMs: number): Address {
    if (!KEY_PATTERN.test(privateKey) || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
      throw new Error('ephemeral_signer_input_invalid');
    }
    const derivedAddress = privateKeyToAccount(privateKey).address;
    if (derivedAddress.toLowerCase() !== expectedAddress.toLowerCase()) throw new Error('ephemeral_signer_payer_mismatch');

    const key = scopeKey(scope);
    this.eraseByKey(key);
    const entry: Entry = {
      keyBytes: Buffer.from(privateKey.slice(2), 'hex'),
      address: derivedAddress,
      expiresAtMs,
      timer: setTimeout(() => this.expireEntry(key, entry), Math.min(expiresAtMs - Date.now(), MAX_TIMER_MS)),
    };
    entry.timer.unref?.();
    this.entries.set(key, entry);
    return entry.address;
  }

  async withAccount<T>(scope: SignerScope, work: (account: EphemeralAccount) => Promise<T>): Promise<T> {
    const key = scopeKey(scope);
    const entry = this.entries.get(key);
    if (!entry || entry.expiresAtMs <= Date.now()) {
      this.eraseByKey(key);
      throw new Error('ephemeral_signer_unavailable');
    }
    const privateKey = `0x${entry.keyBytes.toString('hex')}` as Hex;
    const account = privateKeyToAccount(privateKey);
    if (account.address.toLowerCase() !== entry.address.toLowerCase()) {
      this.eraseByKey(key);
      throw new Error('ephemeral_signer_integrity_failure');
    }
    try {
      return await work(account);
    } finally {
      if (entry.expiresAtMs <= Date.now()) this.eraseByKey(key);
    }
  }

  eraseGeneration(scope: SignerScope): void {
    this.eraseByKey(scopeKey(scope));
  }

  eraseEnvironment(envId: string): void {
    for (const [key, entry] of this.entries) {
      if (key.startsWith(`${envId.length}:${envId}`)) this.eraseByKey(key, entry);
    }
  }

  eraseAll(): void {
    for (const [key, entry] of this.entries) this.eraseByKey(key, entry);
  }

  has(scope: SignerScope): boolean {
    const key = scopeKey(scope);
    const entry = this.entries.get(key);
    if (!entry || entry.expiresAtMs <= Date.now()) {
      this.eraseByKey(key);
      return false;
    }
    return true;
  }

  private expireEntry(key: string, entry: Entry): void {
    if (this.entries.get(key) !== entry) return;
    const remaining = entry.expiresAtMs - Date.now();
    if (remaining > 0) {
      entry.timer = setTimeout(() => this.expireEntry(key, entry), Math.min(remaining, MAX_TIMER_MS));
      entry.timer.unref?.();
      return;
    }
    this.eraseByKey(key, entry);
  }

  private eraseByKey(key: string, expected?: Entry): void {
    const entry = this.entries.get(key);
    if (!entry || (expected && entry !== expected)) return;
    clearTimeout(entry.timer);
    entry.keyBytes.fill(0);
    this.entries.delete(key);
  }
}
