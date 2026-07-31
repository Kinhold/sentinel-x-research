import type { ScanRunner } from './pipeline.js';

export interface ScanQueueOptions {
  concurrency?: number;
  timeoutMs?: number;
  onError?: (scanId: number, error: unknown) => void;
}

/**
 * Bounded scan executor: concurrency cap + per-scan timeout.
 */
export class ScanQueue {
  private readonly pending: number[] = [];
  private readonly active = new Map<number, Promise<void>>();
  private readonly concurrency: number;
  private readonly timeoutMs: number;
  private readonly onError?: (scanId: number, error: unknown) => void;

  constructor(
    private readonly runner: ScanRunner,
    options: ScanQueueOptions = {},
  ) {
    this.concurrency = Math.max(1, options.concurrency ?? 2);
    this.timeoutMs = Math.max(5_000, options.timeoutMs ?? 10 * 60_000);
    this.onError = options.onError;
  }

  enqueue(scanId: number): void {
    if (this.active.has(scanId) || this.pending.includes(scanId)) return;
    this.pending.push(scanId);
    this.pump();
  }

  size(): { pending: number; active: number } {
    return { pending: this.pending.length, active: this.active.size };
  }

  private pump(): void {
    while (this.active.size < this.concurrency && this.pending.length > 0) {
      const scanId = this.pending.shift()!;
      const job = this.execute(scanId)
        .catch((error) => this.onError?.(scanId, error))
        .finally(() => {
          this.active.delete(scanId);
          this.pump();
        });
      this.active.set(scanId, job);
    }
  }

  private async execute(scanId: number): Promise<void> {
    const timeout = setTimeout(() => {
      try {
        this.runner.cancel(scanId, `Timed out after ${this.timeoutMs}ms`);
      } catch {
        // scan may already be terminal
      }
    }, this.timeoutMs);
    try {
      await this.runner.run(scanId);
    } finally {
      clearTimeout(timeout);
    }
  }
}
