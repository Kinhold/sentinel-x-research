import { createHash } from 'node:crypto';

export interface WebhookEvent {
  type: 'scan.completed' | 'scan.failed' | 'vulnerability.verified';
  scanId: number;
  timestamp: string;
  payload: Record<string, unknown>;
}

export interface WebhookDispatcherOptions {
  urls?: string[];
  secret?: string | null;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export async function dispatchWebhooks(
  event: WebhookEvent,
  options: WebhookDispatcherOptions = {},
): Promise<Array<{ url: string; ok: boolean; status?: number; error?: string }>> {
  const urls = options.urls ?? parseWebhookUrls(process.env.WEBHOOK_URLS);
  if (urls.length === 0) return [];
  const fetchImpl = options.fetchImpl ?? fetch;
  const body = JSON.stringify(event);
  const secret = options.secret ?? process.env.WEBHOOK_SECRET ?? null;
  const signature = secret
    ? createHash('sha256').update(`${secret}.${body}`).digest('hex')
    : null;

  const results: Array<{ url: string; ok: boolean; status?: number; error?: string }> = [];
  for (const url of urls) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 5_000);
      const response = await fetchImpl(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-sentinel-event': event.type,
          ...(signature ? { 'x-sentinel-signature': signature } : {}),
        },
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);
      results.push({ url, ok: response.ok, status: response.status });
    } catch (error) {
      results.push({
        url,
        ok: false,
        error: error instanceof Error ? error.message : 'webhook failed',
      });
    }
  }
  return results;
}

export function parseWebhookUrls(value?: string): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => /^https?:\/\//i.test(part));
}

/** Tiny token-bucket rate limiter for API surfaces. */
export class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; updatedAt: number }>();

  constructor(
    private readonly capacity = 60,
    private readonly refillPerSecond = 1,
  ) {}

  allow(key: string): boolean {
    const now = Date.now();
    const bucket = this.buckets.get(key) ?? { tokens: this.capacity, updatedAt: now };
    const elapsed = (now - bucket.updatedAt) / 1000;
    bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsed * this.refillPerSecond);
    bucket.updatedAt = now;
    if (bucket.tokens < 1) {
      this.buckets.set(key, bucket);
      return false;
    }
    bucket.tokens -= 1;
    this.buckets.set(key, bucket);
    return true;
  }
}
