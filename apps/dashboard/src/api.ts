const API_BASE = import.meta.env.VITE_API_BASE ?? '';

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has('content-type')) {
    headers.set('content-type', 'application/json');
  }
  const key = import.meta.env.VITE_API_KEY;
  if (key) headers.set('x-api-key', key);
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // ignore
    }
    throw new Error(message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const client = {
  health: () => api<{ status: string }>('/api/healthz'),
  stats: () => api<DashboardStats>('/api/stats/dashboard'),
  targets: () => api<Target[]>('/api/targets'),
  createTarget: (body: CreateTargetBody) =>
    api<Target>('/api/targets', { method: 'POST', body: JSON.stringify(body) }),
  scans: () => api<Scan[]>('/api/scans'),
  createScan: (targetId: number) =>
    api<Scan>('/api/scans', { method: 'POST', body: JSON.stringify({ targetId }) }),
  cancelScan: (id: number) => api<Scan>(`/api/scans/${id}/cancel`, { method: 'POST' }),
  vulnerabilities: () => api<Vulnerability[]>('/api/vulnerabilities'),
  updateVulnerability: (id: number, status: Vulnerability['status']) =>
    api<Vulnerability>(`/api/vulnerabilities/${id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    }),
  report: (vulnerabilityId: number) => api<Report>(`/api/reports/${vulnerabilityId}`),
  sarif: (scanId?: number) =>
    api<unknown>(`/api/exports/sarif${scanId != null ? `?scanId=${scanId}` : ''}`),
  metrics: () => api<Record<string, unknown>>('/api/metrics'),
  provenance: (scanId: number) =>
    api<{ scanId: number; chainValid: boolean; entries: unknown[] }>(`/api/provenance/${scanId}`),
};

export type TargetLanguage = 'rust' | 'noir' | 'solana';

export interface Target {
  id: number;
  repoUrl: string;
  name: string;
  language: TargetLanguage;
  description?: string | null;
  bountyPlatform?: string | null;
  maxPayout?: number | null;
  createdAt: string;
}

export interface CreateTargetBody {
  repoUrl: string;
  name: string;
  language: TargetLanguage;
  description?: string | null;
  maxPayout?: number | null;
}

export interface Scan {
  id: number;
  targetId: number;
  status: 'pending' | 'running' | 'completed' | 'failed';
  phase?: string | null;
  bugsFound: number;
  bugsVerified: number;
  sourceMode?: string | null;
  errorMessage?: string | null;
  target?: Target | null;
}

export interface Vulnerability {
  id: number;
  scanId: number;
  title: string;
  severity: string;
  status: 'discovered' | 'verified' | 'false_positive' | 'reported';
  vulnType: string;
  targetLanguage: string;
  ruleId?: string | null;
  confidenceScore?: number | null;
  estimatedPayout?: number | null;
}

export interface Report {
  vulnerabilityId: number;
  markdown: string;
  title: string;
  severity: string;
  generatedAt: string;
}

export interface DashboardStats {
  totalScans: number;
  activeScans: number;
  totalTargets: number;
  totalVulnerabilities: number;
  verifiedVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  payoutPotential: number;
  recentActivity: Array<{ id: number; type: string; message: string; timestamp: string }>;
}

export function streamScanLogs(
  scanId: number,
  onEvent: (entry: { level: string; phase: string; message: string; timestamp: string }) => void,
  onComplete: (status: string) => void,
): () => void {
  const source = new EventSource(`${API_BASE}/api/logs/${scanId}`);
  source.onmessage = (event) => {
    try {
      onEvent(JSON.parse(event.data));
    } catch {
      // ignore malformed chunks
    }
  };
  source.addEventListener('complete', (event) => {
    try {
      const payload = JSON.parse((event as MessageEvent).data) as { status: string };
      onComplete(payload.status);
    } catch {
      onComplete('unknown');
    }
    source.close();
  });
  source.onerror = () => {
    source.close();
  };
  return () => source.close();
}
