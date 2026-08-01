import { useEffect, useState, useTransition, type FormEvent } from 'react';
import {
  client,
  streamScanLogs,
  type CreateTargetBody,
  type DashboardStats,
  type Scan,
  type Target,
  type Vulnerability,
} from './api';

export function App() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [selectedScan, setSelectedScan] = useState<number | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [report, setReport] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const [form, setForm] = useState<CreateTargetBody>({
    name: 'noir-sample',
    repoUrl: 'https://github.com/example/noir-sample',
    language: 'noir',
    maxPayout: 10000,
  });

  async function refresh() {
    const [nextStats, nextTargets, nextScans, nextVulns] = await Promise.all([
      client.stats(),
      client.targets(),
      client.scans(),
      client.vulnerabilities(),
    ]);
    setStats(nextStats);
    setTargets(nextTargets);
    setScans(nextScans);
    setVulns(nextVulns);
  }

  useEffect(() => {
    startTransition(() => {
      void refresh().catch((err: unknown) => {
        setError(err instanceof Error ? err.message : 'Failed to load');
      });
    });
    const id = window.setInterval(() => {
      void refresh().catch(() => undefined);
    }, 4000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (selectedScan == null) return;
    setLogs([]);
    return streamScanLogs(
      selectedScan,
      (entry) => {
        setLogs((prev) => [...prev, `[${entry.phase}/${entry.level}] ${entry.message}`]);
      },
      () => {
        void refresh();
      },
    );
  }, [selectedScan]);

  async function onCreateTarget(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await client.createTarget(form);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Create target failed');
    }
  }

  async function onScan(targetId: number) {
    setError(null);
    try {
      const scan = await client.createScan(targetId);
      setSelectedScan(scan.id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed to start');
    }
  }

  async function onCancel(scanId: number) {
    await client.cancelScan(scanId);
    await refresh();
  }

  async function onOpenReport(vulnerabilityId: number) {
    const next = await client.report(vulnerabilityId);
    setReport(next.markdown);
  }

  async function onMarkReported(vulnerabilityId: number) {
    const challenge = (await fetch(`${import.meta.env.VITE_API_BASE ?? ''}/api/vulnerabilities/${vulnerabilityId}/challenge`, {
      method: 'POST',
      headers: import.meta.env.VITE_API_KEY ? { 'x-api-key': import.meta.env.VITE_API_KEY } : undefined,
    }).then((r) => r.json())) as {
      challengeId: string;
      nonce: string;
      requiredEcho: { ruleId: string; fingerprint: string; affectedFile: string; lineNumber: number };
    };
    await client.updateVulnerabilityReported(vulnerabilityId, challenge);
    await refresh();
  }

  return (
    <div className="app-shell">
      <header className="top-row">
        <div>
          <p className="brand-mark">Sentinel-X</p>
          <p className="brand-sub">
            Defensive AVR operator console. Fixture-first discovery, structural verification, Immunefi
            report shells — never auto-submit.
          </p>
        </div>
        <div className="cta-row">
          <button className="btn ghost" type="button" onClick={() => void refresh()} disabled={pending}>
            Refresh
          </button>
          <button
            className="btn ghost"
            type="button"
            onClick={() => {
              void client.sarif(selectedScan ?? undefined).then((payload) => {
                setReport(JSON.stringify(payload, null, 2));
              });
            }}
          >
            Export SARIF
          </button>
          <button
            className="btn ghost"
            type="button"
            onClick={() => {
              void Promise.all([
                client.metrics(),
                client.risk(selectedScan ?? undefined),
                selectedScan != null ? client.provenance(selectedScan) : null,
                selectedScan != null ? client.attestation(selectedScan) : null,
              ]).then(([metrics, risk, provenance, attestation]) => {
                setReport(JSON.stringify({ metrics, risk, provenance, attestation }, null, 2));
              });
            }}
          >
            Risk / attest
          </button>
        </div>
      </header>

      {stats && (
        <section className="stats" aria-label="Dashboard statistics">
          <div className="stat">
            <span className="label">Targets</span>
            <div className="value">{stats.totalTargets}</div>
          </div>
          <div className="stat">
            <span className="label">Active scans</span>
            <div className="value">{stats.activeScans}</div>
          </div>
          <div className="stat">
            <span className="label">Verified</span>
            <div className="value">{stats.verifiedVulnerabilities}</div>
          </div>
          <div className="stat">
            <span className="label">Payout lane</span>
            <div className="value">${Math.round(stats.payoutPotential).toLocaleString()}</div>
          </div>
        </section>
      )}

      {error && <p className="error">{error}</p>}

      <div className="grid-2" style={{ marginTop: '1rem' }}>
        <section className="panel">
          <h2>Provision target</h2>
          <form className="form-grid" onSubmit={onCreateTarget}>
            <label>
              Name
              <input
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                required
              />
            </label>
            <label>
              Repo URL
              <input
                value={form.repoUrl}
                onChange={(e) => setForm((f) => ({ ...f, repoUrl: e.target.value }))}
                required
              />
            </label>
            <label>
              Language
              <select
                value={form.language}
                onChange={(e) =>
                  setForm((f) => ({ ...f, language: e.target.value as CreateTargetBody['language'] }))
                }
              >
                <option value="rust">rust</option>
                <option value="noir">noir</option>
                <option value="solana">solana</option>
              </select>
            </label>
            <label>
              Max payout
              <input
                type="number"
                value={form.maxPayout ?? ''}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    maxPayout: e.target.value === '' ? null : Number(e.target.value),
                  }))
                }
              />
            </label>
            <button className="btn" type="submit">
              Add target
            </button>
          </form>
        </section>

        <section className="panel">
          <h2>Targets</h2>
          <div className="list">
            {targets.map((target) => (
              <div className="list-item" key={target.id}>
                <strong>{target.name}</strong>
                <span className="meta">
                  {target.language} · {target.repoUrl}
                </span>
                <div className="cta-row">
                  <button className="btn" type="button" onClick={() => void onScan(target.id)}>
                    Start scan
                  </button>
                </div>
              </div>
            ))}
            {targets.length === 0 && <p className="meta">No targets yet. Seed from fixtures or clone allowlisted repos.</p>}
          </div>
        </section>
      </div>

      <div className="grid-2">
        <section className="panel">
          <h2>Scans</h2>
          <div className="list">
            {scans.map((scan) => (
              <button
                type="button"
                className={`list-item ${selectedScan === scan.id ? 'active' : ''}`}
                key={scan.id}
                onClick={() => setSelectedScan(scan.id)}
                style={{ textAlign: 'left', width: '100%', background: 'transparent' }}
              >
                <strong>
                  Scan #{scan.id} <span className={`pill ${scan.status}`}>{scan.status}</span>
                </strong>
                <span className="meta">
                  {scan.target?.name ?? `target ${scan.targetId}`} · {scan.bugsVerified}/{scan.bugsFound} verified
                  {scan.sourceMode ? ` · ${scan.sourceMode}` : ''}
                </span>
                {(scan.status === 'running' || scan.status === 'pending') && (
                  <span
                    className="btn ghost"
                    role="link"
                    onClick={(e) => {
                      e.stopPropagation();
                      void onCancel(scan.id);
                    }}
                  >
                    Cancel
                  </span>
                )}
              </button>
            ))}
          </div>
          {selectedScan != null && (
            <div className="log-stream" aria-live="polite">
              {logs.length ? logs.join('\n') : 'Waiting for scan log stream…'}
            </div>
          )}
        </section>

        <section className="panel">
          <h2>Findings</h2>
          <div className="list">
            {vulns.map((vuln) => (
              <div className="list-item" key={vuln.id}>
                <strong>
                  {vuln.title} <span className={`pill ${vuln.severity}`}>{vuln.severity}</span>{' '}
                  <span className={`pill ${vuln.status}`}>{vuln.status}</span>
                </strong>
                <span className="meta">
                  {vuln.vulnType}
                  {vuln.ruleId ? ` · ${vuln.ruleId}` : ''}
                  {vuln.confidenceScore != null ? ` · ${(vuln.confidenceScore * 100).toFixed(0)}%` : ''}
                </span>
                <div className="cta-row">
                  <button className="btn ghost" type="button" onClick={() => void onOpenReport(vuln.id)}>
                    Report
                  </button>
                  {vuln.status === 'verified' && (
                    <button className="btn" type="button" onClick={() => void onMarkReported(vuln.id)}>
                      Mark reported
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
          {report && <pre className="report">{report}</pre>}
        </section>
      </div>
    </div>
  );
}
