import type { DiscoveryFinding, Scan, Target } from '@sentinel-x/contracts';
import type { SentinelStore } from '@sentinel-x/storage';
import type { ScanQueue } from './queue.js';
import { portfolioRiskScore } from './hypothesis.js';

export interface CampaignPlan {
  id: number;
  name: string;
  targetIds: number[];
  scanIds: number[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'mixed';
  createdAt: string;
}

export function createAndEnqueueCampaign(
  store: SentinelStore,
  queue: ScanQueue,
  input: { name: string; targetIds: number[] },
): CampaignPlan {
  if (!input.name.trim()) throw new Error('Campaign name required');
  if (!input.targetIds.length) throw new Error('Campaign requires at least one target');
  for (const targetId of input.targetIds) {
    if (!store.getTarget(targetId)) throw new Error(`Target ${targetId} not found`);
  }
  const campaign = store.createCampaign(input.name.trim(), input.targetIds);
  const scanIds: number[] = [];
  for (const targetId of input.targetIds) {
    const scan = store.createScan(targetId);
    store.linkCampaignScan(campaign.id, scan.id);
    queue.enqueue(scan.id);
    scanIds.push(scan.id);
  }
  return {
    id: campaign.id,
    name: campaign.name,
    targetIds: input.targetIds,
    scanIds,
    status: 'pending',
    createdAt: campaign.createdAt,
  };
}

export function getCampaignStatus(store: SentinelStore, campaignId: number): {
  campaign: { id: number; name: string; createdAt: string };
  scans: Scan[];
  targets: Target[];
  status: CampaignPlan['status'];
  risk: ReturnType<typeof portfolioRiskScore>;
} | null {
  const campaign = store.getCampaign(campaignId);
  if (!campaign) return null;
  const scans = store.listCampaignScans(campaignId);
  const targets = campaign.targetIds
    .map((id) => store.getTarget(id))
    .filter((t): t is Target => Boolean(t));
  const statuses = new Set(scans.map((s) => s.status));
  let status: CampaignPlan['status'] = 'pending';
  if (statuses.has('running') || statuses.has('pending')) status = statuses.has('running') ? 'running' : 'pending';
  else if (statuses.size === 1 && statuses.has('completed')) status = 'completed';
  else if (statuses.size === 1 && statuses.has('failed')) status = 'failed';
  else status = 'mixed';

  const vulns = scans.flatMap((scan) => store.listVulnerabilities({ scanId: scan.id }));
  return {
    campaign: { id: campaign.id, name: campaign.name, createdAt: campaign.createdAt },
    scans,
    targets,
    status,
    risk: portfolioRiskScore(vulns),
  };
}

export function applySuppressions(
  findings: DiscoveryFinding[],
  suppressions: Array<{ fingerprint?: string | null; ruleId?: string | null; pathGlob?: string | null }>,
): { kept: DiscoveryFinding[]; suppressed: DiscoveryFinding[] } {
  const kept: DiscoveryFinding[] = [];
  const suppressed: DiscoveryFinding[] = [];
  for (const finding of findings) {
    const hit = suppressions.some((sup) => {
      if (sup.fingerprint && finding.fingerprint && sup.fingerprint === finding.fingerprint) return true;
      if (sup.ruleId && finding.ruleId && sup.ruleId === finding.ruleId) return true;
      if (sup.pathGlob && finding.affectedFile && matchSimpleGlob(finding.affectedFile, sup.pathGlob)) return true;
      return false;
    });
    if (hit) suppressed.push(finding);
    else kept.push(finding);
  }
  return { kept, suppressed };
}

function matchSimpleGlob(path: string, glob: string): boolean {
  const normalized = path.replace(/\\/g, '/');
  const pattern = glob
    .replace(/\\/g, '/')
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '::DOUBLE::')
    .replace(/\*/g, '[^/]*')
    .replace(/::DOUBLE::/g, '.*');
  return new RegExp(`^${pattern}$`, 'i').test(normalized);
}
