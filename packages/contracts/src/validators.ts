import type {
  CreateScanBody,
  CreateCampaignBody,
  CreateTargetBody,
  CreateSuppressionBody,
  TargetLanguage,
  UpdateVulnerabilityBody,
  VulnerabilitySeverity,
  VulnerabilityStatus,
  VulnerabilityType,
} from './types.js';

const TARGET_LANGUAGES = new Set<TargetLanguage>(['rust', 'noir', 'solana']);
const SEVERITIES = new Set<VulnerabilitySeverity>(['critical', 'high', 'medium', 'low', 'informational']);
const VULN_STATUSES = new Set<VulnerabilityStatus>(['discovered', 'verified', 'false_positive', 'reported']);
const VULN_TYPES = new Set<VulnerabilityType>([
  'integer_overflow',
  'reentrancy',
  'access_control',
  'under_constrained_circuit',
  'arithmetic_error',
  'uninitialized_account',
  'cpi_vulnerability',
  'other',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value.trim();
}

function optionalString(value: unknown): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== 'string') throw new Error('Expected string or null');
  return value;
}

function optionalNumber(value: unknown): number | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== 'number' || Number.isNaN(value)) throw new Error('Expected number or null');
  return value;
}

export function parseCreateTargetBody(body: unknown): CreateTargetBody {
  if (!isRecord(body)) throw new Error('Body must be an object');
  const language = requireString(body.language, 'language') as TargetLanguage;
  if (!TARGET_LANGUAGES.has(language)) throw new Error('Unsupported language');
  return {
    repoUrl: requireString(body.repoUrl, 'repoUrl'),
    name: requireString(body.name, 'name'),
    language,
    description: optionalString(body.description),
    bountyPlatform: optionalString(body.bountyPlatform),
    maxPayout: optionalNumber(body.maxPayout),
  };
}

export function parseCreateScanBody(body: unknown): CreateScanBody {
  if (!isRecord(body)) throw new Error('Body must be an object');
  if (typeof body.targetId !== 'number' || !Number.isInteger(body.targetId) || body.targetId < 1) {
    throw new Error('targetId must be a positive integer');
  }
  return { targetId: body.targetId };
}

export function parseCreateCampaignBody(body: unknown): CreateCampaignBody {
  if (!isRecord(body)) throw new Error('Body must be an object');
  const name = requireString(body.name, 'name');
  if (!Array.isArray(body.targetIds) || body.targetIds.length === 0) {
    throw new Error('targetIds must be a non-empty array');
  }
  const targetIds = body.targetIds.map((value, index) => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
      throw new Error(`targetIds[${index}] must be a positive integer`);
    }
    return value;
  });
  return { name, targetIds };
}

export function parseCreateSuppressionBody(body: unknown): CreateSuppressionBody {
  if (!isRecord(body)) throw new Error('Body must be an object');
  const reason = requireString(body.reason, 'reason');
  const fingerprint = optionalString(body.fingerprint);
  const ruleId = optionalString(body.ruleId);
  const pathGlob = optionalString(body.pathGlob);
  if (!fingerprint && !ruleId && !pathGlob) {
    throw new Error('Suppression requires fingerprint, ruleId, or pathGlob');
  }
  return {
    reason,
    fingerprint,
    ruleId,
    pathGlob,
    expiresAt: optionalString(body.expiresAt),
  };
}

export function parseUpdateVulnerabilityBody(body: unknown): UpdateVulnerabilityBody {
  if (!isRecord(body)) throw new Error('Body must be an object');
  const status = requireString(body.status, 'status') as VulnerabilityStatus;
  if (!VULN_STATUSES.has(status)) throw new Error('Unsupported vulnerability status');
  const result: UpdateVulnerabilityBody = { status };
  if (status === 'reported') {
    result.challengeId = requireString(body.challengeId, 'challengeId');
    result.ruleId = typeof body.ruleId === 'string' ? body.ruleId : '';
    result.fingerprint = typeof body.fingerprint === 'string' ? body.fingerprint : '';
    result.affectedFile = typeof body.affectedFile === 'string' ? body.affectedFile : '';
    if (typeof body.lineNumber !== 'number' || !Number.isInteger(body.lineNumber)) {
      throw new Error('lineNumber must be an integer for reported status');
    }
    result.lineNumber = body.lineNumber;
    result.nonce = requireString(body.nonce, 'nonce');
  }
  return result;
}

export function isTargetLanguage(value: string): value is TargetLanguage {
  return TARGET_LANGUAGES.has(value as TargetLanguage);
}

export function isVulnerabilitySeverity(value: string): value is VulnerabilitySeverity {
  return SEVERITIES.has(value as VulnerabilitySeverity);
}

export function isVulnerabilityStatus(value: string): value is VulnerabilityStatus {
  return VULN_STATUSES.has(value as VulnerabilityStatus);
}

export function isVulnerabilityType(value: string): value is VulnerabilityType {
  return VULN_TYPES.has(value as VulnerabilityType);
}

export const SEVERITY_PAYOUT_WEIGHT: Record<VulnerabilitySeverity, number> = {
  critical: 1,
  high: 0.65,
  medium: 0.35,
  low: 0.15,
  informational: 0.05,
};
