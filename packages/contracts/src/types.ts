export type TargetLanguage = 'rust' | 'noir' | 'solana';
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';
export type ScanPhase = 'discovery' | 'verification' | 'reporting' | 'idle';
export type VulnerabilitySeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type VulnerabilityStatus = 'discovered' | 'verified' | 'false_positive' | 'reported';
export type VulnerabilityType =
  | 'integer_overflow'
  | 'reentrancy'
  | 'access_control'
  | 'under_constrained_circuit'
  | 'arithmetic_error'
  | 'uninitialized_account'
  | 'cpi_vulnerability'
  | 'other';
export type ActivityType =
  | 'scan_started'
  | 'bug_found'
  | 'bug_verified'
  | 'scan_completed'
  | 'scan_cancelled'
  | 'report_generated';

export interface HealthStatus {
  status: string;
  requestId?: string;
}

export interface ApiError {
  error: string;
  requestId?: string;
  code?: string;
}

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
  bountyPlatform?: string | null;
  maxPayout?: number | null;
}

export type ScanSourceMode = 'fixture' | 'clone' | 'workspace';

export interface Scan {
  id: number;
  targetId: number;
  status: ScanStatus;
  phase?: ScanPhase | null;
  startedAt?: string | null;
  completedAt?: string | null;
  createdAt: string;
  errorMessage?: string | null;
  bugsFound: number;
  bugsVerified: number;
  sourceMode?: ScanSourceMode | null;
  sourcePath?: string | null;
  sourceCommit?: string | null;
  target?: Target | null;
}

export interface CreateScanBody {
  targetId: number;
}

export interface Vulnerability {
  id: number;
  scanId: number;
  targetId: number;
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  vulnType: VulnerabilityType;
  targetLanguage: TargetLanguage;
  status: VulnerabilityStatus;
  affectedFile?: string | null;
  affectedFunction?: string | null;
  lineNumber?: number | null;
  pocCode?: string | null;
  fvHarness?: string | null;
  fvLog?: string | null;
  counterExample?: string | null;
  estimatedPayout?: number | null;
  confidenceScore?: number | null;
  ruleId?: string | null;
  fingerprint?: string | null;
  createdAt: string;
  verifiedAt?: string | null;
}

export interface UpdateVulnerabilityBody {
  status: VulnerabilityStatus;
}

export interface Report {
  vulnerabilityId: number;
  markdown: string;
  title: string;
  severity: string;
  generatedAt: string;
}

export interface ActivityItem {
  id: number;
  type: ActivityType;
  message: string;
  timestamp: string;
  severity?: string | null;
}

export interface SeverityCount {
  severity: string;
  count: number;
  verified: number;
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
  recentActivity: ActivityItem[];
  severityBreakdown: SeverityCount[];
}

export interface TargetPayout {
  targetId: number;
  targetName: string;
  payout: number;
  verifiedCount: number;
}

export interface SeverityPayout {
  severity: string;
  payout: number;
  count: number;
}

export interface PayoutPotential {
  total: number;
  byTarget: TargetPayout[];
  bySeverity: SeverityPayout[];
}

export interface ScanLogEntry {
  scanId: number;
  level: 'info' | 'warn' | 'error';
  phase: ScanPhase;
  message: string;
  timestamp: string;
}

export interface DiscoveryFinding {
  title: string;
  description: string;
  severity: VulnerabilitySeverity;
  vulnType: VulnerabilityType;
  affectedFile?: string;
  affectedFunction?: string;
  lineNumber?: number;
  pocCode?: string;
  confidenceScore: number;
  ruleId?: string;
  fingerprint?: string;
}
