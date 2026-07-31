import type { DiscoveryFinding, TargetLanguage, Vulnerability, VulnerabilitySeverity } from '@sentinel-x/contracts';

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        informationUri: string;
        version: string;
        rules: Array<{
          id: string;
          shortDescription: { text: string };
          fullDescription?: { text: string };
          defaultConfiguration?: { level: 'error' | 'warning' | 'note' };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: 'error' | 'warning' | 'note';
      message: { text: string };
      fingerprints?: Record<string, string>;
      locations?: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region?: { startLine: number };
        };
      }>;
      properties?: Record<string, string | number | boolean | null>;
    }>;
  }>;
}

const SEVERITY_LEVEL: Record<VulnerabilitySeverity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  informational: 'note',
};

export function buildSarifReport(input: {
  vulnerabilities: Vulnerability[];
  findings?: DiscoveryFinding[];
  targetLanguage?: TargetLanguage;
}): SarifLog {
  const rules = new Map<string, { id: string; title: string; description: string; level: 'error' | 'warning' | 'note' }>();

  for (const vuln of input.vulnerabilities) {
    const ruleId = vuln.ruleId ?? `sentinel.${vuln.vulnType}`;
    if (!rules.has(ruleId)) {
      rules.set(ruleId, {
        id: ruleId,
        title: vuln.title,
        description: vuln.description,
        level: SEVERITY_LEVEL[vuln.severity],
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentinel-X',
            informationUri: 'https://github.com/Kinhold/sentinel-x-research',
            version: '0.1.0',
            rules: [...rules.values()].map((rule) => ({
              id: rule.id,
              shortDescription: { text: rule.title },
              fullDescription: { text: rule.description },
              defaultConfiguration: { level: rule.level },
            })),
          },
        },
        results: input.vulnerabilities
          .filter((vuln) => vuln.status === 'verified' || vuln.status === 'reported' || vuln.status === 'discovered')
          .map((vuln) => ({
            ruleId: vuln.ruleId ?? `sentinel.${vuln.vulnType}`,
            level: SEVERITY_LEVEL[vuln.severity],
            message: { text: vuln.title },
            fingerprints: vuln.fingerprint ? { 'sentinel/v1': vuln.fingerprint } : undefined,
            locations: vuln.affectedFile
              ? [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: vuln.affectedFile },
                      region: vuln.lineNumber ? { startLine: vuln.lineNumber } : undefined,
                    },
                  },
                ]
              : undefined,
            properties: {
              status: vuln.status,
              vulnType: vuln.vulnType,
              targetLanguage: vuln.targetLanguage,
              confidenceScore: vuln.confidenceScore ?? null,
              scanId: vuln.scanId,
            },
          })),
      },
    ],
  };
}
