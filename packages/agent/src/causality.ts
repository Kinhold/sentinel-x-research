import type { DiscoveryFinding, Vulnerability } from '@sentinel-x/contracts';

export type CausalRelation =
  | 'same-function'
  | 'same-file'
  | 'type-enables'
  | 'temporal-persistent';

export interface CausalEdge {
  from: string;
  to: string;
  relation: CausalRelation;
  weight: number;
}

export interface CausalGraph {
  nodes: string[];
  edges: CausalEdge[];
  roots: string[];
  sinks: string[];
}

const ENABLEMENT: Partial<Record<string, string[]>> = {
  access_control: ['cpi_vulnerability', 'reentrancy', 'uninitialized_account'],
  uninitialized_account: ['cpi_vulnerability', 'reentrancy'],
  integer_overflow: ['access_control'],
  under_constrained_circuit: ['arithmetic_error'],
};

/**
 * Build a directed enablement DAG over findings.
 * Edges are explanatory hypotheses for operator review — not proofs of exploit chains.
 */
export function buildCausalGraph(findings: DiscoveryFinding[]): CausalGraph {
  const nodes = findings.map((f) => nodeId(f));
  const edges: CausalEdge[] = [];

  for (let i = 0; i < findings.length; i += 1) {
    for (let j = 0; j < findings.length; j += 1) {
      if (i === j) continue;
      const a = findings[i]!;
      const b = findings[j]!;
      const aId = nodeId(a);
      const bId = nodeId(b);

      if (a.affectedFile && a.affectedFile === b.affectedFile && a.affectedFunction && a.affectedFunction === b.affectedFunction) {
        edges.push({ from: aId, to: bId, relation: 'same-function', weight: 0.35 });
      } else if (a.affectedFile && a.affectedFile === b.affectedFile) {
        edges.push({ from: aId, to: bId, relation: 'same-file', weight: 0.15 });
      }

      const enabled = ENABLEMENT[a.vulnType] ?? [];
      if (enabled.includes(b.vulnType)) {
        edges.push({ from: aId, to: bId, relation: 'type-enables', weight: 0.45 });
      }
    }
  }

  const incoming = new Map<string, number>();
  const outgoing = new Map<string, number>();
  for (const node of nodes) {
    incoming.set(node, 0);
    outgoing.set(node, 0);
  }
  for (const edge of edges) {
    incoming.set(edge.to, (incoming.get(edge.to) ?? 0) + 1);
    outgoing.set(edge.from, (outgoing.get(edge.from) ?? 0) + 1);
  }

  return {
    nodes,
    edges,
    roots: nodes.filter((n) => (incoming.get(n) ?? 0) === 0),
    sinks: nodes.filter((n) => (outgoing.get(n) ?? 0) === 0),
  };
}

export function causalBoostFor(finding: DiscoveryFinding, graph: CausalGraph): number {
  const id = nodeId(finding);
  const inbound = graph.edges.filter((e) => e.to === id);
  if (inbound.length === 0) return 0;
  const boost = inbound.reduce((sum, e) => sum + e.weight, 0) * 0.04;
  return Math.min(0.12, boost);
}

export function temporalPersistenceBoost(
  fingerprint: string | undefined,
  history: Array<Pick<Vulnerability, 'fingerprint' | 'status' | 'scanId'>>,
): number {
  if (!fingerprint) return 0;
  const hits = history.filter((h) => h.fingerprint === fingerprint);
  if (hits.length <= 1) return 0;
  const verifiedHits = hits.filter((h) => h.status === 'verified' || h.status === 'reported').length;
  const scanIds = new Set(hits.map((h) => h.scanId));
  if (scanIds.size < 2) return 0;
  return Math.min(0.1, 0.03 * scanIds.size + 0.02 * verifiedHits);
}

function nodeId(finding: DiscoveryFinding): string {
  return finding.fingerprint ?? `${finding.ruleId ?? finding.vulnType}:${finding.affectedFile}:${finding.lineNumber}`;
}
