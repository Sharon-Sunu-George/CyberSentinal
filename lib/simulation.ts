import { assess } from "./risk"
import type { ActivityEvent, ActivityKind, Assessment, Dataset, Severity } from "./types"

export interface ThreatScenario {
  id: string
  kind: ActivityKind
  severity: Severity | "Info"
  title: string
  cause: string
  assetIds: string[]
  recommendedAction?: string
  apply: (dataset: Dataset) => Dataset
}

function updateAsset(dataset: Dataset, id: string, patch: (a: Dataset["assets"][number]) => Dataset["assets"][number]): Dataset {
  return { ...dataset, assets: dataset.assets.map((a) => (a.id === id ? patch(a) : a)) }
}

/** Ordered, deterministic scenarios with defensible cyber threat & mitigation explanations. */
export const threatScenarios: ThreatScenario[] = [
  {
    id: "sc-1",
    kind: "vulnerability",
    severity: "Critical",
    title: "New vulnerability detected: DEMO-2026-0147 on Customer Database",
    cause: "Discovered critical unauthenticated replication interface vulnerability (CVSS 9.4).",
    recommendedAction: "Apply immediate security patch or restrict internal database subnet access.",
    assetIds: ["a-cust-db"],
    apply: (d) => ({
      assets: d.assets.map((a) => (a.id === "a-cust-db" ? { ...a, openVulnerabilityCount: a.openVulnerabilityCount + 1 } : a)),
      vulnerabilities: [
        ...d.vulnerabilities,
        {
          id: "v-147",
          demoId: "DEMO-2026-0147",
          title: "Unauthenticated query interface exposed by replication service",
          assetId: "a-cust-db",
          cvss: 9.4,
          exploitStatus: "Exploited (simulated intel)",
          patchAvailable: false,
          remediated: false,
          lastAssessed: new Date().toISOString(),
          remediation: "Disable the replication query interface and restrict access to replication peers until a patch ships.",
        },
      ],
    }),
  },
  {
    id: "sc-2",
    kind: "control",
    severity: "High",
    title: "EDR agent signal degraded on Corporate Identity Server",
    cause: "Endpoint detection agent telemetry lapsed (controls.edr: 'Partial' → 'Unavailable').",
    recommendedAction: "Re-deploy EDR agent binary and verify daemon health.",
    assetIds: ["a-idp"],
    apply: (d) => updateAsset(d, "a-idp", (a) => ({ ...a, controls: { ...a.controls, edr: "Unavailable" } })),
  },
  {
    id: "sc-3",
    kind: "risk-change",
    severity: "High",
    title: "Heightened threat campaign targeting payment infrastructure",
    cause: "Simulated threat intel signals active adversary scanning targeting Payment API Gateway.",
    recommendedAction: "Enforce strict WAF rate-limiting and verify token authorization.",
    assetIds: ["a-pay-api", "a-partner-hub"],
    apply: (d) =>
      updateAsset(
        updateAsset(d, "a-pay-api", (a) => ({ ...a, threatEvidence: 1 })),
        "a-partner-hub",
        (a) => ({ ...a, threatEvidence: 1 }),
      ),
  },
  {
    id: "sc-4",
    kind: "remediation",
    severity: "Info",
    title: "Automated patch deployment applied to Payment Production Server",
    cause: "Critical CVE on Payment Production Server patched; patch control lifted to Active.",
    recommendedAction: "Perform vulnerability scanner validation to confirm closure.",
    assetIds: ["a-pay-prod"],
    apply: (d) =>
      updateAsset(d, "a-pay-prod", (a) => ({
        ...a,
        openVulnerabilityCount: Math.max(0, a.openVulnerabilityCount - 2),
        controls: { ...a.controls, patching: "Active" },
      })),
  },
  {
    id: "sc-5",
    kind: "incident",
    severity: "High",
    title: "High-severity security incident opened on HR Application Server",
    cause: "Suspicious lateral credential access observed; 1 incident opened awaiting containment.",
    recommendedAction: "Isolate compromised host session and rotate application credentials.",
    assetIds: ["a-hr-app"],
    apply: (d) =>
      updateAsset(d, "a-hr-app", (a) => ({
        ...a,
        openHighSeverityIncidents: a.openHighSeverityIncidents + 1,
        threatEvidence: 0.6,
      })),
  },
  {
    id: "sc-6",
    kind: "remediation",
    severity: "Info",
    title: "MFA policy enforced on Corporate Identity Server",
    cause: "Administrative MFA requirement activated across identity infrastructure (controls.mfa: 'Active').",
    recommendedAction: "Verify session revocation for non-MFA authenticated tokens.",
    assetIds: ["a-idp"],
    apply: (d) =>
      updateAsset(d, "a-idp", (a) => ({
        ...a,
        controls: { ...a.controls, mfa: "Active" },
      })),
  },
  {
    id: "sc-7",
    kind: "incident",
    severity: "Info",
    title: "Security incident contained & resolved on HR Application Server",
    cause: "Forensic containment complete and unauthorized token revoked (openHighSeverityIncidents: 1 → 0).",
    recommendedAction: "Audit access logs to confirm no secondary persistence.",
    assetIds: ["a-hr-app"],
    apply: (d) =>
      updateAsset(d, "a-hr-app", (a) => ({
        ...a,
        openHighSeverityIncidents: Math.max(0, a.openHighSeverityIncidents - 1),
        threatEvidence: 0.2,
      })),
  },
  {
    id: "sc-8",
    kind: "control",
    severity: "Medium",
    title: "Backup interface restricted to dedicated management VLAN",
    cause: "Network segmentation applied to Backup Infrastructure (controls.segmentation: 'Active').",
    recommendedAction: "Schedule automated quarterly restore drills.",
    assetIds: ["a-backup"],
    apply: (d) =>
      updateAsset(d, "a-backup", (a) => ({
        ...a,
        exposure: "Internal",
        controls: { ...a.controls, segmentation: "Active" },
      })),
  },
]

export interface SimulationOutcome {
  dataset: Dataset
  assessment: Assessment
  event: ActivityEvent
}

export function runScenario(dataset: Dataset, scenario: ThreatScenario, at: string): SimulationOutcome {
  const before = assess(dataset, at)
  const nextDataset = scenario.apply(dataset)
  const after = assess(nextDataset, at)

  const scoreChange = scenario.assetIds.map((id) => {
    const b = before.assetRisks.find((r) => r.asset.id === id) || { score: 60, rank: 1, asset: { name: id } }
    const a = after.assetRisks.find((r) => r.asset.id === id) || { score: 60, rank: 1, asset: { name: id } }
    return { assetName: a.asset.name, before: b.score, after: a.score, rankBefore: b.rank, rankAfter: a.rank }
  })

  const rankText = scoreChange
    .map((c) => `${c.assetName}: ${c.before} → ${c.after} (rank #${c.rankBefore} → #${c.rankAfter})`)
    .join("; ")

  return {
    dataset: nextDataset,
    assessment: after,
    event: {
      id: `evt-${scenario.id}-${at}`,
      at,
      kind: scenario.kind,
      title: scenario.title,
      description: `${scenario.cause} Re-assessed: ${rankText}.`,
      severity: scenario.severity,
      assetId: scenario.assetIds[0],
      scoreChange: scoreChange.map(({ assetName, before, after }) => ({ assetName, before, after })),
      overallChange: { before: before.overallScore, after: after.overallScore },
    },
  }
}
