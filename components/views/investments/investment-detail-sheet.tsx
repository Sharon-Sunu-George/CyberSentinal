"use client"

import { useMemo } from "react"
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  ExternalLink,
  Flame,
  Layers,
  Lock,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TrendingDown,
  Wrench,
  Zap,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { ExposureText, LevelBadge, scoreColor } from "@/components/app/badges"
import { formatCurrency } from "@/lib/format"
import { CRITICAL_REMEDIATION_CVSS } from "@/lib/investments"
import type { Asset, ControlKey, Dataset, InvestmentOption, Vulnerability } from "@/lib/types"
import { cn } from "@/lib/utils"

interface InvestmentDetailSheetProps {
  option: InvestmentOption | null
  standalonePct?: number
  marginalReduction?: number | null
  efficiencyPerLakh?: number
  coverageCount?: number
  baselineExposure?: number
  dataset: Dataset
  isOpen: boolean
  onClose: () => void
  onNavigateToExplorer: () => void
}

interface ProblemMapping {
  problemsAddressed: string
  remediationPerformed: string
  securityOutcome: string
  controlKey?: ControlKey
  hasDirectVulns?: boolean
}

const INVESTMENT_KNOWLEDGE: Record<string, ProblemMapping> = {
  "inv-vuln": {
    problemsAddressed:
      "Critical open vulnerabilities (CVSS ≥ 9.0) with public exploit availability and missing patches leave perimeter servers directly exposed to Remote Code Execution (RCE) and zero-day breaches.",
    remediationPerformed:
      "Apply vendor-certified emergency security patches across all targeted hosts and upgrade patch management compliance from Missing to Partial.",
    securityOutcome:
      "Neutralizes high-impact exploitable CVEs, eliminates attacker footholds, and immediately raises patch compliance on vulnerable assets.",
    controlKey: "patching",
    hasDirectVulns: true,
  },
  "inv-mfa": {
    problemsAddressed:
      "Single-factor or missing authentication on identity servers, admin interfaces, and remote-access portals exposes corporate assets to credential stuffing, password spray, and identity takeover.",
    remediationPerformed:
      "Enforce mandatory hardware-token and FIDO2 Multi-Factor Authentication across all administrative, SSH, and remote-access paths.",
    securityOutcome:
      "Upgrades MFA posture to Active across all targeted assets, completely eliminating single-factor credential stuffing and brute-force takeover vectors.",
    controlKey: "mfa",
    hasDirectVulns: false,
  },
  "inv-edr": {
    problemsAddressed:
      "Missing or degraded endpoint detection agents leave security teams blind to stealthy in-memory exploits, living-off-the-land binaries (LotL), and lateral movement.",
    remediationPerformed:
      "Deploy unified EDR telemetry agents to uncovered servers and restore sensor connectivity on degraded or partial endpoint agents.",
    securityOutcome:
      "Upgrades EDR posture to Active across all monitored hosts, enabling 24/7 behavioral telemetry, instant alert correlation, and automated host isolation.",
    controlKey: "edr",
    hasDirectVulns: false,
  },
  "inv-seg": {
    problemsAddressed:
      "Flat network architecture without micro-segmentation allows an adversary who breaches an internet-facing host to move laterally into payment databases and identity tiers.",
    remediationPerformed:
      "Implement zero-trust network access (ZTNA) policies, VPC security boundaries, and micro-segmentation restricting east-west traffic between application tiers.",
    securityOutcome:
      "Upgrades Network Segmentation to Active, strictly isolating payment, data, and identity tiers and drastically containing the blast radius of any breach.",
    controlKey: "segmentation",
    hasDirectVulns: false,
  },
  "inv-backup": {
    problemsAddressed:
      "Unsegmented backup repositories and untested disaster recovery procedures leave the organization vulnerable to catastrophic data loss and ransomware extortion.",
    remediationPerformed:
      "Deploy immutable air-gapped backup storage with automated cryptographic verification and validated disaster recovery restore testing.",
    securityOutcome:
      "Upgrades Backup & Recovery to Active, ensuring guaranteed operational recovery and cyber resilience against destructive ransomware attacks.",
    controlKey: "backup",
    hasDirectVulns: false,
  },
}

export function InvestmentDetailSheet({
  option,
  standalonePct = 0,
  marginalReduction,
  efficiencyPerLakh = 0,
  coverageCount = 0,
  baselineExposure = 1,
  dataset,
  isOpen,
  onClose,
  onNavigateToExplorer,
}: InvestmentDetailSheetProps) {
  if (!option) return null

  const knowledge = INVESTMENT_KNOWLEDGE[option.id] || {
    problemsAddressed: option.description,
    remediationPerformed: `Implement ${option.name} across targeted assets.`,
    securityOutcome: `Reduces overall risk score by improving ${option.riskCategories.join(", ")}.`,
    controlKey: undefined,
    hasDirectVulns: false,
  }

  // 1. Calculate affected assets
  const affectedAssets = useMemo(() => {
    if (option.id === "inv-vuln") {
      const fixedAssetIds = new Set(
        dataset.vulnerabilities
          .filter((v) => !v.remediated && v.patchAvailable && v.cvss >= CRITICAL_REMEDIATION_CVSS)
          .map((v) => v.assetId),
      )
      return dataset.assets.filter((a) => fixedAssetIds.has(a.id))
    }
    if (knowledge.controlKey) {
      return dataset.assets.filter((a) => a.controls[knowledge.controlKey!] !== "Active")
    }
    return dataset.assets
  }, [option.id, knowledge.controlKey, dataset])

  // 2. Calculate affected vulnerabilities
  const affectedVulns = useMemo(() => {
    if (option.id === "inv-vuln") {
      return dataset.vulnerabilities.filter(
        (v) => !v.remediated && v.patchAvailable && v.cvss >= CRITICAL_REMEDIATION_CVSS,
      )
    }
    const assetIds = new Set(affectedAssets.map((a) => a.id))
    return dataset.vulnerabilities.filter((v) => !v.remediated && assetIds.has(v.assetId))
  }, [option.id, affectedAssets, dataset])

  const marginalPct = marginalReduction
    ? ((marginalReduction / (baselineExposure || 1)) * 100).toFixed(1)
    : standalonePct.toFixed(1)

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader className="border-b border-border/60 pb-4">
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary">
              <Zap className="size-4" aria-hidden="true" />
            </span>
            <span className="text-[11px] font-bold uppercase tracking-wider text-primary">
              Investment Impact Breakdown
            </span>
          </div>
          <SheetTitle className="text-lg font-bold text-foreground mt-1">
            {option.name}
          </SheetTitle>
          <SheetDescription className="text-xs text-muted-foreground">
            What specific security problem does this investment solve and what is the expected outcome?
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-5 py-4 text-xs">
          {/* 1. KEY FINANCIAL & ROI METRICS */}
          <div className="grid grid-cols-3 gap-2 rounded-xl border border-border/80 bg-muted/20 p-3 text-center">
            <div>
              <span className="block text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                Investment Cost
              </span>
              <span className="mt-0.5 block font-mono text-base font-bold text-foreground">
                {formatCurrency(option.cost)}
              </span>
              <span className="text-[10px] text-muted-foreground font-medium">{option.effort} Effort</span>
            </div>

            <div className="border-x border-border/50">
              <span className="block text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                Risk Reduction
              </span>
              <span className="mt-0.5 block font-mono text-base font-bold text-emerald-600 dark:text-emerald-400">
                −{marginalPct}%
              </span>
              <span className="text-[10px] text-muted-foreground">
                {efficiencyPerLakh.toFixed(1)} pts / $100k
              </span>
            </div>

            <div>
              <span className="block text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">
                Affected Scope
              </span>
              <span className="mt-0.5 block font-mono text-base font-bold text-foreground">
                {affectedAssets.length}
              </span>
              <span className="text-[10px] text-muted-foreground">Monitored Hosts</span>
            </div>
          </div>

          {/* 2. SPECIFIC SECURITY PROBLEMS BEING ADDRESSED */}
          <div className="rounded-xl border border-destructive/30 bg-destructive/5 p-4">
            <div className="flex items-center gap-2 text-xs font-bold text-destructive">
              <AlertCircle className="size-4 shrink-0" />
              Security Problem Addressed
            </div>
            <p className="mt-2 text-xs text-foreground leading-relaxed text-pretty">
              {knowledge.problemsAddressed}
            </p>
          </div>

          {/* 3. WHAT REMEDIATION / ACTION WILL BE PERFORMED */}
          <div className="rounded-xl border border-primary/30 bg-primary/5 p-4">
            <div className="flex items-center gap-2 text-xs font-bold text-primary">
              <Wrench className="size-4 shrink-0" />
              Remediation Action Executed
            </div>
            <p className="mt-2 text-xs text-foreground leading-relaxed text-pretty">
              {knowledge.remediationPerformed}
            </p>
          </div>

          {/* 4. EXPECTED SECURITY OUTCOME */}
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4">
            <div className="flex items-center gap-2 text-xs font-bold text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="size-4 shrink-0" />
              Expected Security Outcome
            </div>
            <p className="mt-2 text-xs text-foreground leading-relaxed text-pretty">
              {knowledge.securityOutcome}
            </p>
          </div>

          {/* 5. AFFECTED ASSETS LIST */}
          <div className="flex flex-col gap-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 font-bold text-foreground">
                <Server className="size-3.5 text-muted-foreground" />
                <span>Targeted Monitored Hosts ({affectedAssets.length})</span>
              </div>
              <span className="text-[11px] text-muted-foreground">Directly impacted by this control</span>
            </div>

            <div className="max-h-52 overflow-y-auto rounded-lg border border-border/70 bg-card divide-y divide-border/40">
              {affectedAssets.length === 0 ? (
                <div className="p-3 text-center text-muted-foreground text-xs">
                  All monitored hosts already comply with this control.
                </div>
              ) : (
                affectedAssets.map((asset) => (
                  <div key={asset.id} className="flex items-center justify-between p-2.5 hover:bg-muted/30">
                    <div className="min-w-0 flex-1">
                      <p className="font-semibold text-foreground truncate">{asset.name}</p>
                      <p className="text-[11px] text-muted-foreground">
                        {asset.type} · {asset.owner}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <LevelBadge level={asset.criticality} />
                      <ExposureText exposure={asset.exposure} />
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* 6. AFFECTED VULNERABILITIES ACTION LINK */}
          {affectedVulns.length > 0 && (
            <div className="flex items-center justify-between rounded-lg border border-border/70 bg-muted/20 p-3">
              <div>
                <span className="font-semibold text-foreground block">
                  {affectedVulns.length} Related Open Finding{affectedVulns.length === 1 ? "" : "s"}
                </span>
                <span className="text-[11px] text-muted-foreground">
                  {option.id === "inv-vuln"
                    ? "Critical CVSS ≥ 9.0 findings patched by this control"
                    : "Active findings on targeted hosts"}
                </span>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  onClose()
                  onNavigateToExplorer()
                }}
                className="gap-1 text-xs"
              >
                View in Explorer
                <ExternalLink className="size-3" />
              </Button>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
