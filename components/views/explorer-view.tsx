"use client"

import { useDeferredValue, useMemo, useState } from "react"
import { Filter, Layers, RotateCcw, Search, ShieldAlert, Sparkles, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useAppState } from "@/components/app/app-state"
import { AssetRiskTable } from "@/components/app/asset-risk-table"
import { AssetDetail } from "@/components/app/asset-detail"
import { FilterChips } from "@/components/app/filter-chips"
import { Panel } from "@/components/app/panel"
import { severityFromCvss } from "@/lib/risk"
import type { Criticality, ExploitStatus, Exposure, Severity } from "@/lib/types"
import { VulnerabilityTable, type VulnRow } from "./explorer/vulnerability-table"
import { VulnerabilityDetail } from "./explorer/vulnerability-detail"
import { cn } from "@/lib/utils"

const SEVERITIES = ["Critical", "High", "Medium", "Low"] as const satisfies readonly Severity[]
const EXPLOIT_OPTIONS = ["Exploited (simulated intel)", "Public PoC", "None known"] as const
const PATCH_OPTIONS = ["Available", "None"] as const

type Selection = { kind: "asset"; id: string } | { kind: "vuln"; id: string } | null

export function ExplorerView() {
  const { assessment, dataset } = useAppState()
  const [query, setQuery] = useState("")
  const q = useDeferredValue(query).trim().toLowerCase()

  const [severity, setSeverity] = useState<Severity[]>([])
  const [exploitFilter, setExploitFilter] = useState<string[]>([])
  const [patchFilter, setPatchFilter] = useState<string[]>([])

  const [tab, setTab] = useState<"vulns" | "assets">("vulns")
  const [selection, setSelection] = useState<Selection>(null)

  // Filtered Assets list
  const assetRisks = useMemo(
    () =>
      assessment.assetRisks.filter((r) => {
        const a = r.asset
        if (severity.length && (r.highestSeverity === "None" || !severity.includes(r.highestSeverity))) return false
        if (q && !`${a.name} ${a.type} ${a.owner}`.toLowerCase().includes(q)) return false
        return true
      }),
    [assessment.assetRisks, severity, q],
  )

  // Filtered Vulnerabilities list
  const vulnRows = useMemo<VulnRow[]>(() => {
    const byId = new Map(dataset.assets.map((a) => [a.id, a]))
    return dataset.vulnerabilities.flatMap((v) => {
      const asset = byId.get(v.assetId)
      if (!asset) return []
      const sev = severityFromCvss(v.cvss)

      // 1. Severity filter
      if (severity.length && !severity.includes(sev)) return []

      // 2. Exploit filter
      if (exploitFilter.length && !exploitFilter.includes(v.exploitStatus)) return []

      // 3. Patch filter
      if (patchFilter.length) {
        if (patchFilter.includes("Available") && !patchFilter.includes("None") && !v.patchAvailable) return []
        if (patchFilter.includes("None") && !patchFilter.includes("Available") && v.patchAvailable) return []
      }

      // 4. Search query
      if (q && !`${v.demoId} ${v.title} ${asset.name} ${asset.type}`.toLowerCase().includes(q)) return []

      return [{ vuln: v, asset, severity: sev }]
    })
  }, [dataset, severity, exploitFilter, patchFilter, q])

  const hasActiveFilters = !!(query || severity.length || exploitFilter.length || patchFilter.length)

  const clearAllFilters = () => {
    setQuery("")
    setSeverity([])
    setExploitFilter([])
    setPatchFilter([])
  }

  const selectedAsset = selection?.kind === "asset" ? assessment.assetRisks.find((r) => r.asset.id === selection.id) : undefined
  const selectedVuln = selection?.kind === "vuln" ? dataset.vulnerabilities.find((v) => v.id === selection.id) : undefined

  return (
    <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
      {/* ─────────────────────────────────────────────────────────────
          LEFT COLUMN: SEARCH, FILTERS, TABS & TABLE
      ───────────────────────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-col gap-4">
        {/* 1. Tabs Header at Top */}
        <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)} className="w-full">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/80 pb-3">
            <TabsList className="bg-muted/60 p-1">
              <TabsTrigger value="vulns" className="gap-2 px-3 py-1.5 text-xs font-semibold">
                <ShieldAlert className="size-3.5" aria-hidden="true" />
                Vulnerabilities
                <span className="rounded bg-background px-1.5 py-0.2 font-mono text-[11px] font-bold text-foreground">
                  {vulnRows.length}
                </span>
              </TabsTrigger>
              <TabsTrigger value="assets" className="gap-2 px-3 py-1.5 text-xs font-semibold">
                <Layers className="size-3.5" aria-hidden="true" />
                Monitored Assets
                <span className="rounded bg-background px-1.5 py-0.2 font-mono text-[11px] font-bold text-foreground">
                  {assetRisks.length}
                </span>
              </TabsTrigger>
            </TabsList>

            <span className="text-xs text-muted-foreground hidden sm:inline-block">
              {tab === "vulns" ? "Itemized high-impact findings" : "Ranked enterprise asset inventory"}
            </span>
          </div>

          {/* 2. Unified Search & Filter Control Bar */}
          <div className="mt-3 flex flex-col gap-3 rounded-lg border border-border/80 bg-card p-3.5 shadow-sm">
            {/* Search Input Row */}
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search
                  className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground"
                  aria-hidden="true"
                />
                <Input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={
                    tab === "vulns"
                      ? "Search vulnerabilities by CVE ID, title, or asset name…"
                      : "Search assets by name, type, or owner…"
                  }
                  aria-label="Search items"
                  className="h-9 pl-9 text-xs"
                />
              </div>

              {hasActiveFilters ? (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={clearAllFilters}
                  className="h-9 gap-1 text-xs text-muted-foreground hover:text-foreground"
                >
                  <RotateCcw className="size-3" aria-hidden="true" />
                  Clear Filters
                </Button>
              ) : null}
            </div>

            {/* Filter Chips Row */}
            <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border/50 pt-2.5">
              <FilterChips label="Severity" options={SEVERITIES} value={severity} onChange={setSeverity} />

              {tab === "vulns" ? (
                <>
                  <FilterChips
                    label="Exploit Status"
                    options={EXPLOIT_OPTIONS}
                    value={exploitFilter}
                    onChange={setExploitFilter}
                  />
                  <FilterChips
                    label="Patch Status"
                    options={PATCH_OPTIONS}
                    value={patchFilter}
                    onChange={setPatchFilter}
                  />
                </>
              ) : null}
            </div>
          </div>

          {/* 3. Tab Contents */}
          <TabsContent value="vulns" className="mt-4">
            <div className="rounded-lg border border-border/80 bg-card shadow-sm">
              <VulnerabilityTable
                rows={vulnRows}
                selectedId={selection?.kind === "vuln" ? selection.id : null}
                onSelect={(id) => setSelection({ kind: "vuln", id })}
              />
            </div>
          </TabsContent>

          <TabsContent value="assets" className="mt-4">
            <div className="rounded-lg border border-border/80 bg-card px-2 py-1 shadow-sm">
              <AssetRiskTable
                risks={assetRisks}
                compact
                selectedId={selection?.kind === "asset" ? selection.id : null}
                onSelect={(id) => setSelection({ kind: "asset", id })}
              />
            </div>
          </TabsContent>
        </Tabs>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          RIGHT COLUMN: DETAILS PANEL (COMPACT EMPTY STATE / RICH ACTIVE)
      ───────────────────────────────────────────────────────────── */}
      <div className="xl:sticky xl:top-16 xl:self-start">
        {selectedAsset || selectedVuln ? (
          <Panel
            title={selectedAsset ? selectedAsset.asset.name : selectedVuln ? selectedVuln.demoId : "Details"}
            description={selectedAsset ? "Monitored Asset Profile" : "Vulnerability Intelligence & Remediation"}
            action={
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelection(null)}
                className="h-7 size-7 p-0 text-muted-foreground hover:text-foreground"
                aria-label="Close details"
              >
                <X className="size-4" />
              </Button>
            }
            bodyClassName="max-h-[calc(100svh-10rem)] overflow-y-auto"
          >
            {selectedAsset ? (
              <AssetDetail risk={selectedAsset} />
            ) : selectedVuln ? (
              <VulnerabilityDetail
                vuln={selectedVuln}
                onSelectAsset={(id) => setSelection({ kind: "asset", id })}
              />
            ) : null}
          </Panel>
        ) : (
          /* Sleek, Non-Dominant Empty State */
          <div className="rounded-xl border border-dashed border-border/80 bg-card/50 p-6 text-center shadow-sm">
            <div className="mx-auto flex size-10 items-center justify-center rounded-full bg-muted/60 text-muted-foreground">
              <Sparkles className="size-5" aria-hidden="true" />
            </div>
            <h3 className="mt-3 text-xs font-semibold uppercase tracking-wider text-foreground">
              Inspector Panel
            </h3>
            <p className="mt-1 text-xs text-muted-foreground leading-relaxed text-pretty">
              Select any row from the vulnerability or asset table to inspect full risk factors, active attack intel, and simulated remediation actions.
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
