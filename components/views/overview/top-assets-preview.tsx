"use client"

import { ArrowRight, ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { cn } from "@/lib/utils"
import type { AssetRisk } from "@/lib/types"
import { ExposureText, LevelBadge, RiskScore } from "@/components/app/badges"
import { Panel } from "@/components/app/panel"

interface TopAssetsPreviewProps {
  risks: AssetRisk[]
  totalCount: number
  onSelect: (assetId: string) => void
  selectedId?: string | null
  onViewAll: () => void
}

export function TopAssetsPreview({
  risks,
  totalCount,
  onSelect,
  selectedId,
  onViewAll,
}: TopAssetsPreviewProps) {
  const topFive = risks.slice(0, 5)

  return (
    <Panel
      title="Top Risk Assets"
      description={`Top 5 prioritized assets requiring remediation out of ${totalCount} total monitored inventory. Click any row to inspect deep risk factors.`}
      action={
        <Button
          variant="ghost"
          size="sm"
          onClick={onViewAll}
          className="gap-1 text-xs text-foreground hover:text-foreground"
        >
          View All in Explorer ({totalCount})
          <ArrowRight className="size-3.5" aria-hidden="true" />
        </Button>
      }
      bodyClassName="p-0"
    >
      <div className="overflow-x-auto">
        <Table className="text-xs">
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-12 text-center">#</TableHead>
              <TableHead className="min-w-44">Asset</TableHead>
              <TableHead className="min-w-32">Risk Score</TableHead>
              <TableHead className="min-w-24">Category</TableHead>
              <TableHead className="min-w-28 hidden sm:table-cell">Exposure</TableHead>
              <TableHead className="min-w-64 hidden lg:table-cell">Recommended Next Action</TableHead>
              <TableHead className="w-10 text-right pr-4">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {topFive.map((r) => (
              <TableRow
                key={r.asset.id}
                data-state={selectedId === r.asset.id ? "selected" : undefined}
                onClick={() => onSelect(r.asset.id)}
                className="cursor-pointer hover:bg-muted/40 transition-colors"
              >
                <TableCell className="text-center font-mono font-medium text-muted-foreground tabular-nums">
                  #{r.rank}
                </TableCell>
                <TableCell>
                  <div className="font-semibold text-foreground">{r.asset.name}</div>
                  <div className="text-[11px] text-muted-foreground">{r.asset.type}</div>
                </TableCell>
                <TableCell>
                  <RiskScore score={r.score} />
                </TableCell>
                <TableCell>
                  <LevelBadge level={r.category} />
                </TableCell>
                <TableCell className="hidden sm:table-cell">
                  <ExposureText exposure={r.asset.exposure} />
                </TableCell>
                <TableCell className="hidden max-w-sm whitespace-normal text-muted-foreground text-pretty lg:table-cell">
                  {r.nextAction}
                </TableCell>
                <TableCell className="text-right pr-4">
                  <span className="inline-flex size-6 items-center justify-center rounded-md text-muted-foreground group-hover:text-foreground">
                    <ChevronRight className="size-4" aria-hidden="true" />
                  </span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Panel>
  )
}
