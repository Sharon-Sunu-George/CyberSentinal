"use client"

import { ShieldAlert, AlertTriangle, ShieldCheck } from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { LevelBadge } from "@/components/app/badges"

export function GapsView() {
  const { gaps, navigate } = useAppState()

  return (
    <div className="flex flex-col gap-6">
      <Card className="border-warning/20 bg-warning/5">
        <CardHeader>
          <div className="flex items-center gap-2 text-warning">
            <ShieldAlert className="size-5" />
            <CardTitle>Security Gaps & Control Weaknesses</CardTitle>
          </div>
          <CardDescription>
            Prioritised security control gaps detected across assets with evidence and remediation steps.
          </CardDescription>
        </CardHeader>
      </Card>

      {gaps.length === 0 ? (
        <Card className="p-8 text-center border-dashed">
          <ShieldCheck className="mx-auto size-8 text-emerald-500 mb-2" />
          <p className="text-sm font-semibold text-foreground">No Active Security Control Gaps</p>
          <p className="text-xs text-muted-foreground mt-1 max-w-md mx-auto">
            All assets evaluated in the current assessment meet baseline control criteria (MFA, EDR, Patching, Segmentation, and Backup).
          </p>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {gaps.map((gap) => (
            <Card key={gap.id}>
              <CardHeader className="pb-3">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                  <CardTitle className="text-base font-semibold flex items-center gap-2">
                    <AlertTriangle className="size-4 text-warning" />
                    {gap.title}
                  </CardTitle>
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-muted-foreground">Urgency Score: {gap.urgencyScore}</span>
                    <LevelBadge level={gap.severity} />
                  </div>
                </div>
                <CardDescription>{gap.consequence}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4 text-xs">
                <div>
                  <h4 className="font-semibold text-foreground uppercase tracking-wider mb-1.5">
                    Affected Assets ({gap.affectedAssets.length})
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {gap.affectedAssets.map((asset) => (
                      <button
                        key={asset.id}
                        onClick={() => navigate("explorer")}
                        className="rounded bg-muted px-2 py-1 font-mono hover:bg-muted/80 text-foreground transition-colors"
                      >
                        {asset.name}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="pt-2 border-t">
                  <h4 className="font-semibold text-foreground uppercase tracking-wider mb-1">
                    Remediation Action
                  </h4>
                  <p className="text-muted-foreground leading-relaxed">{gap.remediation}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
