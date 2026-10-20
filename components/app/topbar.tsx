"use client"

import { useEffect, useState } from "react"
import { AlertCircle, ArrowLeft, Bell, CheckCircle2, FlaskConical, Home, Loader2, Menu, RefreshCw, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { formatDateTime } from "@/lib/format"
import { useAppState } from "./app-state"
import { NAV_ITEMS } from "./nav-config"
import { Logo, SidebarNav } from "./sidebar"
import { ActivityList } from "./activity-list"

export function Topbar() {
  const {
    view,
    assessment,
    isAssessing,
    assessmentError,
    clearAssessmentError,
    isStale,
    runAssessment,
    autoRefreshEnabled,
    nextAssessmentSeconds,
    toggleAutoRefresh,
    unread,
    markRead,
    activity,
    navigate,
    goBack,
    canGoBack,
    activeReport,
    lastRiskAssessmentAt,
    lastReportAnalyzedAt,
  } = useAppState()
  const [menuOpen, setMenuOpen] = useState(false)
  const [notifOpen, setNotifOpen] = useState(false)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  const item = NAV_ITEMS.find((n) => n.id === view) ?? NAV_ITEMS[0]

  return (
    <>
      <div className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/80 lg:px-6">
        <Button
          variant="ghost"
          size="icon"
          className="lg:hidden"
          onClick={() => setMenuOpen(true)}
          aria-label="Open navigation"
        >
          <Menu />
        </Button>
        <button
          type="button"
          onClick={() => navigate("landing")}
          className="lg:hidden cursor-pointer"
          title="CyberSentinel AI — Return to Home / Welcome Screen"
        >
          <Logo />
        </button>

        {/* Back Navigation Button */}
        <Button
          variant="outline"
          size="sm"
          onClick={goBack}
          className="flex items-center gap-1.5 h-8 px-2.5 text-xs font-medium border-border/70 bg-card/60 hover:bg-muted text-foreground transition-colors"
          title="Navigate back to previous page"
          aria-label="Navigate back"
        >
          <ArrowLeft className="size-3.5 text-primary" />
          <span>Back</span>
        </Button>

        <div className="ml-auto flex items-center gap-2">
          {/* Home / Welcome Screen button */}
          <Button
            variant="outline"
            size="sm"
            className="flex items-center gap-1.5 h-8 text-xs font-medium"
            onClick={() => navigate("landing")}
            title="Return to Home / Welcome Screen"
          >
            <Home className="size-3.5 text-primary" />
            <span className="hidden sm:inline">Home Screen</span>
          </Button>

          {/* Simulation Telemetry Status Pill */}
          <button
            type="button"
            onClick={toggleAutoRefresh}
            title={
              autoRefreshEnabled
                ? "Simulated telemetry feed is active on demo infrastructure. Click to pause."
                : "Simulated telemetry feed is paused. Click to resume."
            }
            className="flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-mono transition-colors hover:bg-muted/40"
          >
            <span
              className={`size-2 rounded-full ${
                autoRefreshEnabled ? "bg-emerald-500 animate-pulse" : "bg-muted-foreground"
              }`}
            />
            <span className="text-[11px] text-foreground">
              {autoRefreshEnabled ? "Telemetry Feed: Active" : "Telemetry Feed: Paused"}
            </span>
          </button>

          {/* Environmental Fidelity Indicator */}
          {activeReport ? (
            <span
              className="hidden items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-600 dark:text-emerald-400 font-medium sm:inline-flex"
              title="Real Report Mode: Live findings, CVEs, and FAIR risk metrics were extracted directly by the FastAPI backend. Enterprise network connectors and live SIEM remain simulated."
            >
              <CheckCircle2 className="size-3.5 text-emerald-500" aria-hidden="true" />
              Real Report (Hybrid)
            </span>
          ) : (
            <span
              className="hidden items-center gap-1.5 rounded-md border border-dashed border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs text-amber-600 dark:text-amber-400 font-medium sm:inline-flex"
              title="Simulated Mode: Monitored assets and vulnerability findings represent a baseline demonstration estate."
            >
              <FlaskConical className="size-3.5 text-amber-500" aria-hidden="true" />
              Simulated Baseline Data
            </span>
          )}

          <Button
            variant="ghost"
            size="icon"
            className="relative"
            onClick={() => {
              setNotifOpen(true)
              markRead()
            }}
            aria-label={unread > 0 ? `Notifications, ${unread} unread` : "Notifications"}
          >
            <Bell />
            {unread > 0 ? (
              <span className="absolute -top-0.5 -right-0.5 flex size-4 items-center justify-center rounded-full bg-destructive font-mono text-[10px] font-semibold text-white">
                {unread > 9 ? "9+" : unread}
              </span>
            ) : null}
          </Button>
        </div>
      </div>

      {/* Assessment Error Banner */}
      {assessmentError && (
        <div className="flex items-center justify-between gap-3 border-b border-destructive/20 bg-destructive/10 px-4 py-2.5 text-xs text-destructive lg:px-6">
          <div className="flex items-center gap-2">
            <AlertCircle className="size-4 shrink-0" />
            <span>
              <strong>Assessment Error:</strong> {assessmentError}
            </span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button
              size="sm"
              variant="outline"
              className="h-7 border-destructive/30 px-2.5 text-xs text-destructive hover:bg-destructive/10"
              onClick={runAssessment}
              disabled={isAssessing}
            >
              Retry
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
              onClick={clearAssessmentError}
            >
              <X className="size-3.5" />
            </Button>
          </div>
        </div>
      )}

      <div className="flex flex-col gap-3 border-b px-4 py-4 sm:flex-row sm:items-end sm:justify-between lg:px-6">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold tracking-tight text-foreground text-balance">{item.title}</h1>
          <p className="mt-0.5 text-sm text-muted-foreground text-pretty">{item.description}</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="text-xs leading-tight text-muted-foreground" aria-live="polite">
            {activeReport ? (
              <span className="block text-[11px] text-muted-foreground">
                Report: <strong className="font-mono text-foreground">{activeReport.filename || activeReport.report_id}</strong>
              </span>
            ) : (
              <span className="block text-[11px] text-muted-foreground">
                Mode: <strong className="font-mono text-foreground">Baseline Demonstration</strong>
              </span>
            )}
            {mounted && isStale ? <span className="block text-warning font-medium mt-0.5">Telemetry changed — re-run queued</span> : null}
          </div>

          <Button onClick={runAssessment} disabled={isAssessing} size="lg">
            {isAssessing ? <Loader2 className="animate-spin" aria-hidden="true" /> : <RefreshCw aria-hidden="true" />}
            {isAssessing ? "Assessing…" : "Run Risk Assessment"}
          </Button>
        </div>
      </div>

      <Sheet open={menuOpen} onOpenChange={setMenuOpen}>
        <SheetContent side="left" className="w-72 bg-sidebar p-0">
          <SheetHeader className="border-b">
            <SheetTitle className="sr-only">Navigation</SheetTitle>
            <SheetDescription className="sr-only">Switch between application views</SheetDescription>
            <Logo />
          </SheetHeader>
          <div className="p-3">
            <SidebarNav onNavigate={() => setMenuOpen(false)} />
          </div>
        </SheetContent>
      </Sheet>

      <Sheet open={notifOpen} onOpenChange={setNotifOpen}>
        <SheetContent side="right" className="w-full sm:max-w-md">
          <SheetHeader className="border-b">
            <SheetTitle>Notifications</SheetTitle>
            <SheetDescription>Recent simulated events and assessments.</SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto px-4">
            <ActivityList events={activity.slice(0, 8)} compact />
          </div>
          <div className="border-t p-4">
            <Button
              variant="outline"
              className="w-full"
              onClick={() => {
                setNotifOpen(false)
                navigate("activity")
              }}
            >
              View full activity log
            </Button>
          </div>
        </SheetContent>
      </Sheet>
    </>
  )
}
