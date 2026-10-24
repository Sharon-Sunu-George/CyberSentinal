"use client"

import { useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  DollarSign,
  FileCode,
  FileSearch,
  FlaskConical,
  Home,
  ImageIcon,
  Info,
  RotateCcw,
  ShieldAlert,
  Sparkles,
  UploadCloud,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { LevelBadge } from "@/components/app/badges"
import { formatCurrency } from "@/lib/format"

export function ReportAnalysisView() {
  const { activeReport, navigate, currency } = useAppState()
  const [showTechnicalDetails, setShowTechnicalDetails] = useState(true)
  const [showTextPreview, setShowTextPreview] = useState(false)

  if (!activeReport) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] max-w-xl mx-auto text-center px-4 pt-12">
        <div className="flex size-14 items-center justify-center rounded-2xl bg-muted/60 text-muted-foreground mb-4">
          <FileSearch className="size-7" />
        </div>
        <h2 className="text-xl font-bold text-foreground">No Security Report Analyzed</h2>
        <p className="text-sm text-muted-foreground mt-2 leading-relaxed">
          Upload a vulnerability scan, penetration testing report, or compliance audit document to preview extracted findings and calculate authoritative FAIR risk metrics.
        </p>
        <div className="flex items-center gap-3 mt-6">
          <Button onClick={() => navigate("report-upload")}>
            <UploadCloud className="size-4 mr-2" />
            Upload Security Report
          </Button>
          <Button variant="outline" onClick={() => navigate("landing")}>
            <Home className="size-4 mr-2" />
            Back to Home
          </Button>
        </div>
      </div>
    )
  }

  const getFormatBadgeColor = (fmt?: string | null) => {
    if (!fmt) return "bg-muted text-muted-foreground"
    if (fmt.includes("CSV") || fmt.includes("JSON"))
      return "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
    if (fmt.includes("DOCX") || fmt.includes("TXT"))
      return "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30"
    if (fmt.includes("PDF"))
      return "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30"
    if (fmt.includes("Image") || fmt.includes("OCR"))
      return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30"
    return "bg-muted text-muted-foreground"
  }

  return (
    <div className="flex flex-col gap-6 max-w-5xl mx-auto pt-7 px-4 pb-16">
      {/* Navigation Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b pb-4">
        <div>
          <div className="flex items-center gap-2 text-primary font-semibold text-lg">
            <CheckCircle2 className="size-5 text-emerald-500" />
            <span>Report Analysis & Findings Preview</span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Document processed via FastAPI. Review extracted findings before proceeding to the Executive Overview.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("landing")}
            className="text-xs text-muted-foreground"
          >
            <Home className="size-3.5 mr-1" />
            Home
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate("report-upload")}
            className="text-xs"
          >
            <RotateCcw className="size-3.5 mr-1" />
            Upload Another
          </Button>
          <Button
            size="sm"
            onClick={() => navigate("overview")}
            className="text-xs font-medium gap-1.5"
          >
            View Executive Overview
            <ArrowRight className="size-3.5" />
          </Button>
        </div>
      </div>

      {/* Main Analysis Status Card */}
      <Card className="border-emerald-500/40 bg-emerald-500/5">
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="size-5" />
              <CardTitle className="text-base font-semibold">
                Document Ingestion & Quantification Complete
              </CardTitle>
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {activeReport.detected_format && (
                <span
                  className={`rounded border px-2 py-0.5 font-mono text-[11px] font-semibold ${getFormatBadgeColor(
                    activeReport.detected_format
                  )}`}
                >
                  {activeReport.detected_format}
                </span>
              )}
              <span className="rounded bg-muted border px-2 py-0.5 font-mono text-[11px] text-foreground">
                Status: {activeReport.analysis_status || "COMPLETED"}
              </span>
              {activeReport.is_synthetic && (
                <span className="flex items-center gap-1 rounded bg-warning/20 border border-warning/30 px-2 py-0.5 font-mono text-[11px] text-warning">
                  <FlaskConical className="size-3" />
                  Synthetic Benchmark
                </span>
              )}
            </div>
          </div>
          <CardDescription className="text-foreground text-xs mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              File: <strong className="font-mono">{activeReport.filename}</strong>
            </span>
            <span>
              · Target: <strong className="font-mono">{activeReport.target}</strong>
            </span>
            <span>
              · Report ID: <span className="font-mono text-muted-foreground">{activeReport.report_id}</span>
            </span>
            {activeReport.report_date && (
              <span>
                · Report Date: <span className="font-mono text-muted-foreground">{activeReport.report_date}</span>
              </span>
            )}
          </CardDescription>

          <div className="flex flex-wrap items-center gap-2 pt-2 text-[11px] font-mono">
            <span className="flex items-center gap-1 rounded bg-card/80 border px-2 py-0.5 text-muted-foreground">
              <Cpu className="size-3 text-primary" />
              AI Parser: <span className="font-medium text-foreground">{activeReport.ai_status || "Deterministic Rule Engine"}</span>
            </span>
            <span className="flex items-center gap-1 rounded bg-card/80 border px-2 py-0.5 text-muted-foreground">
              <ImageIcon className="size-3 text-amber-500" />
              OCR Engine: <span className="font-medium text-foreground">{activeReport.ocr_status || "Not Required"}</span>
            </span>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Findings Count Breakdown */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5 text-center">
            <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-2.5">
              <span className="text-[10px] uppercase font-bold text-destructive">Critical</span>
              <p className="font-mono text-xl font-bold text-destructive">
                {activeReport.summary.critical}
              </p>
            </div>
            <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 p-2.5">
              <span className="text-[10px] uppercase font-bold text-orange-600 dark:text-orange-400">High</span>
              <p className="font-mono text-xl font-bold text-orange-600 dark:text-orange-400">
                {activeReport.summary.high}
              </p>
            </div>
            <div className="rounded-lg border border-warning/20 bg-warning/10 p-2.5">
              <span className="text-[10px] uppercase font-bold text-warning">Medium</span>
              <p className="font-mono text-xl font-bold text-warning">
                {activeReport.summary.medium}
              </p>
            </div>
            <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 p-2.5">
              <span className="text-[10px] uppercase font-bold text-blue-600 dark:text-blue-400">Low</span>
              <p className="font-mono text-xl font-bold text-blue-600 dark:text-blue-400">
                {activeReport.summary.low}
              </p>
            </div>
            <div className="col-span-2 sm:col-span-1 rounded-lg border border-border bg-card p-2.5">
              <span className="text-[10px] uppercase font-bold text-muted-foreground">Total Findings</span>
              <p className="font-mono text-xl font-bold text-foreground">
                {activeReport.summary.total_findings}
              </p>
            </div>
          </div>

          {/* FAIR Risk Metrics Summary */}
          {activeReport.calculated_metrics && (
            <div className="rounded-lg border border-primary/20 bg-primary/5 p-3 text-xs flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <DollarSign className="size-4 text-primary shrink-0" />
                <div>
                  <span className="font-semibold text-foreground">FAIR Financial Risk Loss Quantified: </span>
                  <span className="text-muted-foreground">
                    ALE:{" "}
                    <strong className="text-destructive font-mono">
                      {formatCurrency(activeReport.calculated_metrics.annual_loss_expectancy, currency)}
                    </strong>{" "}
                    · SLE:{" "}
                    <span className="font-mono">
                      {formatCurrency(activeReport.calculated_metrics.single_loss_expectancy, currency)}
                    </span>{" "}
                    · LEF:{" "}
                    <span className="font-mono">
                      {activeReport.calculated_metrics.loss_event_frequency.toFixed(2)}/yr
                    </span>
                    {activeReport.calculated_metrics.security_roi_percentage != null && (
                      <>
                        {" "}· Projected Net ROI:{" "}
                        <span className="font-mono text-emerald-500 font-semibold">
                          +{activeReport.calculated_metrics.security_roi_percentage.toFixed(0)}%
                        </span>
                      </>
                    )}
                  </span>
                </div>
              </div>

              <Button
                size="sm"
                onClick={() => navigate("overview")}
                className="font-medium gap-1.5 shrink-0"
              >
                Continue to Dashboard
                <ArrowRight className="size-3.5" />
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Warnings & Model Assumption Notices (if any) */}
      {((activeReport.warnings && activeReport.warnings.length > 0) ||
        (activeReport.missing_fields && activeReport.missing_fields.length > 0)) && (
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardHeader className="py-2.5 px-4">
            <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
              <AlertTriangle className="size-4" />
              <CardTitle className="text-xs font-semibold">
                Model Transparency & Assumption Notices
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-1.5 text-xs">
            {activeReport.missing_fields && activeReport.missing_fields.length > 0 && (
              <div className="flex items-start gap-2 text-amber-700 dark:text-amber-300">
                <Info className="size-3.5 mt-0.5 shrink-0" />
                <div>
                  <strong>Omitted Parameters: </strong>
                  <span className="font-mono">{activeReport.missing_fields.join(", ")}</span>
                  <p className="text-[11px] text-muted-foreground mt-0.5">
                    Missing parameters were not fabricated. Assessment utilizes standard FAIR baseline estimation formulas.
                  </p>
                </div>
              </div>
            )}
            {activeReport.warnings &&
              activeReport.warnings.map((w, idx) => (
                <div key={idx} className="flex items-start gap-2 text-muted-foreground text-[11px]">
                  <span className="text-amber-500 font-bold">•</span>
                  <span>{w}</span>
                </div>
              ))}
          </CardContent>
        </Card>
      )}

      {/* Itemized Findings Breakdown */}
      <Card>
        <CardHeader className="pb-3 flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldAlert className="size-4 text-primary" />
              Extracted Live Findings ({activeReport.findings.length} Items)
            </CardTitle>
            <CardDescription className="text-xs mt-0.5">
              Deterministic findings extracted directly from {activeReport.filename}.
            </CardDescription>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
            className="text-xs text-muted-foreground"
          >
            {showTechnicalDetails ? (
              <>
                <ChevronUp className="size-3.5 mr-1" /> Hide List
              </>
            ) : (
              <>
                <ChevronDown className="size-3.5 mr-1" /> Show List
              </>
            )}
          </Button>
        </CardHeader>

        {showTechnicalDetails && (
          <CardContent className="p-0">
            <div className="divide-y text-xs max-h-[460px] overflow-y-auto">
              {activeReport.findings.map((finding, idx) => (
                <div key={finding.id || idx} className="p-3.5 space-y-1.5 hover:bg-muted/30 transition-colors">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <LevelBadge level={finding.severity as any} />
                      <span className="font-mono text-[11px] text-muted-foreground">
                        {finding.cve || finding.id}
                      </span>
                      <span className="font-medium text-foreground text-xs">
                        {finding.title}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold flex items-center gap-1 ${
                          finding.is_inferred
                            ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/30"
                            : "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30"
                        }`}
                      >
                        {finding.is_inferred ? <Sparkles className="size-3" /> : <Check className="size-3" />}
                        {finding.is_inferred ? "AI-Inferred" : "Stated Fact"}
                      </span>
                      {finding.cvss_score != null && (
                        <span className="font-mono text-xs font-semibold rounded bg-muted px-1.5 py-0.5 border">
                          CVSS {finding.cvss_score.toFixed(1)}
                        </span>
                      )}
                    </div>
                  </div>

                  {finding.recommendation && (
                    <p className="text-muted-foreground text-[11px] leading-relaxed">
                      <strong className="text-foreground">Remediation: </strong>
                      {finding.recommendation}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        )}
      </Card>

      {/* Raw Extracted Untrusted Document Text Preview */}
      {activeReport.extracted_text_preview && (
        <Card>
          <CardHeader
            className="py-2.5 px-4 cursor-pointer"
            onClick={() => setShowTextPreview(!showTextPreview)}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
                <FileCode className="size-3.5 text-muted-foreground" />
                <span>Extracted Document Text Preview (Sanitized Passive Text)</span>
              </div>
              <Button variant="ghost" size="sm" className="h-6 text-xs text-muted-foreground">
                {showTextPreview ? (
                  <>
                    <ChevronUp className="size-3 mr-1" /> Hide
                  </>
                ) : (
                  <>
                    <ChevronDown className="size-3 mr-1" /> View
                  </>
                )}
              </Button>
            </div>
          </CardHeader>
          {showTextPreview && (
            <CardContent className="pt-0 px-4 pb-3">
              <pre className="max-h-52 overflow-auto rounded bg-muted/60 p-2.5 font-mono text-[10px] text-muted-foreground whitespace-pre-wrap leading-relaxed border">
                {activeReport.extracted_text_preview}
              </pre>
              <p className="text-[10px] text-muted-foreground mt-1 italic">
                * Passive string preview only. Document contents are never executed or evaluated as code.
              </p>
            </CardContent>
          )}
        </Card>
      )}

      {/* Bottom Action Footer */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
        <Button
          variant="outline"
          size="default"
          onClick={() => navigate("report-upload")}
          className="text-xs"
        >
          <RotateCcw className="size-3.5 mr-1.5" />
          Upload Another Document
        </Button>
        <Button
          size="default"
          onClick={() => navigate("overview")}
          className="font-medium gap-2 w-full sm:w-auto"
        >
          View Executive Overview
          <ArrowRight className="size-4" />
        </Button>
      </div>
    </div>
  )
}
