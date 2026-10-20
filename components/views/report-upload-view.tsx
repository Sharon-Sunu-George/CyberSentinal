"use client"

import { useState } from "react"
import {
  AlertCircle,
  BrainCircuit,
  FileCode,
  FileSpreadsheet,
  FileText,
  Home,
  ImageIcon,
  Loader2,
  RotateCcw,
  Shield,
  Upload,
  UploadCloud,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useAppState } from "@/components/app/app-state"
import { apiClient } from "@/lib/api-client"

export function ReportUploadView() {
  const { navigate, importScannerReport } = useAppState()
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [progressPercent, setProgressPercent] = useState(20)
  const [statusMessage, setStatusMessage] = useState("Connecting to FastAPI backend...")
  const [error, setError] = useState<string | null>(null)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null
    setError(null)

    if (file) {
      const validExtensions = [".json", ".csv", ".txt", ".docx", ".pdf", ".png", ".jpg", ".jpeg"]
      const fileNameLower = file.name.toLowerCase()
      const hasValidExt = validExtensions.some((ext) => fileNameLower.endsWith(ext))

      if (!hasValidExt) {
        setError(
          "Invalid file format. Supported formats: Structured CSV, JSON, TXT, Word (.docx), PDF (text/scanned), and Images (.png, .jpg, .jpeg)."
        )
        setSelectedFile(null)
        return
      }

      if (file.size > 25 * 1024 * 1024) {
        setError("File size exceeds allowable limit of 25MB.")
        setSelectedFile(null)
        return
      }

      if (file.size === 0) {
        setError("Uploaded file is empty (0 bytes).")
        setSelectedFile(null)
        return
      }

      setSelectedFile(file)
    }
  }

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setError("Please select a document or report before submitting.")
      return
    }
    setError(null)
    setIsAnalyzing(true)
    setProgressPercent(25)
    setStatusMessage("Uploading document to FastAPI ingestion endpoint (port 8000)...")

    try {
      // Send document to FastAPI /api/v1/reports/upload endpoint
      const result = await apiClient.uploadReport(selectedFile)
      setProgressPercent(80)
      setStatusMessage("Extracting findings & evaluating deterministic FAIR metrics...")
      
      // Ingest the parsed findings into the global app state and calculate risk
      importScannerReport(result)
      setProgressPercent(100)
      
      // Navigate directly to the Executive Overview dashboard with latest report data
      navigate("overview")
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(`Processing failed: ${msg}. Please verify document formatting and ensure FastAPI is reachable on port 8000.`)
      setIsAnalyzing(false)
    }
  }

  const handleReset = () => {
    setSelectedFile(null)
    setError(null)
  }

  return (
    <div className="flex flex-col max-w-4xl mx-auto pt-10 md:pt-14 px-4 pb-16">
      {/* Top Header with Back to Home in Top Right Corner */}
      <div className="flex items-start justify-between gap-4 border-b pb-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-primary font-semibold text-lg md:text-xl">
            <UploadCloud className="size-5" />
            <span>Security Scanner & Document Ingestion</span>
          </div>
          <p className="text-xs text-muted-foreground max-w-xl leading-relaxed">
            Upload vulnerability scan results, penetration testing documents, or compliance audits to ingest live findings directly into the Executive Overview dashboard.
          </p>
        </div>

        <div className="shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (typeof window !== "undefined") {
                window.location.href = "/"
              }
            }}
            className="text-xs gap-1.5 shadow-sm"
          >
            <Home className="size-3.5 text-primary" />
            Back to Home
          </Button>
        </div>
      </div>

      {/* Main Content pushed down slightly */}
      <div className="mt-7 flex flex-col gap-6">

      {/* Supported Formats Banner */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
        <div className="flex items-center gap-1.5 rounded-md border bg-card p-2">
          <FileSpreadsheet className="size-3.5 text-emerald-500 shrink-0" />
          <div className="truncate">
            <span className="font-semibold block text-[11px]">CSV & JSON</span>
            <span className="text-[10px] text-muted-foreground">FAIR & Vulnerability tables</span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 rounded-md border bg-card p-2">
          <FileText className="size-3.5 text-blue-500 shrink-0" />
          <div className="truncate">
            <span className="font-semibold block text-[11px]">TXT & DOCX</span>
            <span className="text-[10px] text-muted-foreground">Word docs & Pentest notes</span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 rounded-md border bg-card p-2">
          <FileCode className="size-3.5 text-purple-500 shrink-0" />
          <div className="truncate">
            <span className="font-semibold block text-[11px]">PDF Reports</span>
            <span className="text-[10px] text-muted-foreground">Vector & Scanned PDFs</span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 rounded-md border bg-card p-2">
          <ImageIcon className="size-3.5 text-amber-500 shrink-0" />
          <div className="truncate">
            <span className="font-semibold block text-[11px]">PNG / JPG</span>
            <span className="text-[10px] text-muted-foreground">Windows / Tesseract OCR</span>
          </div>
        </div>
      </div>

      {/* Upload Drop Zone Card - Primary Focus */}
      <Card className="border-primary/20 bg-card">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">
            {isAnalyzing ? "Ingesting & Quantifying Document" : "Select or Drop Document"}
          </CardTitle>
          <CardDescription className="text-xs">
            {isAnalyzing
              ? "Running deterministic FAIR quantification engine on extracted findings."
              : "Supported formats: JSON, CSV, TXT, Word (.docx), PDF, PNG, JPG/JPEG (Up to 25MB). Uploads are safely treated as untrusted data without execution."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isAnalyzing ? (
            /* Calculating Active State - Quantifying Financial Cyber Risk */
            <div className="flex flex-col items-center justify-center py-10 px-4 space-y-5 max-w-md mx-auto text-center">
              <div className="relative mx-auto w-fit">
                <div className="size-16 rounded-full border-4 border-primary/20 border-t-primary animate-spin" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <BrainCircuit className="size-6 text-primary animate-pulse" />
                </div>
              </div>

              <div className="space-y-1.5">
                <h3 className="text-sm font-semibold text-foreground">
                  Quantifying Financial Cyber Risk
                </h3>
                <p className="text-xs text-muted-foreground font-mono">
                  {statusMessage}
                </p>
              </div>

              {/* Real progress track */}
              <div className="space-y-1.5 w-full">
                <div className="h-2 w-full bg-secondary rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary transition-all duration-300 ease-out"
                    style={{ width: `${progressPercent}%` }}
                  />
                </div>
                <div className="flex justify-between text-[11px] text-muted-foreground font-mono">
                  <span>FAIR Engine (FastAPI 8000)</span>
                  <span>{progressPercent}%</span>
                </div>
              </div>

              <div className="rounded-lg bg-card border p-3 text-left space-y-1 text-[11px] text-muted-foreground w-full">
                <div className="flex items-center gap-1.5 text-foreground font-medium">
                  <Shield className="size-3.5 text-primary" />
                  <span>Deterministic Calculations in Progress:</span>
                </div>
                <p>• Single Loss Expectancy (SLE) = Direct Loss + Indirect Loss</p>
                <p>• Loss Event Frequency (LEF) = Threat Frequency × Vulnerability Probability</p>
                <p>• Annual Loss Expectancy (ALE) = LEF × SLE</p>
                <p>• Net Security ROI = (Risk Reduction - Investment Cost) / Investment Cost</p>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border-2 border-dashed border-border bg-card/50 p-8 text-center transition-colors hover:border-primary/50">
              <input
                type="file"
                id="report-upload-input"
                className="hidden"
                onChange={handleFileChange}
                accept=".pdf,.json,.csv,.xlsx,.txt,.docx,.png,.jpg,.jpeg"
              />
              <label
                htmlFor="report-upload-input"
                className="flex flex-col items-center justify-center cursor-pointer gap-3"
              >
                <div className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary">
                  <Upload className="size-6" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-medium text-foreground">
                    Click to select a document or drag & drop
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Accepts structured scan exports, audit documents, or camera/screenshot images
                  </p>
                </div>
              </label>

              {/* Selected File Details & Upload Action */}
              {selectedFile && (
                <div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-md border bg-muted/40 px-4 py-3 text-left">
                  <div className="flex items-center gap-3">
                    <FileText className="size-5 text-primary shrink-0" />
                    <div>
                      <p className="text-xs font-medium text-foreground truncate max-w-xs sm:max-w-md">
                        {selectedFile.name}
                      </p>
                      <p className="text-[11px] text-muted-foreground font-mono">
                        {(selectedFile.size / 1024).toFixed(1)} KB · {selectedFile.type || "Document"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={handleReset}
                      disabled={isAnalyzing}
                      className="text-xs text-muted-foreground"
                    >
                      <RotateCcw className="size-3.5 mr-1" />
                      Clear
                    </Button>
                    <Button
                      size="sm"
                      onClick={handleAnalyze}
                      disabled={isAnalyzing}
                      className="shrink-0"
                    >
                      Upload & Scan Document
                    </Button>
                  </div>
                </div>
              )}

              {error && (
                <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-destructive text-left rounded-md bg-destructive/10 p-3 border border-destructive/20">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="size-4 shrink-0" />
                    <span>{error}</span>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={handleAnalyze}
                    disabled={!selectedFile || isAnalyzing}
                    className="h-7 text-xs border-destructive/30 hover:bg-destructive/20 self-start sm:self-auto"
                  >
                    Retry Upload
                  </Button>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      </div>
    </div>
  )
}
