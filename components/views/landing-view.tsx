"use client"

import { ArrowRight, Bot, BrainCircuit, FileSearch, ShieldCheck } from "lucide-react"
import { useAppState } from "@/components/app/app-state"

export function LandingView() {
  const { navigate } = useAppState()

  return (
    <div
      className="relative flex min-h-svh w-full flex-col items-center justify-center p-4 md:p-8 bg-cover bg-center bg-no-repeat"
      style={{ backgroundImage: "url('/home-bg.jpg')" }}
    >
      {/* Dark overlay to preserve readability */}
      <div className="absolute inset-0 bg-background/80 backdrop-blur-[2px]" aria-hidden="true" />

      <div className="relative z-10 flex w-full max-w-5xl flex-col items-center text-center">
        {/* CyberSentinel AI Logo & Branding */}
        <div className="mb-6 flex items-center gap-3">
          <span className="flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary ring-1 ring-inset ring-primary/30 shadow-md">
            <ShieldCheck className="size-6" aria-hidden="true" />
          </span>
          <div className="flex flex-col text-left leading-tight">
            <span className="text-base font-bold text-foreground">CyberSentinel AI</span>
            <span className="text-xs text-muted-foreground">Cyber Risk Intelligence & Optimization</span>
          </div>
        </div>

        {/* Short Headline & Supporting Sentence */}
        <h1 className="text-3xl font-bold tracking-tight text-foreground md:text-4xl text-balance">
          What would you like to do?
        </h1>
        <p className="mt-2 text-sm text-muted-foreground md:text-base text-balance">
          Choose a service to get started.
        </p>

        {/* Exactly THREE Prominent Cards */}
        <div className="mt-10 grid w-full grid-cols-1 gap-5 sm:grid-cols-3">
          {/* Card 1: Cyber Risk Analysis */}
          <button
            type="button"
            onClick={() => navigate("risk-assessment")}
            className="group flex flex-col items-start justify-between rounded-xl border border-border/80 bg-card/90 p-6 text-left backdrop-blur-sm transition-all hover:border-primary/60 hover:bg-card hover:shadow-xl focus-visible:outline-2 focus-visible:outline-ring"
          >
            <div className="w-full">
              <div className="mb-4 flex size-12 items-center justify-center rounded-lg bg-primary/10 text-primary transition-transform group-hover:scale-105">
                <BrainCircuit className="size-6" aria-hidden="true" />
              </div>
              <h2 className="text-lg font-semibold text-foreground group-hover:text-primary">
                Cyber Risk Analysis
              </h2>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                Analyze cyber risks and discover actionable insights.
              </p>
            </div>
            <div className="mt-6 flex w-full items-center text-xs font-medium text-primary">
              <span>Start Risk Analysis</span>
              <ArrowRight className="ml-1.5 size-3.5 transition-transform group-hover:translate-x-1" aria-hidden="true" />
            </div>
          </button>

          {/* Card 2: Security Report Analysis */}
          <button
            type="button"
            onClick={() => navigate("report-upload")}
            className="group flex flex-col items-start justify-between rounded-xl border border-border/80 bg-card/90 p-6 text-left backdrop-blur-sm transition-all hover:border-primary/60 hover:bg-card hover:shadow-xl focus-visible:outline-2 focus-visible:outline-ring"
          >
            <div className="w-full">
              <div className="mb-4 flex size-12 items-center justify-center rounded-lg bg-accent/30 text-foreground transition-transform group-hover:scale-105">
                <FileSearch className="size-6 text-primary" aria-hidden="true" />
              </div>
              <h2 className="text-lg font-semibold text-foreground group-hover:text-primary">
                Security Report Analysis
              </h2>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                Upload a security report or scanned document for analysis.
              </p>
            </div>
            <div className="mt-6 flex w-full items-center text-xs font-medium text-primary">
              <span>Upload & Analyze</span>
              <ArrowRight className="ml-1.5 size-3.5 transition-transform group-hover:translate-x-1" aria-hidden="true" />
            </div>
          </button>

          {/* Card 3: Real Website Assessment & Remediation Planner */}
          <button
            type="button"
            onClick={() => navigate("agent-simulation")}
            className="group flex flex-col items-start justify-between rounded-xl border border-border/80 bg-card/90 p-6 text-left backdrop-blur-sm transition-all hover:border-warning/60 hover:bg-card hover:shadow-xl focus-visible:outline-2 focus-visible:outline-ring"
          >
            <div className="w-full">
              <div className="mb-4 flex size-12 items-center justify-center rounded-lg bg-warning/10 text-warning transition-transform group-hover:scale-105">
                <Bot className="size-6" aria-hidden="true" />
              </div>
              <h2 className="text-lg font-semibold text-foreground group-hover:text-warning">
                Real Website Assessment
              </h2>
              <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                Real Website Assessment and Remediation Planner for web security assessments.
              </p>
            </div>
            <div className="mt-6 flex w-full items-center text-xs font-medium text-warning">
              <span>Launch Assessment Engine</span>
              <ArrowRight className="ml-1.5 size-3.5 transition-transform group-hover:translate-x-1" aria-hidden="true" />
            </div>
          </button>
        </div>
      </div>
    </div>
  )
}
