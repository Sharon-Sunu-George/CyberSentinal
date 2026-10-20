"use client"

import {
  createContext,
  use,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type ReactNode,
} from "react"
import {
  initialActivity,
  initialDataset,
  riskTrendHistory as initialRiskTrendHistory,
  securityGapDefinitions,
  SIMULATED_BASE_TIME,
} from "@/lib/mock-data"
import { assess, deriveSecurityGaps } from "@/lib/risk"
import { runScenario, threatScenarios } from "@/lib/simulation"
import type {
  ActivityEvent,
  Assessment,
  Asset,
  AssetType,
  Criticality,
  Dataset,
  Exposure,
  SecurityGap,
  Severity,
  ViewId,
  Vulnerability,
} from "@/lib/types"
import {
  apiClient,
  type BackendParsedReportResponse,
  type BackendRiskAssessmentResponse,
} from "@/lib/api-client"

import type { CurrencyCode } from "@/lib/types"

const DEFAULT_AUTO_REFRESH_INTERVAL_SEC = 60
const ASSESSMENT_DELAY_MS = 500

const STORAGE_KEYS = {
  DATASET: "cybersentinel_dataset_v1",
  ASSESSMENT: "cybersentinel_assessment_v1",
  ACTIVITY: "cybersentinel_activity_v1",
  TREND: "cybersentinel_trend_v1",
  AUTO_REFRESH: "cybersentinel_autorefresh_v1",
  SCENARIO_INDEX: "cybersentinel_scenario_index_v1",
  ACTIVE_REPORT: "cybersentinel_active_report_v1",
  VIEW: "cybersentinel_view_v1",
  HISTORY: "cybersentinel_history_v1",
  CURRENCY: "cybersentinel_currency_v1",
  LAST_ASSESSMENT_AT: "cybersentinel_last_assessment_v1",
  LAST_REPORT_AT: "cybersentinel_last_report_v1",
}

export function getViewFromUrl(): ViewId | null {
  if (typeof window === "undefined") return null
  const searchParam = new URLSearchParams(window.location.search).get("view")
  const hash = window.location.hash.replace(/^#\/?/, "")
  const candidate = (searchParam || hash) as ViewId | null
  const validViews: ViewId[] = [
    "landing",
    "overview",
    "explorer",
    "analyst",
    "investments",
    "gaps",
    "activity",
    "settings",
    "risk-assessment",
    "report-upload",
    "report-analysis",
    "agent-simulation",
  ]
  if (candidate && validViews.includes(candidate)) {
    return candidate
  }
  return null
}

interface TrendPoint {
  day: string
  score: number
}

interface State {
  view: ViewId
  history: ViewId[]
  dataset: Dataset
  assessment: Assessment
  previousAssessment: Assessment | null
  activity: ActivityEvent[]
  trendHistory: TrendPoint[]
  scenarioIndex: number
  isAssessing: boolean
  assessmentError: string | null
  isStale: boolean
  unread: number
  analystAssetId: string | null
  lastSimulation: ActivityEvent | null
  autoRefreshEnabled: boolean
  nextAssessmentSeconds: number
  activeReport: BackendParsedReportResponse | null
  currency: CurrencyCode
  lastRiskAssessmentAt: string | null
  lastReportAnalyzedAt: string | null
}

type Action =
  | { type: "hydrate-storage"; payload: Partial<State> }
  | { type: "navigate"; view: ViewId; analystAssetId?: string }
  | { type: "go-back" }
  | { type: "assess-start" }
  | { type: "assess-complete"; at: string; backendResult?: BackendRiskAssessmentResponse }
  | { type: "assess-failed"; error: string }
  | { type: "clear-assessment-error" }
  | { type: "simulate-tick"; at: string }
  | { type: "simulate-scenario"; at: string }
  | { type: "record-remediation"; vulnerabilityId: string; at: string }
  | { type: "import-scanner-report"; report: BackendParsedReportResponse; at: string }
  | { type: "restore-baseline"; at: string }
  | { type: "toggle-auto-refresh" }
  | { type: "decrement-timer" }
  | { type: "reset-timer" }
  | { type: "mark-read" }
  | { type: "set-currency"; currency: CurrencyCode }
  | { type: "reset" }

function loadPersistedState(): Partial<State> {
  if (typeof window === "undefined") return {}
  try {
    // Clear legacy saved view key so it never overrides the initial landing page
    localStorage.removeItem(STORAGE_KEYS.VIEW)

    const savedDataset = localStorage.getItem(STORAGE_KEYS.DATASET)
    const savedAssessment = localStorage.getItem(STORAGE_KEYS.ASSESSMENT)
    const savedActivity = localStorage.getItem(STORAGE_KEYS.ACTIVITY)
    const savedTrend = localStorage.getItem(STORAGE_KEYS.TREND)
    const savedAutoRefresh = localStorage.getItem(STORAGE_KEYS.AUTO_REFRESH)
    const savedScenarioIdx = localStorage.getItem(STORAGE_KEYS.SCENARIO_INDEX)
    const savedReport = localStorage.getItem(STORAGE_KEYS.ACTIVE_REPORT)
    const savedHistory = localStorage.getItem(STORAGE_KEYS.HISTORY)
    const savedCurrency = localStorage.getItem(STORAGE_KEYS.CURRENCY) as CurrencyCode | null
    const savedLastAssessment = localStorage.getItem(STORAGE_KEYS.LAST_ASSESSMENT_AT)
    const savedLastReport = localStorage.getItem(STORAGE_KEYS.LAST_REPORT_AT)

    return {
      dataset: savedDataset ? JSON.parse(savedDataset) : undefined,
      assessment: savedAssessment ? JSON.parse(savedAssessment) : undefined,
      activity: savedActivity ? JSON.parse(savedActivity) : undefined,
      trendHistory: savedTrend ? JSON.parse(savedTrend) : undefined,
      autoRefreshEnabled: savedAutoRefresh !== null ? JSON.parse(savedAutoRefresh) : undefined,
      scenarioIndex: savedScenarioIdx !== null ? Number(savedScenarioIdx) : undefined,
      activeReport: savedReport ? JSON.parse(savedReport) : null,
      history: savedHistory ? JSON.parse(savedHistory) : undefined,
      currency: savedCurrency || "USD",
      lastRiskAssessmentAt: savedLastAssessment || null,
      lastReportAnalyzedAt: savedLastReport || null,
    }
  } catch {
    return {}
  }
}

function saveStateToStorage(state: State) {
  if (typeof window === "undefined") return
  try {
    localStorage.setItem(STORAGE_KEYS.DATASET, JSON.stringify(state.dataset))
    localStorage.setItem(STORAGE_KEYS.ASSESSMENT, JSON.stringify(state.assessment))
    localStorage.setItem(STORAGE_KEYS.ACTIVITY, JSON.stringify(state.activity))
    localStorage.setItem(STORAGE_KEYS.TREND, JSON.stringify(state.trendHistory))
    localStorage.setItem(STORAGE_KEYS.AUTO_REFRESH, JSON.stringify(state.autoRefreshEnabled))
    localStorage.setItem(STORAGE_KEYS.SCENARIO_INDEX, String(state.scenarioIndex))
    localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(state.history || []))
    localStorage.setItem(STORAGE_KEYS.CURRENCY, state.currency)
    if (state.lastRiskAssessmentAt) {
      localStorage.setItem(STORAGE_KEYS.LAST_ASSESSMENT_AT, state.lastRiskAssessmentAt)
    }
    if (state.lastReportAnalyzedAt) {
      localStorage.setItem(STORAGE_KEYS.LAST_REPORT_AT, state.lastReportAnalyzedAt)
    } else {
      localStorage.removeItem(STORAGE_KEYS.LAST_REPORT_AT)
    }
    if (state.activeReport) {
      localStorage.setItem(STORAGE_KEYS.ACTIVE_REPORT, JSON.stringify(state.activeReport))
    } else {
      localStorage.removeItem(STORAGE_KEYS.ACTIVE_REPORT)
    }
  } catch {
    // LocalStorage write ignored
  }
}

function initState(): State {
  const dataset = initialDataset
  const baseAssessment = assess(dataset, SIMULATED_BASE_TIME)
  if (!baseAssessment.backendResult) {
    baseAssessment.backendResult = {
      scenario_name: "FinSecure Technologies - Customer Core Banking & PII Database Risk Evaluation",
      asset_name: "Customer Core Banking & PII Database",
      asset_value: 5000000,
      metrics: {
        loss_event_frequency: 0.7,
        single_loss_expectancy: 450000,
        annual_loss_expectancy: 315000,
        mitigated_annual_loss_expectancy: 90000,
        annual_risk_reduction: 225000,
        security_roi_percentage: 350,
      },
      assumptions: [
        "Threat Event Frequency (TEF): 2.00 attempts/year.",
        "Baseline Vulnerability Probability: 35.0%.",
        "Single Loss Expectancy (SLE): $450,000.00 per event ($150,000.00 direct + $300,000.00 indirect).",
        "Linear Loss Event Frequency (LEF = TEF * Vulnerability) assumed under standard FAIR principles.",
      ],
      recommendation: "RECOMMENDED: Deploy security controls. The proposed investment of $50,000.00 yields an estimated annual financial risk reduction of $225,000.00 (Net ROI: 350.0%).",
    }
  }

  return {
    view: "landing",
    history: [],
    dataset,
    assessment: baseAssessment,
    previousAssessment: null,
    activity: initialActivity,
    trendHistory: initialRiskTrendHistory,
    scenarioIndex: 0,
    isAssessing: false,
    assessmentError: null,
    isStale: false,
    unread: 2,
    analystAssetId: null,
    lastSimulation: null,
    autoRefreshEnabled: true,
    nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
    activeReport: null,
    currency: "USD",
    lastRiskAssessmentAt: SIMULATED_BASE_TIME,
    lastReportAnalyzedAt: null,
  }
}

function updateTrend(history: TrendPoint[], latestScore: number): TrendPoint[] {
  const last = history[history.length - 1]
  if (last && last.day === "Today") {
    return [...history.slice(0, -1), { day: "Today", score: latestScore }]
  }
  const slice = history.length >= 7 ? history.slice(1) : history
  return [...slice, { day: "Today", score: latestScore }]
}

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "set-currency": {
      const nextState = { ...state, currency: action.currency }
      saveStateToStorage(nextState)
      return nextState
    }

    case "hydrate-storage": {
      const p = action.payload
      const nextView = p.view || state.view
      return {
        ...state,
        view: nextView,
        history: p.history || state.history,
        dataset: p.dataset || state.dataset,
        assessment: p.assessment || state.assessment,
        activity: p.activity || state.activity,
        trendHistory: p.trendHistory || state.trendHistory,
        autoRefreshEnabled: p.autoRefreshEnabled !== undefined ? p.autoRefreshEnabled : state.autoRefreshEnabled,
        scenarioIndex: p.scenarioIndex !== undefined ? p.scenarioIndex : state.scenarioIndex,
        activeReport: p.activeReport !== undefined ? p.activeReport : state.activeReport,
        currency: p.currency || state.currency,
        lastRiskAssessmentAt: p.lastRiskAssessmentAt !== undefined ? p.lastRiskAssessmentAt : state.lastRiskAssessmentAt,
        lastReportAnalyzedAt: p.lastReportAnalyzedAt !== undefined ? p.lastReportAnalyzedAt : state.lastReportAnalyzedAt,
      }
    }

    case "navigate": {
      if (action.view === state.view) {
        return { ...state, analystAssetId: action.analystAssetId ?? state.analystAssetId }
      }
      const nextHistory = [...(state.history || []), state.view].slice(-25)
      const nextState = {
        ...state,
        view: action.view,
        history: nextHistory,
        analystAssetId: action.analystAssetId ?? state.analystAssetId,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "go-back": {
      const currentHistory = state.history || []
      if (currentHistory.length === 0) {
        // Fallback: if in subpage return to overview; if on overview return to landing
        const fallbackView: ViewId = state.view === "overview" ? "landing" : "overview"
        const nextState = { ...state, view: fallbackView }
        saveStateToStorage(nextState)
        return nextState
      }
      const nextHistory = [...currentHistory]
      const prevView = nextHistory.pop()!
      const nextState = { ...state, view: prevView, history: nextHistory }
      saveStateToStorage(nextState)
      return nextState
    }

    case "assess-start":
      return { ...state, isAssessing: true, assessmentError: null }

    case "assess-failed":
      return { ...state, isAssessing: false, assessmentError: action.error }

    case "clear-assessment-error":
      return { ...state, assessmentError: null }

    case "assess-complete": {
      const next = assess(state.dataset, action.at)
      if (action.backendResult) {
        next.backendResult = action.backendResult
      } else if (state.assessment.backendResult) {
        next.backendResult = state.assessment.backendResult
      }
      const delta = next.overallScore - state.assessment.overallScore
      const event: ActivityEvent = {
        id: `evt-assess-${action.at}`,
        at: action.at,
        kind: "assessment",
        title: action.backendResult
          ? `FAIR risk assessment quantified: ${action.backendResult.asset_name}`
          : "Risk assessment completed",
        description: action.backendResult
          ? `Quantified ALE: $${action.backendResult.metrics.annual_loss_expectancy.toLocaleString()} (SLE: $${action.backendResult.metrics.single_loss_expectancy.toLocaleString()}, LEF: ${action.backendResult.metrics.loss_event_frequency}/yr). ${action.backendResult.recommendation}`
          : `Re-assessed ${next.assetRisks.length} assets and telemetry signals. Overall risk ${state.assessment.overallScore} → ${next.overallScore}${delta === 0 ? " (stable)" : ""}.`,
        severity: "Info",
        overallChange: { before: state.assessment.overallScore, after: next.overallScore },
      }
      const nextTrend = updateTrend(state.trendHistory, next.overallScore)
      const nextState: State = {
        ...state,
        previousAssessment: state.assessment,
        assessment: next,
        trendHistory: nextTrend,
        isAssessing: false,
        assessmentError: null,
        isStale: false,
        activity: [event, ...state.activity.slice(0, 49)],
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
        lastRiskAssessmentAt: action.at,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "simulate-tick": {
      // If a real scan report is actively loaded, do not mutate its real findings with synthetic demo scenarios
      if (state.activeReport) {
        return {
          ...state,
          nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
        }
      }

      // Periodic automatic simulation step: cycle through realistic threat & remediation scenarios on baseline estate
      const idx = state.scenarioIndex % threatScenarios.length
      const scenario = threatScenarios[idx]
      const outcome = runScenario(state.dataset, scenario, action.at)
      if (state.assessment.backendResult) {
        outcome.assessment.backendResult = state.assessment.backendResult
      }
      const nextTrend = updateTrend(state.trendHistory, outcome.assessment.overallScore)
      const nextState: State = {
        ...state,
        dataset: outcome.dataset,
        previousAssessment: state.assessment,
        assessment: outcome.assessment,
        trendHistory: nextTrend,
        activity: [outcome.event, ...state.activity.slice(0, 49)],
        scenarioIndex: idx + 1,
        isAssessing: false,
        isStale: false,
        unread: state.unread + 1,
        lastSimulation: outcome.event,
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "simulate-scenario": {
      const idx = state.scenarioIndex % threatScenarios.length
      const scenario = threatScenarios[idx]
      const outcome = runScenario(state.dataset, scenario, action.at)
      if (state.assessment.backendResult) {
        outcome.assessment.backendResult = state.assessment.backendResult
      }
      const nextTrend = updateTrend(state.trendHistory, outcome.assessment.overallScore)
      const nextState: State = {
        ...state,
        dataset: outcome.dataset,
        previousAssessment: state.assessment,
        assessment: outcome.assessment,
        trendHistory: nextTrend,
        activity: [outcome.event, ...state.activity.slice(0, 49)],
        scenarioIndex: idx + 1,
        isAssessing: false,
        isStale: false,
        unread: state.unread + 1,
        lastSimulation: outcome.event,
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "record-remediation": {
      const vuln = state.dataset.vulnerabilities.find((v) => v.id === action.vulnerabilityId)
      if (!vuln || vuln.remediated) return state
      const asset = state.dataset.assets.find((a) => a.id === vuln.assetId)
      const dataset: Dataset = {
        vulnerabilities: state.dataset.vulnerabilities.map((v) => (v.id === vuln.id ? { ...v, remediated: true } : v)),
        assets: state.dataset.assets.map((a) =>
          a.id === vuln.assetId ? { ...a, openVulnerabilityCount: Math.max(0, a.openVulnerabilityCount - 1) } : a,
        ),
      }
      const event: ActivityEvent = {
        id: `evt-rem-${vuln.id}-${action.at}`,
        at: action.at,
        kind: "remediation",
        title: `Remediation recorded: ${vuln.demoId}`,
        description: `${vuln.title} remediated on ${asset?.name ?? "asset"}. Triggering automatic reassessment.`,
        severity: "Info",
        assetId: vuln.assetId,
      }
      const afterAssess = assess(dataset, action.at)
      const nextTrend = updateTrend(state.trendHistory, afterAssess.overallScore)
      const nextState: State = {
        ...state,
        dataset,
        previousAssessment: state.assessment,
        assessment: afterAssess,
        trendHistory: nextTrend,
        isStale: false,
        activity: [event, ...state.activity.slice(0, 49)],
        unread: state.unread + 1,
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "import-scanner-report": {
      const report = action.report

      // Extract unique asset names from report findings and scenarios
      const assetMap = new Map<string, { critical: number; high: number; medium: number; low: number; total: number }>()

      // Gather from scenarios
      if (report.scenarios && report.scenarios.length > 0) {
        for (const sc of report.scenarios) {
          const aName = sc.asset_name?.trim() || report.target || "Scanned Target Environment"
          if (!assetMap.has(aName)) {
            assetMap.set(aName, { critical: 0, high: 0, medium: 0, low: 0, total: 0 })
          }
        }
      }

      // Gather from findings
      for (const f of report.findings) {
        const aName = f.asset?.trim() || report.target || "Scanned Target Environment"
        if (!assetMap.has(aName)) {
          assetMap.set(aName, { critical: 0, high: 0, medium: 0, low: 0, total: 0 })
        }
        const counts = assetMap.get(aName)!
        const sev = (f.severity || "Low").toLowerCase()
        if (sev === "critical") counts.critical++
        else if (sev === "high") counts.high++
        else if (sev === "medium") counts.medium++
        else counts.low++
        counts.total++
      }

      if (assetMap.size === 0) {
        assetMap.set(report.target || "Scanned Target Environment", {
          critical: report.summary.critical,
          high: report.summary.high,
          medium: report.summary.medium,
          low: report.summary.low,
          total: report.summary.total_findings,
        })
      }

      // Build assets
      const assets: Asset[] = []
      const assetNameToId = new Map<string, string>()

      let assetIdx = 1
      for (const [aName, counts] of assetMap.entries()) {
        const assetId = `asset-scan-${assetIdx++}`
        assetNameToId.set(aName, assetId)

        const aNameLower = aName.toLowerCase()
        let assetType: AssetType = "Web Server"
        if (aNameLower.includes("db") || aNameLower.includes("database")) assetType = "Database"
        else if (aNameLower.includes("api") || aNameLower.includes("gateway")) assetType = "API Gateway"
        else if (aNameLower.includes("auth") || aNameLower.includes("idp") || aNameLower.includes("identity")) assetType = "Identity Server"
        else if (aNameLower.includes("backup")) assetType = "Backup System"
        else if (aNameLower.includes("app") || aNameLower.includes("prod")) assetType = "Application Server"
        else if (aNameLower.includes("vpn") || aNameLower.includes("router") || aNameLower.includes("network")) assetType = "Network Appliance"

        const criticality: Criticality = counts.critical > 0 ? "Critical" : counts.high > 0 ? "High" : "Medium"
        const exposure: Exposure = aNameLower.includes("internal") ? "Internal" : "Internet-facing"

        assets.push({
          id: assetId,
          name: aName,
          type: assetType,
          owner: "SecOps / Engineering",
          criticality,
          exposure,
          threatEvidence: counts.critical > 0 ? 0.9 : counts.high > 0 ? 0.75 : 0.5,
          openHighSeverityIncidents: counts.critical > 0 ? counts.critical : 0,
          openVulnerabilityCount: counts.total,
          controls: {
            mfa: counts.critical > 0 ? "Missing" : "Active",
            edr: counts.high > 0 ? "Partial" : "Active",
            patching: "Missing",
            segmentation: counts.critical > 0 ? "Missing" : "Partial",
            backup: "Active",
          },
        })
      }

      // Convert findings to itemized vulnerabilities
      const vulns: Vulnerability[] = report.findings.map((f, i) => {
        const aName = f.asset?.trim() || report.target || "Scanned Target Environment"
        const assetId = assetNameToId.get(aName) || assets[0].id

        const sev: Severity =
          f.severity === "Critical" || f.severity === "High" || f.severity === "Medium" || f.severity === "Low"
            ? f.severity
            : "Medium"
        const cvss =
          f.cvss_score ??
          (sev === "Critical" ? 9.2 : sev === "High" ? 7.5 : sev === "Medium" ? 5.4 : 2.5)

        return {
          id: `vuln-scan-${report.report_id}-${f.id || i}`,
          demoId: f.cve || f.id || `FIND-${i + 1}`,
          title: f.title,
          assetId,
          cvss,
          exploitStatus:
            sev === "Critical"
              ? "Exploited (simulated intel)"
              : sev === "High"
              ? "Public PoC"
              : "None known",
          patchAvailable: true,
          remediated: false,
          lastAssessed: report.report_date || action.at,
          remediation: f.recommendation || `Apply patch or configuration fix for ${f.title}`,
        }
      })

      const dataset: Dataset = {
        assets,
        vulnerabilities: vulns,
      }

      const calculatedAssessment = assess(dataset, action.at)

      // Use backend FAIR quantitative risk metrics if calculated, or fall back to baseline estimation
      const annualAle =
        report.calculated_metrics?.annual_loss_expectancy ??
        ((report.summary.critical * 250000) + (report.summary.high * 100000) + (report.summary.medium * 35000) + (report.summary.low * 10000))
      const mitigatedAle =
        report.calculated_metrics?.mitigated_annual_loss_expectancy ?? Math.round(annualAle * 0.28)
      const riskReduction =
        report.calculated_metrics?.annual_risk_reduction ?? (annualAle - mitigatedAle)

      calculatedAssessment.backendResult = {
        scenario_name: `${report.report_id} - ${assets[0]?.name || report.target} Quantitative Analysis`,
        asset_name: assets[0]?.name || report.target,
        asset_value: report.scenarios?.[0]?.asset_value ?? 5000000,
        metrics: {
          loss_event_frequency: report.calculated_metrics?.loss_event_frequency ?? (report.summary.critical > 0 ? 1.85 : 0.6),
          single_loss_expectancy: report.calculated_metrics?.single_loss_expectancy ?? 250000,
          annual_loss_expectancy: annualAle,
          mitigated_annual_loss_expectancy: mitigatedAle,
          annual_risk_reduction: riskReduction,
          security_roi_percentage: report.calculated_metrics?.security_roi_percentage ?? (riskReduction > 0 ? 275 : null),
        },
        assumptions: [
          `Scanned target: ${report.target} across ${assets.length} monitored asset${assets.length === 1 ? "" : "s"}.`,
          `Distribution: ${report.summary.critical} Critical, ${report.summary.high} High, ${report.summary.medium} Medium, ${report.summary.low} Low (${report.summary.total_findings} total findings).`,
          `Report ID: ${report.report_id} · Format: ${report.detected_format || "Security Report"}.`,
        ],
        recommendation:
          report.scenarios?.[0]?.recommendation ||
          `Remediate ${report.summary.critical} Critical and ${report.summary.high} High findings across ${assets.length} asset${assets.length === 1 ? "" : "s"} to mitigate estimated $${annualAle.toLocaleString()} annual exposure.`,
      }

      const event: ActivityEvent = {
        id: `evt-scan-${report.report_id}-${action.at}`,
        at: action.at,
        kind: "assessment",
        title: `Security Report Ingested: ${report.filename || report.report_id}`,
        description: `Ingested ${report.summary.total_findings} findings (${report.summary.critical} Critical, ${report.summary.high} High, ${report.summary.medium} Medium, ${report.summary.low} Low) across ${assets.length} asset${assets.length === 1 ? "" : "s"}. Format: ${report.detected_format || "Document"}. Dashboard updated.`,
        severity: report.summary.critical > 0 ? "Critical" : report.summary.high > 0 ? "High" : "Medium",
        overallChange: { before: state.assessment.overallScore, after: calculatedAssessment.overallScore },
      }

      const nextTrend = updateTrend(state.trendHistory, calculatedAssessment.overallScore)
      const reportTimestamp = report.report_date || action.at
      const filteredActivity = state.activity.filter((e) => !e.id.startsWith("evt-scan-"))
      const nextState: State = {
        ...state,
        dataset,
        activeReport: report,
        previousAssessment: state.assessment,
        assessment: calculatedAssessment,
        trendHistory: nextTrend,
        activity: [event, ...filteredActivity.slice(0, 49)],
        unread: state.unread + 1,
        isAssessing: false,
        assessmentError: null,
        isStale: false,
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
        lastReportAnalyzedAt: reportTimestamp,
        lastRiskAssessmentAt: action.at,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "restore-baseline": {
      const dataset = initialDataset
      const calculatedAssessment = assess(dataset, action.at)
      calculatedAssessment.backendResult = {
        scenario_name: "FinSecure Technologies - Customer Core Banking & PII Database Risk Evaluation",
        asset_name: "Customer Core Banking & PII Database",
        asset_value: 5000000,
        metrics: {
          loss_event_frequency: 0.7,
          single_loss_expectancy: 450000,
          annual_loss_expectancy: 315000,
          mitigated_annual_loss_expectancy: 90000,
          annual_risk_reduction: 225000,
          security_roi_percentage: 350,
        },
        assumptions: [
          "Threat Event Frequency (TEF): 2.00 attempts/year.",
          "Baseline Vulnerability Probability: 35.0%.",
          "Single Loss Expectancy (SLE): $450,000.00 per event ($150,000.00 direct + $300,000.00 indirect).",
          "Linear Loss Event Frequency (LEF = TEF * Vulnerability) assumed under standard FAIR principles.",
        ],
        recommendation: "RECOMMENDED: Deploy security controls. The proposed investment of $50,000.00 yields an estimated annual financial risk reduction of $225,000.00 (Net ROI: 350.0%).",
      }

      const event: ActivityEvent = {
        id: `evt-restore-${action.at}`,
        at: action.at,
        kind: "assessment",
        title: "Restored Baseline Enterprise Estate",
        description: `Restored standard 7 monitored assets and 137 open vulnerabilities baseline.`,
        severity: "Info",
        overallChange: { before: state.assessment.overallScore, after: calculatedAssessment.overallScore },
      }

      const nextTrend = updateTrend(state.trendHistory, calculatedAssessment.overallScore)
      const nextState: State = {
        ...state,
        dataset,
        activeReport: null,
        previousAssessment: state.assessment,
        assessment: calculatedAssessment,
        trendHistory: nextTrend,
        activity: [event, ...state.activity.slice(0, 49)],
        unread: state.unread + 1,
        isAssessing: false,
        assessmentError: null,
        isStale: false,
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
        lastReportAnalyzedAt: null,
        lastRiskAssessmentAt: action.at,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "toggle-auto-refresh": {
      const nextEnabled = !state.autoRefreshEnabled
      const nextState = {
        ...state,
        autoRefreshEnabled: nextEnabled,
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "decrement-timer": {
      if (!state.autoRefreshEnabled) return state
      return {
        ...state,
        nextAssessmentSeconds: Math.max(0, state.nextAssessmentSeconds - 1),
      }
    }

    case "reset-timer":
      return { ...state, nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC }

    case "mark-read":
      return { ...state, unread: 0 }

    case "reset": {
      if (typeof window !== "undefined") {
        Object.values(STORAGE_KEYS).forEach((k) => localStorage.removeItem(k))
      }
      const fresh = initState()
      return { ...fresh, view: state.view }
    }
  }
}

interface AppContextValue extends State {
  gaps: SecurityGap[]
  scenariosRemaining: number
  navigate: (view: ViewId, analystAssetId?: string) => void
  goBack: () => void
  canGoBack: boolean
  runAssessment: () => Promise<void>
  recordRiskAssessment: (backendResult: BackendRiskAssessmentResponse) => void
  importScannerReport: (report: BackendParsedReportResponse) => void
  restoreBaseline: () => void
  clearAssessmentError: () => void
  simulateThreat: () => void
  toggleAutoRefresh: () => void
  recordRemediation: (vulnerabilityId: string) => void
  markRead: () => void
  setCurrency: (currency: CurrencyCode) => void
  reset: () => void
}

const AppContext = createContext<AppContextValue | null>(null)

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, undefined, initState)
  const busyRef = useRef(false)
  const [isHydrated, setIsHydrated] = useState(false)

  // Hydrate client-persisted storage cleanly after SSR mount to prevent hydration mismatch
  useEffect(() => {
    try {
      const persisted = loadPersistedState()
      const urlView = getViewFromUrl()
      const initialView = urlView || "landing"

      dispatch({
        type: "hydrate-storage",
        payload: {
          ...persisted,
          view: initialView,
        },
      })
    } catch {
      const urlView = getViewFromUrl()
      if (urlView) {
        dispatch({
          type: "hydrate-storage",
          payload: { view: urlView },
        })
      }
    } finally {
      setIsHydrated(true)
    }
  }, [])

  // Keep browser URL synchronized with current state.view only after hydration
  useEffect(() => {
    if (!isHydrated || typeof window === "undefined") return
    const currentViewInUrl = getViewFromUrl()
    const targetUrl = state.view === "landing" ? "/" : `/?view=${state.view}`
    const currentPathAndSearch = window.location.pathname + (window.location.search || "")

    if (state.view === "landing") {
      if (window.location.search || window.location.hash) {
        window.history.pushState({ view: "landing" }, "", "/")
      }
    } else if (currentViewInUrl !== state.view || currentPathAndSearch !== targetUrl) {
      window.history.pushState({ view: state.view }, "", targetUrl)
    }
  }, [state.view, isHydrated])

  // Handle browser back and forward navigation
  useEffect(() => {
    if (typeof window === "undefined") return
    const handlePopState = () => {
      const v = getViewFromUrl() || "landing"
      dispatch({ type: "navigate", view: v })
    }
    window.addEventListener("popstate", handlePopState)
    return () => window.removeEventListener("popstate", handlePopState)
  }, [])

  const withAssessment = useCallback((complete: (at: string) => Action) => {
    if (busyRef.current) return
    busyRef.current = true
    dispatch({ type: "assess-start" })
    window.setTimeout(() => {
      dispatch(complete(new Date().toISOString()))
      busyRef.current = false
    }, ASSESSMENT_DELAY_MS)
  }, [])

  const navigate = useCallback((view: ViewId, analystAssetId?: string) => {
    dispatch({ type: "navigate", view, analystAssetId })
    window.scrollTo({ top: 0 })
  }, [])

  const goBack = useCallback(() => {
    dispatch({ type: "go-back" })
    window.scrollTo({ top: 0 })
  }, [])

  const canGoBack = true

  const runAssessment = useCallback(async () => {
    if (busyRef.current) return
    busyRef.current = true
    dispatch({ type: "assess-start" })

    try {
      // Find top asset from current dataset to evaluate against real FastAPI risk engine
      const topAsset = state.dataset.assets[0]
      const openVulns = state.dataset.vulnerabilities.filter((v) => v.assetId === topAsset?.id && !v.remediated)
      const vulnProb = openVulns.length > 0 ? Math.min(1.0, 0.2 + openVulns.length * 0.1) : 0.25

      const backendResult = await apiClient.assessRisk({
        scenario_name: `${topAsset?.name || "Critical Enterprise Infrastructure"} Quantitative Risk Assessment`,
        asset_name: topAsset?.name || "Payment Production Server",
        asset_value: 5000000,
        threat_event_frequency: topAsset ? (topAsset.threatEvidence || 1.0) * 3.0 : 2.0,
        vulnerability_probability: vulnProb,
        direct_loss: 150000,
        indirect_loss: 300000,
        proposed_security_cost: 50000,
        mitigated_vulnerability_probability: 0.1,
      })

      dispatch({
        type: "assess-complete",
        at: new Date().toISOString(),
        backendResult,
      })
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      dispatch({
        type: "assess-failed",
        error: msg,
      })
    } finally {
      busyRef.current = false
    }
  }, [state.dataset])

  const recordRiskAssessment = useCallback((backendResult: BackendRiskAssessmentResponse) => {
    dispatch({
      type: "assess-complete",
      at: new Date().toISOString(),
      backendResult,
    })
  }, [])

  const importScannerReport = useCallback((report: BackendParsedReportResponse) => {
    dispatch({
      type: "import-scanner-report",
      report,
      at: new Date().toISOString(),
    })
  }, [])

  const restoreBaseline = useCallback(() => {
    dispatch({
      type: "restore-baseline",
      at: new Date().toISOString(),
    })
  }, [])

  const clearAssessmentError = useCallback(() => {
    dispatch({ type: "clear-assessment-error" })
  }, [])

  const simulateThreat = useCallback(() => {
    withAssessment((at) => ({ type: "simulate-scenario", at }))
  }, [withAssessment])

  const toggleAutoRefresh = useCallback(() => {
    dispatch({ type: "toggle-auto-refresh" })
  }, [])

  const recordRemediation = useCallback(
    (vulnerabilityId: string) => dispatch({ type: "record-remediation", vulnerabilityId, at: new Date().toISOString() }),
    [],
  )

  const markRead = useCallback(() => dispatch({ type: "mark-read" }), [])
  const setCurrency = useCallback((currency: CurrencyCode) => dispatch({ type: "set-currency", currency }), [])
  const reset = useCallback(() => dispatch({ type: "reset" }), [])

  // Auto-refresh timer: 1-second countdown.
  // Note: automatic periodic timer only triggers telemetry/simulation updates (simulate-tick),
  // NEVER an explicit risk assessment run.
  useEffect(() => {
    if (!state.autoRefreshEnabled) return

    let isDocumentVisible = !document.hidden
    const handleVisibilityChange = () => {
      isDocumentVisible = !document.hidden
    }
    document.addEventListener("visibilitychange", handleVisibilityChange)

    const interval = setInterval(() => {
      if (!isDocumentVisible) return

      if (state.nextAssessmentSeconds <= 1) {
        dispatch({ type: "simulate-tick", at: new Date().toISOString() })
      } else {
        dispatch({ type: "decrement-timer" })
      }
    }, 1000)

    return () => {
      clearInterval(interval)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
    }
  }, [state.autoRefreshEnabled, state.nextAssessmentSeconds])

  const gaps = useMemo(() => deriveSecurityGaps(state.dataset, securityGapDefinitions), [state.dataset])

  const value = useMemo<AppContextValue>(
    () => ({
      ...state,
      gaps,
      scenariosRemaining: threatScenarios.length - (state.scenarioIndex % threatScenarios.length),
      navigate,
      goBack,
      canGoBack,
      runAssessment,
      recordRiskAssessment,
      importScannerReport,
      restoreBaseline,
      clearAssessmentError,
      simulateThreat,
      toggleAutoRefresh,
      recordRemediation,
      markRead,
      setCurrency,
      reset,
    }),
    [
      state,
      gaps,
      navigate,
      goBack,
      canGoBack,
      runAssessment,
      recordRiskAssessment,
      importScannerReport,
      restoreBaseline,
      clearAssessmentError,
      simulateThreat,
      toggleAutoRefresh,
      recordRemediation,
      markRead,
      setCurrency,
      reset,
    ],
  )

  return <AppContext value={value}>{children}</AppContext>
}

export function useAppState() {
  const ctx = use(AppContext)
  if (!ctx) throw new Error("useAppState must be used within AppStateProvider")
  return ctx
}
