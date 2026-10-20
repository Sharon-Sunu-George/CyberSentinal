"use client"

import {
  createContext,
  use,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
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
import type { ActivityEvent, Assessment, Dataset, SecurityGap, ViewId } from "@/lib/types"
import { apiClient, type BackendRiskAssessmentResponse } from "@/lib/api-client"

const DEFAULT_AUTO_REFRESH_INTERVAL_SEC = 60
const ASSESSMENT_DELAY_MS = 500

const STORAGE_KEYS = {
  DATASET: "cybersentinel_dataset_v1",
  ASSESSMENT: "cybersentinel_assessment_v1",
  ACTIVITY: "cybersentinel_activity_v1",
  TREND: "cybersentinel_trend_v1",
  AUTO_REFRESH: "cybersentinel_autorefresh_v1",
  SCENARIO_INDEX: "cybersentinel_scenario_index_v1",
}

interface TrendPoint {
  day: string
  score: number
}

interface State {
  view: ViewId
  dataset: Dataset
  assessment: Assessment
  previousAssessment: Assessment | null
  activity: ActivityEvent[]
  trendHistory: TrendPoint[]
  scenarioIndex: number
  isAssessing: boolean
  isStale: boolean
  unread: number
  analystAssetId: string | null
  selectedScanId: string | null
  lastSimulation: ActivityEvent | null
  autoRefreshEnabled: boolean
  nextAssessmentSeconds: number
}

type Action =
  | { type: "navigate"; view: ViewId; analystAssetId?: string; scanId?: string }
  | { type: "assess-start" }
  | { type: "assess-complete"; at: string; backendResult?: BackendRiskAssessmentResponse }
  | { type: "simulate-tick"; at: string }
  | { type: "simulate-scenario"; at: string }
  | { type: "record-remediation"; vulnerabilityId: string; at: string }
  | { type: "toggle-auto-refresh" }
  | { type: "decrement-timer" }
  | { type: "reset-timer" }
  | { type: "mark-read" }
  | { type: "reset" }

function loadPersistedState(): Partial<State> {
  if (typeof window === "undefined") return {}
  try {
    const savedDataset = localStorage.getItem(STORAGE_KEYS.DATASET)
    const savedAssessment = localStorage.getItem(STORAGE_KEYS.ASSESSMENT)
    const savedActivity = localStorage.getItem(STORAGE_KEYS.ACTIVITY)
    const savedTrend = localStorage.getItem(STORAGE_KEYS.TREND)
    const savedAutoRefresh = localStorage.getItem(STORAGE_KEYS.AUTO_REFRESH)
    const savedScenarioIdx = localStorage.getItem(STORAGE_KEYS.SCENARIO_INDEX)

    return {
      dataset: savedDataset ? JSON.parse(savedDataset) : undefined,
      assessment: savedAssessment ? JSON.parse(savedAssessment) : undefined,
      activity: savedActivity ? JSON.parse(savedActivity) : undefined,
      trendHistory: savedTrend ? JSON.parse(savedTrend) : undefined,
      autoRefreshEnabled: savedAutoRefresh !== null ? JSON.parse(savedAutoRefresh) : undefined,
      scenarioIndex: savedScenarioIdx !== null ? Number(savedScenarioIdx) : undefined,
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
  } catch {
    // LocalStorage write ignored
  }
}

function initState(): State {
  const persisted = loadPersistedState()
  const dataset = persisted.dataset || initialDataset
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
    dataset,
    assessment: persisted.assessment || baseAssessment,
    previousAssessment: null,
    activity: persisted.activity || initialActivity,
    trendHistory: persisted.trendHistory || initialRiskTrendHistory,
    scenarioIndex: persisted.scenarioIndex ?? 0,
    isAssessing: false,
    isStale: false,
    unread: 2,
    analystAssetId: null,
    selectedScanId: null,
    lastSimulation: null,
    autoRefreshEnabled: persisted.autoRefreshEnabled ?? true,
    nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
  }
}

function updateTrend(history: TrendPoint[], latestScore: number): TrendPoint[] {
  // If the last point is "Today", update its score; otherwise keep a 7-point rolling window
  const last = history[history.length - 1]
  if (last && last.day === "Today") {
    return [...history.slice(0, -1), { day: "Today", score: latestScore }]
  }
  const slice = history.length >= 7 ? history.slice(1) : history
  return [...slice, { day: "Today", score: latestScore }]
}

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "navigate":
      return {
        ...state,
        view: action.view,
        analystAssetId: action.analystAssetId !== undefined ? action.analystAssetId : state.analystAssetId,
        selectedScanId: action.scanId !== undefined ? action.scanId : state.selectedScanId,
      }

    case "assess-start":
      return { ...state, isAssessing: true }

    case "assess-complete": {
      const next = assess(state.dataset, action.at)
      if (action.backendResult) {
        next.backendResult = action.backendResult
      }
      const delta = next.overallScore - state.assessment.overallScore
      const event: ActivityEvent = {
        id: `evt-assess-${action.at}`,
        at: action.at,
        kind: "assessment",
        title: action.backendResult
          ? `FAIR risk assessment quantified: ${action.backendResult.asset_name}`
          : "Periodic risk assessment completed",
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
        isStale: false,
        activity: [event, ...state.activity.slice(0, 49)],
        nextAssessmentSeconds: DEFAULT_AUTO_REFRESH_INTERVAL_SEC,
      }
      saveStateToStorage(nextState)
      return nextState
    }

    case "simulate-tick": {
      // Periodic automatic simulation step: cycle through realistic threat & remediation scenarios
      const idx = state.scenarioIndex % threatScenarios.length
      const scenario = threatScenarios[idx]
      const outcome = runScenario(state.dataset, scenario, action.at)
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
      // Re-evaluate immediately after remediation
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
  navigate: (view: ViewId, analystAssetId?: string, scanId?: string) => void
  runAssessment: () => void
  recordRiskAssessment: (backendResult: BackendRiskAssessmentResponse) => void
  simulateThreat: () => void
  toggleAutoRefresh: () => void
  recordRemediation: (vulnerabilityId: string) => void
  markRead: () => void
  reset: () => void
}

const AppContext = createContext<AppContextValue | null>(null)

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, undefined, initState)
  const busyRef = useRef(false)

  const withAssessment = useCallback((complete: (at: string) => Action) => {
    if (busyRef.current) return
    busyRef.current = true
    dispatch({ type: "assess-start" })
    window.setTimeout(() => {
      dispatch(complete(new Date().toISOString()))
      busyRef.current = false
    }, ASSESSMENT_DELAY_MS)
  }, [])

  const navigate = useCallback((view: ViewId, analystAssetId?: string, scanId?: string) => {
    dispatch({ type: "navigate", view, analystAssetId, scanId })
    window.scrollTo({ top: 0 })
  }, [])

  const runAssessment = useCallback(async () => {
    if (busyRef.current) return
    busyRef.current = true
    dispatch({ type: "assess-start" })

    // Find top asset from current dataset to evaluate against real FastAPI risk engine
    const topAsset = state.dataset.assets[0]
    const openVulns = state.dataset.vulnerabilities.filter((v) => v.assetId === topAsset?.id && !v.remediated)
    const vulnProb = openVulns.length > 0 ? Math.min(1.0, 0.2 + openVulns.length * 0.1) : 0.25

    let backendResult: BackendRiskAssessmentResponse | undefined = undefined
    try {
      backendResult = await apiClient.assessRisk({
        scenario_name: `${topAsset?.name || "Critical Enterprise Infrastructure"} Quantitative Risk Assessment`,
        asset_name: topAsset?.name || "Payment Production Server",
        asset_value: 5000000,
        threat_event_frequency: topAsset ? topAsset.threatEvidence * 3.0 : 2.0,
        vulnerability_probability: vulnProb,
        direct_loss: 150000,
        indirect_loss: 300000,
        proposed_security_cost: 50000,
        mitigated_vulnerability_probability: 0.1,
      })
    } catch {
      // Backend error will not crash assessment; continue with local dataset
    }

    dispatch({
      type: "assess-complete",
      at: new Date().toISOString(),
      backendResult,
    })
    busyRef.current = false
  }, [state.dataset])

  const recordRiskAssessment = useCallback((backendResult: BackendRiskAssessmentResponse) => {
    dispatch({
      type: "assess-complete",
      at: new Date().toISOString(),
      backendResult,
    })
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
  const reset = useCallback(() => dispatch({ type: "reset" }), [])

  // Auto-refresh timer: 1-second countdown, triggers simulation tick when reaching 0
  useEffect(() => {
    if (!state.autoRefreshEnabled) return

    let isDocumentVisible = !document.hidden
    const handleVisibilityChange = () => {
      isDocumentVisible = !document.hidden
    }
    document.addEventListener("visibilitychange", handleVisibilityChange)

    const interval = setInterval(() => {
      if (!isDocumentVisible || busyRef.current) return

      if (state.nextAssessmentSeconds <= 1) {
        withAssessment((at) => ({ type: "simulate-tick", at }))
      } else {
        dispatch({ type: "decrement-timer" })
      }
    }, 1000)

    return () => {
      clearInterval(interval)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
    }
  }, [state.autoRefreshEnabled, state.nextAssessmentSeconds, withAssessment])

  const gaps = useMemo(() => deriveSecurityGaps(state.dataset, securityGapDefinitions), [state.dataset])

  const value = useMemo<AppContextValue>(
    () => ({
      ...state,
      gaps,
      scenariosRemaining: threatScenarios.length - (state.scenarioIndex % threatScenarios.length),
      navigate,
      runAssessment,
      recordRiskAssessment,
      simulateThreat,
      toggleAutoRefresh,
      recordRemediation,
      markRead,
      reset,
    }),
    [state, gaps, navigate, runAssessment, recordRiskAssessment, simulateThreat, toggleAutoRefresh, recordRemediation, markRead, reset],
  )

  return <AppContext value={value}>{children}</AppContext>
}

export function useAppState() {
  const ctx = use(AppContext)
  if (!ctx) throw new Error("useAppState must be used within AppStateProvider")
  return ctx
}
