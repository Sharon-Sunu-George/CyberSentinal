/**
 * API client for CyberQuant FastAPI backend.
 */
const BASE_URL = process.env.NEXT_PUBLIC_API_URL
  ? `${process.env.NEXT_PUBLIC_API_URL}/api/v1`
  : "http://127.0.0.1:8010/api/v1"

/**
 * Assess a single cyber risk scenario via the backend.
 Pass the same fields as RiskAssessmentRequest.
*/
export async function assessRisk(data: {
  scenario_name: string
  asset_name: string
  asset_value: number
  threat_event_frequency: number
  vulnerability_probability: number
  direct_loss: number
  indirect_loss: number
  proposed_security_cost?: number
  mitigated_vulnerability_probability?: number
}) {
  const res = await fetch(`${BASE_URL}/risk/assess`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(`Backend assess risk failed: ${res.status} ${txt}`)
  }
  return res.json()
}

/**
 * Assess website risk via the backend (uses assumed FAIR parameters).
*/
export async function websiteRisk(data: {
  url: string
  industry?: string
  asset_value?: number
}) {
  const res = await fetch(`${BASE_URL}/risk/website-risk`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(`Backend website risk failed: ${res.status} ${txt}`)
  }
  return res.json()
}

/**
 * Compare multiple scenarios via the backend.
*/
export async function compareScenarios(data: {
  scenarios: any[]
}) {
  const res = await fetch(`${BASE_URL}/risk/compare`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  })
  if (!res.ok) {
    const txt = await res.text()
    throw new Error(`Backend compare scenarios failed: ${res.status} ${txt}`)
  }
  return res.json()
}

/**
 * Quick health check.
*/
export async function healthCheck() {
  const res = await fetch(`${BASE_URL}/risk/health`)
  if (!res.ok) throw new Error(`Backend health check failed: ${res.status}`)
  return res.json()
}