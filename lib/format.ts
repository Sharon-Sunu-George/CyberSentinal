import type { CurrencyCode } from "./types"

export interface CurrencyConfig {
  code: CurrencyCode
  symbol: string
  name: string
  rateFromUSD: number
  locale: string
  description: string
}

export const CURRENCY_CONFIGS: Record<CurrencyCode, CurrencyConfig> = {
  USD: {
    code: "USD",
    symbol: "$",
    name: "US Dollar",
    rateFromUSD: 1.0,
    locale: "en-US",
    description: "Standard base currency (FAIR model native)",
  },
  INR: {
    code: "INR",
    symbol: "₹",
    name: "Indian Rupee",
    rateFromUSD: 83.5,
    locale: "en-IN",
    description: "RBI reference rate (1 USD = ₹83.50)",
  },
  EUR: {
    code: "EUR",
    symbol: "€",
    name: "Euro",
    rateFromUSD: 0.92,
    locale: "de-DE",
    description: "ECB reference rate (1 USD = €0.92)",
  },
  GBP: {
    code: "GBP",
    symbol: "£",
    name: "British Pound",
    rateFromUSD: 0.79,
    locale: "en-GB",
    description: "Bank of England benchmark (1 USD = £0.79)",
  },
}

export const RATES_LAST_UPDATED = "ECB & RBI Baseline Reference Benchmark (Configured Oct 2026)"

const formatters: Partial<Record<CurrencyCode, Intl.NumberFormat>> = {}

function getFormatter(currency: CurrencyCode): Intl.NumberFormat {
  if (!formatters[currency]) {
    const cfg = CURRENCY_CONFIGS[currency] || CURRENCY_CONFIGS.USD
    formatters[currency] = new Intl.NumberFormat(cfg.locale, {
      style: "currency",
      currency: cfg.code,
      maximumFractionDigits: 0,
    })
  }
  return formatters[currency]!
}

const dateTime = new Intl.DateTimeFormat("en-IN", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "Asia/Kolkata",
})

export function formatCurrency(valueInUSD: number, currency: CurrencyCode = "USD"): string {
  const cfg = CURRENCY_CONFIGS[currency] || CURRENCY_CONFIGS.USD
  const converted = valueInUSD * cfg.rateFromUSD
  return getFormatter(cfg.code).format(converted)
}

export function formatINR(valueInUSD: number): string {
  return formatCurrency(valueInUSD, "INR")
}

export function formatDateTime(iso: string): string {
  if (!iso) return "—"
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return iso
    return `${dateTime.format(d)} IST`
  } catch {
    return iso
  }
}

export function formatPoints(value: number): string {
  return value.toFixed(1)
}
