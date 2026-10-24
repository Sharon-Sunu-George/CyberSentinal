"use client"

import { ShieldCheck } from "lucide-react"
import { cn } from "@/lib/utils"
import { useAppState } from "./app-state"
import { NAV_ITEMS } from "./nav-config"

export function Logo({ onClick }: { onClick?: () => void }) {
  const { navigate } = useAppState()
  return (
    <div
      onClick={() => {
        if (onClick) onClick()
        else navigate("landing")
      }}
      className="flex items-center gap-2.5 cursor-pointer select-none transition-opacity hover:opacity-85"
      role="button"
      tabIndex={0}
      title="CyberSentinel AI — Return to Home / Welcome Screen"
    >
      <span className="flex size-8 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-inset ring-primary/30">
        <ShieldCheck className="size-4.5" aria-hidden="true" />
      </span>
      <span className="flex flex-col leading-tight">
        <span className="text-sm font-semibold text-foreground">CyberSentinel AI</span>
        <span className="text-[11px] text-muted-foreground">Risk & Investment Intelligence</span>
      </span>
    </div>
  )
}

export function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const { view, navigate, gaps, unread } = useAppState()
  return (
    <nav aria-label="Primary" className="flex flex-col gap-0.5">
      {NAV_ITEMS.map((item) => {
        const active = item.id === view
        const Icon = item.icon
        const count = item.id === "gaps" ? gaps.length : item.id === "activity" && unread > 0 ? unread : null
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => {
              navigate(item.id)
              onNavigate?.()
            }}
            aria-current={active ? "page" : undefined}
            className={cn(
              "group flex h-9 w-full items-center gap-2.5 rounded-md px-2.5 text-left text-sm transition-colors focus-visible:outline-2 focus-visible:outline-ring",
              active
                ? "bg-sidebar-accent text-foreground"
                : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
            )}
          >
            <Icon className={cn("size-4 shrink-0", active ? "text-primary" : "")} aria-hidden="true" />
            <span className="flex-1 truncate">{item.label}</span>
            {count !== null ? (
              <span className="rounded bg-muted px-1.5 font-mono text-[10px] tabular-nums text-muted-foreground">
                {count}
              </span>
            ) : null}
          </button>
        )
      })}
    </nav>
  )
}

export function Sidebar() {
  return (
    <aside className="sticky top-0 hidden h-svh w-64 shrink-0 flex-col border-r bg-sidebar lg:flex">
      <div className="flex h-14 items-center border-b px-4">
        <Logo />
      </div>
      <div className="flex-1 overflow-y-auto p-3">
        <SidebarNav />
      </div>
      <div className="border-t p-3">
        <div className="rounded-md border border-dashed border-warning/40 bg-warning/5 p-3">
          <p className="text-xs font-medium text-warning">Simulated environment</p>
          <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
            All assets, findings and events are demonstration data. No real security systems are connected.
          </p>
        </div>
      </div>
    </aside>
  )
}
