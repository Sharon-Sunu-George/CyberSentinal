# CyberSentinal

## Product purpose

CyberSentinal is currently implemented as a cyber-risk management and risk-quantification **demonstration**. Its frontend helps an executive or analyst explore a simulated organisation's assets, vulnerabilities, control weaknesses, risk scores, and hypothetical security investments. It also demonstrates a separate Python API for estimating the financial impact of cyber-risk scenarios.

This purpose describes the product evidenced by the code; it is not confirmation of an independently approved business roadmap. Preserve the existing purpose and behaviour unless the user explicitly changes the goal. Do not invent customers, requirements, data sources, integrations, service-level commitments, or production capabilities.

## Product and implementation boundaries

- **The frontend is a simulation, not a live security monitoring product.** Its sample assets, findings, threat signals, incidents, activity events, controls, and recommended actions are explicitly simulated. Vulnerability identifiers use fictional `DEMO-2026-…` IDs, not real CVEs.
- **There is no generative AI in the analyst view.** Despite the “AI Risk Analyst” navigation label, `lib/analyst.ts` describes and implements deterministic, rule-based analysis of the selected asset. Do not present this view as an LLM, chatbot, or external threat-intelligence integration.
- **The browser frontend and Python backend are separate today.** Frontend state and calculations use local TypeScript data and functions. The frontend contains no calls to the backend API; do not claim that its dashboard, analyst, or optimizer is powered by FastAPI.
- **The backend is a separate risk API, not a database or connected asset-ingestion pipeline.** It provides request-driven financial risk calculations and scenario comparisons. No persistence, authentication, live asset discovery, vendor integration, or production deployment configuration is evidenced in this repository.
- **There are two distinct risk and investment models.** The frontend scores and ranks simulated assets and exhaustively evaluates its illustrative investment options. The backend calculates financial expected-loss metrics and its standalone capital-allocation helper uses a greedy cost-effectiveness approach. Do not silently merge these models or describe them as one implementation.
- **Currency displays are inconsistent across existing frontend surfaces.** The investment page labels its budget USD and uses the USD formatter, while overview recommendations use the INR formatter for the same default budget. The backend financial-risk inputs are described in USD. Do not assume or silently change a currency convention; resolve it explicitly when a task requires a consistent currency.
- **Treat figures and recommendations as illustrative, not validated security advice, financial forecasts, measured benchmarks, or guaranteed outcomes.** Preserve the models' stated weights, assumptions, deterministic behaviour, and demo-data caveats when changing calculations or copy.
- Settings expose simulation controls and reset behavior; they do not currently provide editable risk-model parameters or live data-source configuration.

## Current frontend behaviour

1. `app/page.tsx` renders the shared sidebar, top bar, and selected dashboard view inside `AppStateProvider`.
2. `components/app/app-state.tsx` initializes the in-memory application state from `lib/mock-data.ts`, calculates the initial asset assessment, derives security gaps, and exposes navigation and actions through React context. State is not persisted by this provider.
3. `lib/risk.ts` applies documented weights for criticality, exposure, vulnerability severity, threat evidence, incidents, and control weakness to produce asset scores, risk factors, categories, rankings, next actions, and the organisation-wide score.
4. The views read that shared state to present:
   - **Executive Overview:** score summaries, trends and distribution, ranked assets, recommendations, and recent simulated activity.
   - **Asset & Vulnerability Explorer:** searchable/filterable asset and finding details, with risk-score evidence.
   - **AI Risk Analyst:** rule-based, evidence-backed investigation and proposed actions for a selected asset.
   - **Investment Optimizer:** budget-constrained evaluation of the frontend's illustrative investment options.
   - **Security Gaps:** prioritised control weaknesses, affected assets, evidence, consequences, and remediation.
   - **Activity Log:** the simulated event and assessment history.
   - **Settings:** run the next predefined threat simulation or reset the in-memory demo state.
5. Running an assessment recalculates scores from the current in-memory dataset and records an activity event. A threat simulation applies the next predefined scenario in order, recalculates scores, and records changes. Recording remediation marks a finding remediated and makes the assessment stale; it does not automatically run another assessment. Reset restores the initial sample data and activity state.
6. `lib/optimizer.ts` evaluates combinations of frontend investment options against the same simulated dataset, respecting the supplied budget and accounting for overlapping effects. This is independent of the backend allocator.

## Backend behaviour

- `backend/app/main.py` creates the FastAPI application and mounts the versioned router at `/api/v1`.
- `backend/app/api/v1/api.py` mounts the risk router at `/api/v1/risk`.
- The implemented HTTP routes are `GET /api/v1/risk/health`, `POST /api/v1/risk/assess`, and `POST /api/v1/risk/compare`.
- `/assess` and `/compare` validate Pydantic request models and call `RiskEngineService` in `backend/app/services/risk_engine.py`. The calculations use loss event frequency (TEF × vulnerability probability), single loss expectancy (direct + indirect loss), annual loss expectancy (LEF × SLE), and optional mitigated loss and ROI. Input examples, field descriptions, and monetary amounts in these backend schemas are USD.
- `backend/app/services/scenario_engine.py` and `backend/app/services/capital_allocator.py` are standalone helper modules. Their presence does not mean they are exposed by the current HTTP router or integrated with the frontend. Keep their behaviour distinct from the frontend simulator and optimizer.
- `backend/tests/` contains Python tests for the scenario comparison and capital-allocation helpers.
- The FastAPI app enables permissive CORS in its current source. Do not treat that development-oriented configuration as a production security recommendation.

## Source layout

```text
app/
  page.tsx                       Frontend entry; mounts the provider and dashboard shell
  layout.tsx                     Root layout, metadata, fonts, and global stylesheet
  globals.css                    Tailwind, theme tokens, and global styles
  favicon.ico                    App icon

components/
  app/                           Shared dashboard shell, navigation, context consumers, and reusable app panels
    app-state.tsx                Frontend state, reducer, simulated actions, and context
    nav-config.ts                Navigation labels and descriptions
    sidebar.tsx, topbar.tsx      Dashboard navigation and header
    asset-detail.tsx             Selected asset risk evidence
    asset-risk-table.tsx         Ranked asset display
    activity-list.tsx            Simulated event display
    badges.tsx, filter-chips.tsx, panel.tsx
  views/                         One component per dashboard view
    overview-view.tsx            Executive overview composition
    explorer-view.tsx            Asset and vulnerability exploration
    analyst-view.tsx             Deterministic asset investigation
    investments-view.tsx         Frontend investment optimizer UI
    gaps-view.tsx                Security control gaps
    activity-view.tsx            Activity history
    settings-view.tsx            Demo simulation and reset controls
    overview/                    Overview charts, summary cards, and recommendations
    explorer/                    Vulnerability-specific explorer UI
  ui/                            Reusable primitive UI components

lib/
  types.ts                       Shared frontend domain and view types
  mock-data.ts                   Explicitly simulated assets, findings, gaps, and activity
  risk.ts                        Frontend scoring, ranking, recommendations, and gap derivation
  simulation.ts                  Ordered, deterministic frontend threat scenarios
  analyst.ts                     Rule-based analyst investigation
  investments.ts                 Frontend investment options and their simulated effects
  optimizer.ts                   Frontend budget-combination search and plan evaluation
  format.ts                      INR/USD currency and date/score formatters
  utils.ts                       Shared UI utilities

backend/
  requirements.txt               Python runtime dependencies
  app/
    main.py                      FastAPI application entry point
    api/v1/api.py                Versioned router assembly
    api/v1/endpoints/risk.py     Health, assessment, and comparison HTTP routes
    schemas/risk.py              HTTP risk request/response models
    schemas/allocation.py        Risk, mitigation, and allocation models
    services/risk_engine.py      Financial risk and ROI calculations used by HTTP routes
    services/scenario_engine.py  Standalone mitigation-scenario comparison helpers
    services/capital_allocator.py Standalone greedy budget-allocation helper
  tests/
    test_scenarios.py            Scenario comparison tests
    test_capital_allocator.py    Capital allocation tests

public/                          Static public assets
PRD.md                           Code-backed product purpose, behaviour, constraints, and layout
README.md                        Project setup notes (currently generic create-next-app guidance)
package.json                     Frontend scripts and dependencies
pnpm-lock.yaml                   pnpm lockfile
package-lock.json                npm lockfile
tsconfig.json, next.config.ts    TypeScript and Next.js configuration
eslint.config.mjs                Frontend lint configuration
components.json                  UI component generator configuration
```

Generated or dependency directories such as `node_modules/`, `.next/`, and Python `__pycache__/` are not application source; do not use their contents as product requirements or edit generated files to implement a feature.

## Technology and local development

- Frontend: Next.js App Router, React, TypeScript, Tailwind CSS, and reusable shadcn-style UI components. The `@/*` TypeScript alias resolves from the repository root.
- Package scripts in `package.json`: `pnpm dev` starts the frontend development server, `pnpm build` builds it, `pnpm start` starts the production server, and `pnpm lint` runs ESLint. `npm run <script>` is also available when installing from `package-lock.json`.
- Backend: Python FastAPI with Uvicorn; install `backend/requirements.txt` in the chosen Python environment and run the app from `backend/` with `uvicorn app.main:app --reload`. The interactive API docs are at `/docs`, and the API health route is `/api/v1/risk/health`.
- No root-level script orchestrates the backend and frontend together. Running one does not implicitly start the other.

## Guidance for future changes

1. Start from the observed purpose and current source of truth above; inspect the relevant implementation before changing it.
2. Do not turn simulated data into claims about real systems, real CVEs, live monitoring, actual threat intelligence, validated ROI, or production readiness.
3. Do not describe the analyst as generative AI or make up integrations. Ask for clarification if a task depends on an unprovided product requirement or data-source contract.
4. Keep frontend and backend behaviour separate unless the user explicitly requests integration. For integration work, define and validate the API/data contract rather than assuming the two models are interchangeable.
5. Preserve existing user-visible flows and deterministic demo behaviour unless a requested change intentionally alters them. Add or update the smallest relevant tests when changing calculation or state-transition logic.
6. Do not modify generated files, lockfiles, or unrelated features without a task-specific reason.
