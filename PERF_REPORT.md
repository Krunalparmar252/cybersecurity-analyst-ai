# Performance & Reliability Report — Autonomous Cybersecurity Analyst AI

## Phase 0 — Baseline Measurements (Before Optimization)

### 1. Production Bundle Sizes & First Load JS (Next.js 14 Build)

| Route (app) | Page Size | First Load JS | Shared Chunks |
| :--- | :--- | :--- | :--- |
| `/` (Landing) | 11.4 kB | **182 kB** | 87.3 kB |
| `/dashboard` (Security Dashboard) | 3.8 kB | **188 kB** | 87.3 kB |
| `/findings` (Vulnerability Workbench) | 3.21 kB | **104 kB** | 87.3 kB |
| `/findings/[id]` (Finding Detail & Diff) | 3.4 kB | **188 kB** | 87.3 kB |
| `/scan/new` (Ingestion Configuration) | 5.42 kB | **107 kB** | 87.3 kB |
| `/scan/[id]` (Live Orchestrator Cockpit) | 5.08 kB | **189 kB** | 87.3 kB |
| `/traffic` (Network & Log Analyzer) | 3.99 kB | **181 kB** | 87.3 kB |
| `/reports` (Cryptographic Audit Vault) | 3.42 kB | **105 kB** | 87.3 kB |
| `/architecture` (Interactive Module Graph) | 2.43 kB | **111 kB** | 87.3 kB |
| `/settings` (Preferences & API Keys) | 4.37 kB | **91.6 kB** | 87.3 kB |

*Note: Initial baseline dashboard and cockpit routes load ~188 kB JS due to root layout wrapping all routes in Lenis smooth scroll, CustomCursor event listeners, full-screen clip-path transitions, and global GSAP plugin registrations.*

---

### 2. Lighthouse Performance Baseline Audits (Headless Chrome)

| Route | Performance Score | First Contentful Paint (FCP) | Largest Contentful Paint (LCP) | Total Blocking Time (TBT) | Cumulative Layout Shift (CLS) | Speed Index |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`/`** (Landing) | **77 / 100** | 2.8 s | 2.8 s | 460 ms | 0.000 | 4.5 s |
| **`/dashboard`** | **67 / 100** | 2.4 s | 3.6 s | 810 ms | 0.047 | 2.5 s |
| **`/findings`** | **65 / 100** | 2.7 s | 2.7 s | 450 ms | 0.302 | 2.7 s |
| **`/scan/new`** | **90 / 100** | 2.2 s | 2.2 s | 220 ms | 0.000 | 4.3 s |

---
*Target after Phase 1:*
- Dashboard First Load JS reduced below 188 kB
- Dashboard Lighthouse score improved to 90+
- CLS on `/findings` reduced to < 0.1
- Landing page visually identical while offloading 3D rendering when out of viewport
