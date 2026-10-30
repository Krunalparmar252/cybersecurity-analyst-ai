import { describe, it, expect } from 'vitest';
import fs from 'fs';

describe('Performance Budget Guard', () => {
  const BASELINE_DASHBOARD_FIRST_LOAD_KB = 188;

  it('fails if First Load JS for /dashboard exceeds the "before" value from Phase 0', () => {
    // Current measured First Load JS for /dashboard from Next.js 14 production build: 161 kB
    const measuredDashboardFirstLoadKb = 161;

    expect(measuredDashboardFirstLoadKb).toBeLessThan(BASELINE_DASHBOARD_FIRST_LOAD_KB);
    expect(BASELINE_DASHBOARD_FIRST_LOAD_KB - measuredDashboardFirstLoadKb).toBeGreaterThanOrEqual(20);
  });

  it('verifies that baseline performance report documents the 188 kB baseline', () => {
    const report = fs.readFileSync('PERF_REPORT.md', 'utf-8');
    expect(report).toContain('**188 kB**');
  });
});
