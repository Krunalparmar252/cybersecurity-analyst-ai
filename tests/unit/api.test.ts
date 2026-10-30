import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { api } from '@/lib/api';

describe('SecurityApiClient', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('loads dashboard stats with valid active repo and posture score', async () => {
    const stats = await api.getDashboardStats();
    expect(stats).toBeDefined();
    expect(stats.postureScore).toBeGreaterThanOrEqual(15);
    expect(stats.postureScore).toBeLessThanOrEqual(100);
    expect(['SECURE', 'GUARDED', 'ELEVATED']).toContain(stats.riskLevel);
  });

  it('falls back gracefully to offline state when backend fetch times out or fails', async () => {
    // Mock fetch throwing AbortError (timeout)
    global.fetch = vi.fn().mockImplementation(() => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      return Promise.reject(err);
    });

    // getScans should return local/mock scans despite backend failure
    const scans = await api.getScans();
    expect(scans).toBeDefined();
    expect(Array.isArray(scans)).toBe(true);
    expect(scans.length).toBeGreaterThan(0);
  });

  it('falls back gracefully when startScan backend fetch rejects', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

    const scan = await api.startScan({
      targetRepo: 'https://github.com/example/test-repo',
      branch: 'main',
      rules: ['RULE-PY-SQLI-AST'],
      enableDynamicExploit: true,
      offlineMode: true,
    });

    expect(scan).toBeDefined();
    expect(scan.id).toMatch(/^SCN-2026/);
    expect(scan.targetRepo).toBe('https://github.com/example/test-repo');
    expect(scan.status).toBe('completed');
  });

  it('filters findings by severity and ruleId accurately', async () => {
    const allFindings = await api.getFindings();
    expect(allFindings.length).toBeGreaterThan(0);

    const criticals = await api.getFindings({ severity: 'critical' });
    expect(criticals.every((f) => f.severity === 'critical')).toBe(true);

    const sqli = await api.getFindings({ ruleId: 'RULE-PY-SQLI-AST' });
    expect(sqli.every((f) => f.ruleId === 'RULE-PY-SQLI-AST')).toBe(true);
  });
});
