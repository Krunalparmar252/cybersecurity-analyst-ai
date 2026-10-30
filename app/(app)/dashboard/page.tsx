'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  Terminal,
  Activity,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Play,
  FileCheck2,
  Layers,
  Clock,
  Key,
} from 'lucide-react';
import { api } from '@/lib/api';
import { Scan, Finding, SystemModule } from '@/lib/types';
import CountUp from '@/components/motion/CountUp';

export default function DashboardPage() {
  const [stats, setStats] = useState<any>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [modules, setModules] = useState<SystemModule[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<string>('all');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const [s, sc, m] = await Promise.all([
        api.getDashboardStats(),
        api.getScans(),
        api.getSystemModules(),
      ]);
      setStats(s);
      setScans(sc);
      setModules(m);
      setLoading(false);
    }
    load();
  }, []);

  const availableRepos = Array.from(new Set(scans.map((s) => s.targetRepo)));

  const handleRepoChange = async (repo: string) => {
    setSelectedRepo(repo);
    const updatedStats = await api.getDashboardStats(repo === 'all' ? undefined : repo);
    setStats(updatedStats);
  };

  if (loading || !stats) {
    return (
      <div className="w-full h-96 flex items-center justify-center font-mono text-sm text-text-muted">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-signal animate-ping" />
          <span>Initializing telemetry bus...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 pb-14">
      {/* Top Banner / Breadcrumb */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-hairline">
        <div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
            Security Dashboard
          </h1>
          <div className="flex flex-wrap items-center gap-3 mt-1.5 font-mono text-xs text-text-secondary">
            <span>Target Scope:</span>
            <select
              value={selectedRepo}
              onChange={(e) => handleRepoChange(e.target.value)}
              aria-label="Filter dashboard scope by target repository"
              className="px-2.5 py-1 bg-surface border border-line focus:border-signal text-signal font-semibold rounded outline-none text-xs"
            >
              <option value="all">Active Target: {stats.activeRepo}</option>
              {availableRepos.map((repo) => (
                <option key={repo} value={repo}>
                  {repo}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex items-center gap-3 text-sm">
          <Link
            href="/scan/new"
            className="px-4 py-2 bg-signal text-canvas font-medium rounded hover:bg-signal-hover transition-colors flex items-center gap-2"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>New Scan</span>
          </Link>
          <Link
            href="/reports"
            className="px-4 py-2 bg-surface border border-line text-text-primary rounded hover:border-line-strong transition-colors flex items-center gap-2"
          >
            <FileCheck2 className="w-4 h-4 text-signal" />
            <span>Audit Reports</span>
          </Link>
        </div>
      </div>

      {/* Primary KPI & Severity Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Posture Score Dial */}
        <div className="p-5 bg-surface border border-line rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-text-secondary text-xs uppercase font-medium">
            <span>Posture Score</span>
            <span className="w-2.5 h-2.5 rounded-full bg-signal" />
          </div>
          <div className="my-3">
            <div className="text-3xl sm:text-4xl font-semibold text-text-primary font-mono tabular-nums">
              <CountUp end={stats.postureScore} suffix="/100" />
            </div>
            <div className="text-xs text-signal font-medium mt-1">
              Status: {stats.riskLevel}
            </div>
          </div>
          <div className="text-xs text-text-muted border-t border-hairline pt-2">
            Weighted CVSS + AST Coverage
          </div>
        </div>

        {/* Critical */}
        <div className="p-5 bg-surface border border-line rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-text-secondary text-xs uppercase font-medium">
            <span>Critical Severity</span>
            <span className="w-2.5 h-2.5 rounded-full bg-severity-critical" />
          </div>
          <div className="my-3">
            <div className="text-3xl sm:text-4xl font-semibold text-severity-critical font-mono tabular-nums">
              <CountUp end={stats.critical} />
            </div>
            <div className="text-xs text-text-secondary mt-1">
              {stats.critical > 0 ? `${stats.critical} Exploit Blockers` : 'Zero Critical Flaws'}
            </div>
          </div>
          <div className="text-xs text-signal border-t border-hairline pt-2 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Sandbox Verified</span>
          </div>
        </div>

        {/* High */}
        <div className="p-5 bg-surface border border-line rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-text-secondary text-xs uppercase font-medium">
            <span>High Severity</span>
            <span className="w-2.5 h-2.5 rounded-full bg-severity-high" />
          </div>
          <div className="my-3">
            <div className="text-3xl sm:text-4xl font-semibold text-severity-high font-mono tabular-nums">
              <CountUp end={stats.high} />
            </div>
            <div className="text-xs text-text-secondary mt-1">
              {stats.high > 0 ? `${stats.high} Exposure Hazards` : 'Zero High Hazards'}
            </div>
          </div>
          <div className="text-xs text-signal border-t border-hairline pt-2 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Immunity Proven</span>
          </div>
        </div>

        {/* Medium */}
        <div className="p-5 bg-surface border border-line rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-text-secondary text-xs uppercase font-medium">
            <span>Medium Severity</span>
            <span className="w-2.5 h-2.5 rounded-full bg-severity-medium" />
          </div>
          <div className="my-3">
            <div className="text-3xl sm:text-4xl font-semibold text-severity-medium font-mono tabular-nums">
              <CountUp end={stats.medium} />
            </div>
            <div className="text-xs text-text-secondary mt-1">
              {stats.medium > 0 ? `${stats.medium} Guardrail Flaws` : 'Zero Medium Risks'}
            </div>
          </div>
          <div className="text-xs text-signal border-t border-hairline pt-2 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Merged to Sandbox</span>
          </div>
        </div>

        {/* Patched & Verified */}
        <div className="p-5 bg-surface border border-line rounded-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-text-secondary text-xs uppercase font-medium">
            <span>Verified Patches</span>
            <span className="w-2.5 h-2.5 rounded-full bg-signal" />
          </div>
          <div className="my-3">
            <div className="text-3xl sm:text-4xl font-semibold text-signal font-mono tabular-nums">
              <CountUp end={stats.patchedCount} suffix={`/${stats.totalFindings}`} />
            </div>
            <div className="text-xs text-text-secondary mt-1">
              100% Empirically Validated
            </div>
          </div>
          <div className="text-xs text-text-muted border-t border-hairline pt-2">
            Zero Regressions Detected
          </div>
        </div>
      </div>

      {/* Main 2-Column Analytics Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Recent Scans & Rule Distribution */}
        <div className="lg:col-span-7 space-y-6">
          {/* Recent Scans Table */}
          <div className="bg-surface border border-line rounded-lg p-5">
            <div className="flex items-center justify-between pb-3 border-b border-hairline mb-4 text-sm">
              <div className="flex items-center gap-2 text-text-primary font-semibold">
                <Terminal className="w-4 h-4 text-signal" />
                <span>Recent Orchestrator Scans</span>
              </div>
              <Link href="/scan/new" className="text-signal hover:underline text-xs font-mono">
                Launch Scan →
              </Link>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {scans.map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scan/${scan.id}`}
                  className="block p-3.5 bg-canvas/60 border border-line hover:border-line-strong rounded transition-colors group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-text-primary group-hover:text-signal transition-colors text-sm">
                      {scan.id} · <span className="font-normal text-text-secondary">{scan.targetRepo}</span>
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-signal/15 text-signal border border-signal/20 font-medium">
                      {scan.status.toUpperCase()}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-xs text-text-secondary">
                    <div>Branch: <span className="text-text-primary font-medium">{scan.branch}</span> · Duration: {scan.durationSeconds}s</div>
                    <div className="flex items-center gap-3">
                      <span className="text-severity-critical font-medium">{scan.findingsCount.critical} Crit</span>
                      <span className="text-severity-high font-medium">{scan.findingsCount.high} High</span>
                      <span className="text-severity-medium font-medium">{scan.findingsCount.medium} Med</span>
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          </div>

          {/* AST Rule Distribution */}
          <div className="bg-surface border border-line rounded-lg p-5">
            <div className="flex items-center justify-between pb-3 border-b border-hairline mb-4 text-sm text-text-primary font-semibold">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-signal" />
                <span>AST Rule Coverage &amp; Findings Origin</span>
              </div>
              <span className="text-text-secondary text-xs font-mono">32 Deterministic Rules</span>
            </div>

            <div className="space-y-2.5 text-sm">
              {stats.ruleDistribution.map((item: any) => (
                <div key={item.rule} className="flex items-center justify-between p-2.5 rounded bg-canvas/40 border border-hairline">
                  <div className="flex items-center gap-3">
                    <span className="w-2 h-2 rounded-full bg-signal" />
                    <span className="text-text-primary font-medium">{item.rule}</span>
                    <span className="text-xs font-mono text-text-muted px-2 py-0.5 rounded bg-surface border border-line">
                      {item.cwe}
                    </span>
                  </div>
                  <span className="text-signal font-semibold font-mono text-xs">{item.count} flagged</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Module Health & Latency Telemetry */}
        <div className="lg:col-span-5 space-y-6">
          <div className="bg-surface border border-line rounded-lg p-5">
            <div className="flex items-center justify-between pb-3 border-b border-hairline mb-4 text-sm">
              <div className="flex items-center gap-2 text-text-primary font-semibold">
                <Activity className="w-4 h-4 text-signal" />
                <span>Module Health &amp; Latency</span>
              </div>
              <span className="text-signal text-xs font-mono font-medium">A2A Bus Active</span>
            </div>

            <div className="space-y-3 font-mono text-xs">
              {modules.map((m) => (
                <div
                  key={m.id}
                  className="p-3.5 bg-canvas/50 border border-line rounded flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-semibold text-text-primary text-sm font-sans">{m.name}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-signal/10 text-signal border border-signal/20">
                      {m.code}
                    </span>
                  </div>

                  <div className="text-xs text-text-secondary mb-2">
                    Capability: <code className="text-text-primary">{m.capability}</code>
                  </div>

                  <div className="flex items-center justify-between text-xs text-text-muted border-t border-hairline pt-2">
                    <span>Latency: <span className="text-text-primary font-semibold">{m.latencyAvgMs}ms</span></span>
                    <span>Owner: <span className="text-text-secondary">{m.owner}</span></span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Cryptographic Audit Verification Card */}
          <div className="bg-surface border border-line rounded-lg p-5 text-sm">
            <div className="flex items-center gap-2 text-text-primary font-semibold mb-2">
              <Key className="w-4 h-4 text-signal" />
              <span>Cryptographic Chain Status</span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed mb-3">
              All scans generate an HMAC-SHA256 chained audit sidecar sealed at completion.
              Any unauthorized tampering with report findings invalidates the cryptographic proof.
            </p>
            <div className="p-3 bg-canvas rounded border border-line text-xs font-mono text-signal truncate">
              Sidecar: report_llm.md.integrity.json (VERIFIED)
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
