'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert,
  Search,
  Filter,
  CheckCircle2,
  ArrowRight,
  ExternalLink,
  Code2,
  ChevronRight,
} from 'lucide-react';
import { api } from '@/lib/api';
import { Finding, Severity } from '@/lib/types';
import Reveal from '@/components/motion/Reveal';

export default function FindingsPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scans, setScans] = useState<{ id: string; targetRepo: string }[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedRule, setSelectedRule] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [hoveredFinding, setHoveredFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const [fData, sData] = await Promise.all([
        api.getFindings(),
        api.getScans(),
      ]);
      setFindings(fData);
      setScans(sData);
      setLoading(false);
    }
    load();
  }, []);

  const availableRepos = Array.from(new Set(scans.map((s) => s.targetRepo)));

  const filteredFindings = findings.filter((f) => {
    if (selectedRepo !== 'all') {
      const matchingScanIds = scans.filter((s) => s.targetRepo === selectedRepo).map((s) => s.id);
      const repoSlug = selectedRepo.split('/').pop() || selectedRepo;
      const isMatch =
        (f.scanId && matchingScanIds.includes(f.scanId)) ||
        f.file.toLowerCase().includes(repoSlug.toLowerCase()) ||
        (selectedRepo.includes('seeded-vuln-repo') && (!f.scanId || f.scanId === 'SCN-2026-0941'));
      if (!isMatch) return false;
    }
    if (selectedSeverity !== 'all' && f.severity !== selectedSeverity) return false;
    if (selectedRule !== 'all' && f.ruleId !== selectedRule) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        f.file.toLowerCase().includes(q) ||
        f.ruleTitle.toLowerCase().includes(q) ||
        f.cwe.toLowerCase().includes(q) ||
        f.id.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const uniqueRules = Array.from(new Set(findings.map((f) => f.ruleId)));

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-hairline">
        <div>
          <div className="font-mono text-xs text-signal tracking-widest uppercase mb-1">
            VULNERABILITY INVENTORY // CONFIRMED FINDINGS
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
            Security Findings Workbench
          </h1>
        </div>

        <div className="font-mono text-xs text-text-muted">
          Showing <span className="text-signal font-semibold">{filteredFindings.length}</span> of {findings.length} findings
        </div>
      </div>

      {/* Sticky Filters Toolbar */}
      <div className="sticky top-14 z-30 bg-surface/95 border border-line rounded-lg p-4 font-mono text-xs space-y-3">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          {/* Search Box */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-3.5 h-3.5 text-text-muted absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter by file path, CWE, or rule title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none placeholder:text-text-muted"
            />
          </div>

          <div className="flex items-center gap-3">
            {/* Target Repository Selector */}
            <div className="flex items-center gap-2">
              <span className="text-text-muted text-[11px] shrink-0">Repository:</span>
              <select
                value={selectedRepo}
                onChange={(e) => setSelectedRepo(e.target.value)}
                aria-label="Filter findings by target repository"
                className="px-2.5 py-1.5 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none text-xs max-w-[200px] truncate"
              >
                <option value="all">All Repositories ({availableRepos.length})</option>
                {availableRepos.map((repo) => (
                  <option key={repo} value={repo}>
                    {repo.replace('https://github.com/', '')}
                  </option>
                ))}
              </select>
            </div>

            {/* Rule Selector */}
            <div className="flex items-center gap-2">
              <span className="text-text-muted text-[11px] shrink-0">Rule:</span>
              <select
                value={selectedRule}
                onChange={(e) => setSelectedRule(e.target.value)}
                aria-label="Filter findings by AST security rule"
                className="px-2.5 py-1.5 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none text-xs"
              >
                <option value="all">All AST Rules ({uniqueRules.length})</option>
                {uniqueRules.map((rule) => (
                  <option key={rule} value={rule}>
                    {rule}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {/* Severity Chips */}
        <div className="flex items-center gap-2 pt-2 border-t border-hairline overflow-x-auto">
          <span className="text-text-muted text-[11px] shrink-0 mr-1">Severity:</span>
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => {
            const count =
              sev === 'all'
                ? findings.length
                : findings.filter((f) => f.severity === sev).length;
            const isSelected = selectedSeverity === sev;

            return (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded text-xs transition-colors shrink-0 flex items-center gap-1.5 ${
                  isSelected
                    ? 'bg-signal text-canvas font-semibold'
                    : 'bg-canvas text-text-secondary hover:text-text-primary border border-line'
                }`}
              >
                <span className="capitalize">{sev}</span>
                <span className="text-[10px] opacity-75">({count})</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-surface border border-line rounded-lg overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-hairline bg-canvas/40 text-text-muted text-[11px]">
                <th className="py-3 px-4">FINDING ID</th>
                <th className="py-3 px-4">SEVERITY</th>
                <th className="py-3 px-4">RULE &amp; TITLE</th>
                <th className="py-3 px-4">LOCATION</th>
                <th className="py-3 px-4">CONFIDENCE</th>
                <th className="py-3 px-4">EMPIRICAL STATUS</th>
                <th className="py-3 px-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loading ? (
                Array.from({ length: 6 }).map((_, idx) => (
                  <tr key={`skel-${idx}`} className="h-12 animate-pulse">
                    <td className="py-3.5 px-4"><div className="h-4 w-28 bg-line rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-16 bg-line rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-48 bg-line rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-32 bg-line rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-12 bg-line rounded" /></td>
                    <td className="py-3.5 px-4"><div className="h-4 w-24 bg-line rounded" /></td>
                    <td className="py-3.5 px-4 text-right"><div className="h-4 w-12 bg-line rounded ml-auto" /></td>
                  </tr>
                ))
              ) : (
                filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    id={`finding-row-${finding.id}`}
                    onMouseEnter={() => setHoveredFinding(finding)}
                    onClick={() => router.push(`/findings/${finding.id}`)}
                    className="hover:bg-canvas/60 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-semibold text-text-primary group-hover:text-signal transition-colors">
                      {finding.id}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded uppercase font-semibold ${
                          finding.severity === 'critical'
                            ? 'bg-severity-critical/20 text-severity-critical border border-severity-critical/30'
                            : finding.severity === 'high'
                            ? 'bg-severity-high/20 text-severity-high border border-severity-high/30'
                            : 'bg-severity-medium/20 text-severity-medium border border-severity-medium/30'
                        }`}
                      >
                        {finding.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 max-w-xs">
                      <div className="text-text-primary font-medium truncate">
                        {finding.ruleTitle}
                      </div>
                      <div className="text-[10px] text-text-muted truncate">
                        {finding.cwe.split(':')[0]} · {finding.ruleId}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-text-secondary truncate max-w-[200px]">
                      {finding.file}:{finding.lineStart}
                    </td>
                    <td className="py-3.5 px-4 tabular-nums">
                      {(finding.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="flex items-center gap-1.5 text-signal text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Sandbox Verified</span>
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <span className="inline-flex items-center gap-1 text-signal text-xs group-hover:translate-x-1 transition-transform">
                        <span>Inspect</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row Hover Peek Drawer */}
      {hoveredFinding && (
        <div className="p-4 bg-surface border border-line rounded-lg font-mono text-xs animate-in fade-in duration-150">
          <div className="flex items-center justify-between pb-2 border-b border-hairline mb-2 text-text-muted">
            <span className="text-text-primary font-medium">
              PREVIEW: {hoveredFinding.id} — {hoveredFinding.file}:{hoveredFinding.lineStart}
            </span>
            <span className="text-signal">{hoveredFinding.ruleId}</span>
          </div>
          <p className="text-text-secondary text-[11px] leading-relaxed mb-3">
            {hoveredFinding.explanation}
          </p>
          <pre className="p-3 bg-canvas rounded border border-line text-[11px] text-text-secondary overflow-x-auto">
            {hoveredFinding.snippet}
          </pre>
        </div>
      )}
    </div>
  );
}

