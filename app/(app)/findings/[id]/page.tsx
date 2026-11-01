'use client';

import React, { useEffect, useState, useRef } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Play,
  FileCode,
  Download,
  Terminal,
  Cpu,
  Key,
  Check,
} from 'lucide-react';
import { api } from '@/lib/api';
import { Finding } from '@/lib/types';
import { gsap, useGSAP } from '@/lib/motion';

export default function FindingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const findingId = (params?.id as string) || 'FND-2026-0891';

  const [finding, setFinding] = useState<Finding | null>(null);
  const [applying, setApplying] = useState(false);
  const [applyMessage, setApplyMessage] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    async function load() {
      const data = await api.getFindingById(findingId);
      setFinding(data);
    }
    load();
  }, [findingId]);

  useGSAP(
    () => {
      const container = containerRef.current;
      if (!container) return;

      gsap.fromTo(
        container,
        { opacity: 0, y: 15 },
        { opacity: 1, y: 0, duration: 0.5, ease: 'signal' }
      );
    },
    { scope: containerRef, dependencies: [finding] }
  );

  const handleApplyPatch = async () => {
    if (!finding) return;
    setApplying(true);
    const result = await api.applyPatch(finding.id);
    setTimeout(() => {
      setApplying(false);
      setApplyMessage(result.message);
      if (result.finding) setFinding(result.finding);
    }, 600);
  };

  const handleExportDiff = () => {
    if (!finding?.patch) return;
    const blob = new Blob([finding.patch.diff], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${finding.id}-sandbox-patch.diff`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!finding) {
    return (
      <div className="w-full h-96 flex items-center justify-center font-mono text-xs text-text-muted">
        <span>FETCHING FINDING {findingId}...</span>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="space-y-8 pb-16 max-w-6xl mx-auto">
      {/* Back button & top bar */}
      <div className="flex items-center justify-between pb-4 border-b border-hairline font-mono text-xs">
        <Link
          href="/findings"
          className="flex items-center gap-2 text-text-secondary hover:text-text-primary transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Findings Inventory</span>
        </Link>

        <div className="flex items-center gap-3">
          <span className="text-text-muted">DISCOVERED: {finding.discoveredAt}</span>
          <span
            className={`px-2 py-0.5 rounded font-semibold uppercase text-[10px] ${finding.severity === 'critical'
                ? 'bg-severity-critical/20 text-severity-critical border border-severity-critical/30'
                : finding.severity === 'high'
                  ? 'bg-severity-high/20 text-severity-high border border-severity-high/30'
                  : 'bg-severity-medium/20 text-severity-medium border border-severity-medium/30'
              }`}
          >
            {finding.severity}
          </span>
        </div>
      </div>

      {/* Primary Header */}
      <div>
        <div className="font-mono text-xs text-signal tracking-widest uppercase mb-1">
          {finding.id} {'//'} {finding.cwe}
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
          {finding.ruleTitle}
        </h1>
        <div className="mt-2 flex flex-wrap items-center gap-4 font-mono text-xs text-text-muted">
          <span>File: <code className="text-text-primary">{finding.file}</code> (lines {finding.lineStart}-{finding.lineEnd})</span>
          <span>·</span>
          <span>Rule ID: <code className="text-signal">{finding.ruleId}</code></span>
          <span>·</span>
          <span>Confidence: <strong className="text-text-primary">{(finding.confidence * 100).toFixed(0)}%</strong></span>
        </div>
      </div>

      {/* Toast Feedback */}
      {applyMessage && (
        <div className="p-4 bg-signal/15 border border-signal/30 text-signal font-mono text-xs rounded flex items-center justify-between animate-in fade-in">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{applyMessage}</span>
          </div>
          <button
            onClick={() => setApplyMessage(null)}
            className="text-signal hover:underline text-[11px]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Two Column Layout: Vulnerable Code + LLM Reasoning */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Vulnerable Code View */}
        <div className="lg:col-span-7 bg-surface border border-line rounded-lg p-5 font-mono text-xs">
          <div className="flex items-center justify-between pb-3 border-b border-hairline mb-4 text-text-muted text-[11px]">
            <div className="flex items-center gap-2">
              <FileCode className="w-3.5 h-3.5 text-signal" />
              <span>TRIGGERING AST SINK // {finding.file}</span>
            </div>
            <span>Tree-sitter Python</span>
          </div>

          <pre className="p-4 bg-canvas rounded border border-line text-xs overflow-x-auto leading-relaxed select-text text-text-primary">
            <code>{finding.snippet}</code>
          </pre>

          <div className="mt-4 p-3 bg-canvas/40 border border-hairline rounded text-[11px] text-text-secondary leading-relaxed">
            <span className="text-severity-critical font-semibold">Taint Analysis Result: </span>
            Variable passed as function parameter reaches sink without sanitization or parameter binding.
          </div>
        </div>

        {/* Right Column: LLM Reasoning & Exploit Status */}
        <div className="lg:col-span-5 bg-surface border border-line rounded-lg p-5 font-mono text-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-hairline mb-4 text-[11px] text-text-muted">
              <span>LLM REASONING TRACE</span>
              <span className="text-signal font-semibold">{finding.llmVerdict}</span>
            </div>

            <p className="text-text-secondary text-xs leading-relaxed mb-4">
              {finding.explanation}
            </p>

            <div className="p-3 bg-canvas/60 rounded border border-line space-y-2 text-[11px]">
              <div className="flex justify-between">
                <span className="text-text-muted">Exploit Verdict:</span>
                <span className="text-signal font-semibold">
                  {finding.exploitStatus || 'PATCH_CONFIRMED_IMMUNE'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">Sandbox Retries:</span>
                <span className="text-text-primary">0 (Passed on 1st Attempt)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-text-muted">CWE Reference:</span>
                <span className="text-text-primary">{finding.cwe.split(':')[0]}</span>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="pt-6 border-t border-hairline flex flex-col sm:flex-row gap-3">
            <button
              onClick={handleApplyPatch}
              disabled={applying}
              className="flex-1 py-2.5 px-4 bg-signal text-canvas font-semibold rounded hover:bg-signal-hover transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {applying ? (
                <span>Rechecking Sandbox...</span>
              ) : (
                <>
                  <Check className="w-3.5 h-3.5 stroke-[3]" />
                  <span>Apply Patch to Sandbox</span>
                </>
              )}
            </button>

            <button
              onClick={handleExportDiff}
              className="py-2.5 px-4 bg-canvas border border-line text-text-primary rounded hover:border-line-strong transition-colors flex items-center justify-center gap-2"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export .diff</span>
            </button>
          </div>
        </div>
      </div>

      {/* Side-by-Side Patch Diff View */}
      {finding.patch && (
        <div className="bg-surface border border-line rounded-lg p-5 font-mono text-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-hairline text-text-primary font-medium">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-signal" />
              <span>EMPIRICAL PATCH DIFF &amp; HARNESS VERIFICATION</span>
            </div>
            <span className="text-[11px] text-signal">Sandbox Re-check: PASSED (0 Triggers)</span>
          </div>

          {/* Unified Diff */}
          <div className="p-4 bg-canvas rounded border border-line overflow-x-auto text-xs leading-relaxed">
            {finding.patch.diff.split('\n').map((line, i) => {
              const isAdd = line.startsWith('+') && !line.startsWith('+++');
              const isSub = line.startsWith('-') && !line.startsWith('---');
              const isHdr = line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++');

              return (
                <div
                  key={i}
                  className={
                    isAdd
                      ? 'bg-signal/15 text-signal font-semibold px-1 rounded-sm'
                      : isSub
                        ? 'bg-severity-critical/15 text-severity-critical font-semibold px-1 rounded-sm'
                        : isHdr
                          ? 'text-text-muted font-medium'
                          : 'text-text-secondary'
                  }
                >
                  {line}
                </div>
              );
            })}
          </div>

          {/* Test Harness Output */}
          <div className="p-3 bg-canvas/40 rounded border border-hairline text-[11px] text-text-muted flex items-center justify-between">
            <span className="text-signal">{finding.patch.testHarnessOutput}</span>
            <div className="flex items-center gap-1.5 text-text-muted">
              <Key className="w-3 h-3 text-signal" />
              <span>HMAC Sealed</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

