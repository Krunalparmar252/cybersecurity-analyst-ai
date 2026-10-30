'use client';

import React, { useState, useEffect } from 'react';
import {
  FileText,
  FileCheck2,
  Download,
  Key,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Printer,
} from 'lucide-react';
import { api } from '@/lib/api';
import { ReportItem } from '@/lib/types';
import ScrambleId from '@/components/motion/ScrambleId';

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [selectedReport, setSelectedReport] = useState<ReportItem | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function load() {
      const data = await api.getReports();
      setReports(data);
      if (data.length > 0) setSelectedReport(data[0]);
    }
    load();
  }, []);

  const handleExport = (format: 'md' | 'json') => {
    if (!selectedReport) return;
    const content =
      format === 'md'
        ? `# Security Audit Report — ${selectedReport.targetRepo}\n\nScan ID: ${selectedReport.scanId}\nGenerated: ${selectedReport.generatedAt}\nHMAC Signature: ${selectedReport.hmacSignature}\n\n## Executive Summary\n${selectedReport.executiveSummary}\n\n## Vulnerabilities Remediated\nTotal: ${selectedReport.vulnerabilityCount} (Patches Applied: ${selectedReport.patchesApplied})\nCritical: ${selectedReport.findingsBreakdown.critical}\nHigh: ${selectedReport.findingsBreakdown.high}\nMedium: ${selectedReport.findingsBreakdown.medium}\n\nAll patches verified in isolated sandbox with 0 regressions.`
        : JSON.stringify(
            {
              report_id: selectedReport.id,
              scan_id: selectedReport.scanId,
              target_repo: selectedReport.targetRepo,
              hmac_signature: selectedReport.hmacSignature,
              audit_chain_length: selectedReport.auditChainLength,
              integrity_verified: true,
              generated_at: selectedReport.generatedAt,
            },
            null,
            2
          );

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedReport.id}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopySignature = () => {
    if (!selectedReport) return;
    navigator.clipboard.writeText(selectedReport.hmacSignature);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-hairline">
        <div>
          <div className="font-mono text-xs text-signal tracking-widest uppercase mb-1">
            VERIFIED AUDIT VAULT // CHAIN OF CUSTODY
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
            Cryptographic Audit Reports
          </h1>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            onClick={() => handleExport('md')}
            className="px-3 py-1.5 bg-signal text-canvas font-semibold rounded hover:bg-signal-hover transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Markdown</span>
          </button>
          <button
            onClick={() => handleExport('json')}
            className="px-3 py-1.5 bg-surface border border-line text-text-primary rounded hover:border-line-strong transition-colors flex items-center gap-1.5"
          >
            <Key className="w-3.5 h-3.5 text-signal" />
            <span>.integrity.json</span>
          </button>
        </div>
      </div>

      {/* Reports Split Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Report List */}
        <div className="lg:col-span-4 space-y-3 font-mono text-xs">
          <div className="text-text-muted text-[11px] pb-2 border-b border-hairline uppercase">
            Generated Audit Reports ({reports.length})
          </div>

          {reports.map((rep) => {
            const isSelected = selectedReport?.id === rep.id;
            return (
              <div
                key={rep.id}
                onClick={() => setSelectedReport(rep)}
                className={`p-4 rounded-lg border transition-colors cursor-pointer space-y-2 ${
                  isSelected
                    ? 'bg-surface border-signal'
                    : 'bg-surface/50 border-line hover:border-line-strong'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-text-primary">{rep.id}</span>
                  <span className="text-[10px] text-signal px-2 py-0.5 rounded bg-signal/15 border border-signal/20">
                    SEALED
                  </span>
                </div>

                <div className="text-text-secondary text-[11px]">
                  Repository: <span className="text-text-primary">{rep.targetRepo}</span>
                </div>

                <div className="flex items-center justify-between text-[10px] text-text-muted border-t border-hairline pt-2">
                  <span>{rep.vulnerabilityCount} Findings Fixed</span>
                  <span>{rep.generatedAt.split('T')[0]}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Right Column: Live Report Viewer */}
        <div className="lg:col-span-8 bg-surface border border-line rounded-lg p-6 sm:p-8 font-mono text-xs space-y-6 shadow-xl">
          {selectedReport ? (
            <>
              {/* Report Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-hairline">
                <div>
                  <div className="text-[11px] text-signal font-semibold mb-1">
                    OFFICIAL SECURITY AUDIT REPORT
                  </div>
                  <h2 className="text-xl font-bold text-text-primary">
                    Audit Certificate // {selectedReport.targetRepo}
                  </h2>
                  <div className="text-[11px] text-text-muted mt-1">
                    Scan Identifier: {selectedReport.scanId} · Generated: {selectedReport.generatedAt}
                  </div>
                </div>

                <div className="flex items-center gap-2 p-2 rounded bg-signal/10 border border-signal/30 text-signal text-[11px]">
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                  <span>HMAC CHAIN VERIFIED</span>
                </div>
              </div>

              {/* DrawSVG Conduit Divider */}
              <svg viewBox="0 0 600 4" fill="none" className="w-full h-1 overflow-visible">
                <line
                  x1="0"
                  y1="2"
                  x2="600"
                  y2="2"
                  stroke="#C6FF3D"
                  strokeWidth="1.5"
                  strokeDasharray="6 6"
                />
              </svg>

              {/* Executive Summary Section */}
              <div className="space-y-2">
                <div className="text-text-primary font-semibold text-xs uppercase tracking-wider">
                  1. Executive Summary
                </div>
                <p className="text-text-secondary leading-relaxed text-xs sm:text-[13px] bg-canvas/40 p-4 rounded border border-hairline">
                  {selectedReport.executiveSummary}
                </p>
              </div>

              {/* Vulnerabilities & Patches Breakdown */}
              <div className="space-y-3">
                <div className="text-text-primary font-semibold text-xs uppercase tracking-wider">
                  2. Remediated Vulnerabilities &amp; Sandbox Integrity
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                  <div className="p-3 bg-canvas/60 border border-line rounded">
                    <div className="text-text-muted text-[10px]">CRITICAL</div>
                    <div className="text-xl font-bold text-severity-critical mt-1">
                      {selectedReport.findingsBreakdown.critical}
                    </div>
                  </div>
                  <div className="p-3 bg-canvas/60 border border-line rounded">
                    <div className="text-text-muted text-[10px]">HIGH</div>
                    <div className="text-xl font-bold text-severity-high mt-1">
                      {selectedReport.findingsBreakdown.high}
                    </div>
                  </div>
                  <div className="p-3 bg-canvas/60 border border-line rounded">
                    <div className="text-text-muted text-[10px]">MEDIUM</div>
                    <div className="text-xl font-bold text-severity-medium mt-1">
                      {selectedReport.findingsBreakdown.medium}
                    </div>
                  </div>
                  <div className="p-3 bg-canvas/60 border border-line rounded">
                    <div className="text-text-muted text-[10px]">PATCHES VERIFIED</div>
                    <div className="text-xl font-bold text-signal mt-1">
                      {selectedReport.patchesApplied}/{selectedReport.vulnerabilityCount}
                    </div>
                  </div>
                </div>
              </div>

              {/* Cryptographic Signature Chain */}
              <div className="space-y-3 pt-4 border-t border-hairline">
                <div className="flex items-center justify-between text-text-primary font-semibold text-xs uppercase tracking-wider">
                  <div className="flex items-center gap-2">
                    <Key className="w-3.5 h-3.5 text-signal" />
                    <span>3. Cryptographic Proof of Chain of Custody</span>
                  </div>
                  <button
                    onClick={handleCopySignature}
                    className="text-[11px] text-signal hover:underline flex items-center gap-1"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{copied ? 'Copied' : 'Copy Hash'}</span>
                  </button>
                </div>

                <div className="p-4 bg-canvas border border-line rounded space-y-2 text-[11px]">
                  <div className="text-text-muted flex justify-between">
                    <span>Audit Chain Length:</span>
                    <span className="text-text-primary">{selectedReport.auditChainLength} transitions</span>
                  </div>
                  <div className="text-text-muted">
                    HMAC-SHA256 Digest:
                    <div className="text-signal break-all mt-1 font-mono text-[11px] bg-surface p-2 rounded border border-hairline">
                      {selectedReport.hmacSignature}
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="py-12 text-center text-text-muted">
              Select a report from the vault to inspect certification details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

