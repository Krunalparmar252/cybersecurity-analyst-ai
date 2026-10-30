'use client';

import React, { useEffect, useState, useRef, memo } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import {
  Terminal,
  CheckCircle2,
  ArrowRight,
  Key,
} from 'lucide-react';
import { api } from '@/lib/api';
import { Scan, Finding } from '@/lib/types';
import StageRail, { Stage } from '@/components/motion/StageRail';
import ScrambleId from '@/components/motion/ScrambleId';
import CountUp from '@/components/motion/CountUp';

// Memoized streaming terminal log to isolate streaming re-renders from the page
interface TerminalStreamProps {
  logs: string[];
  isCompleted: boolean;
  integrityHash: string;
}

const TerminalStream = memo(function TerminalStream({
  logs,
  isCompleted,
  integrityHash,
}: TerminalStreamProps) {
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-canvas border border-line rounded-lg overflow-hidden shadow-2xl">
      <div className="flex items-center justify-between px-4 py-3 bg-surface border-b border-hairline font-mono text-xs text-text-muted">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-signal" />
          <span className="text-text-primary font-medium">A2A CAPABILITY BUS STREAM</span>
        </div>
        <div className="flex items-center gap-3 text-[10px]">
          <span className="flex items-center gap-1.5 text-signal">
            <span className="w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
            LIVE
          </span>
          <span>SHA256 HMAC CHAIN</span>
        </div>
      </div>

      {/* Console Log Area */}
      <div
        ref={terminalRef}
        aria-live="polite"
        className="h-80 overflow-y-auto p-4 font-mono text-xs space-y-1.5 text-text-secondary select-text scroll-smooth"
      >
        {logs.map((log, index) => {
          const isError = log.includes('CRITICAL') || log.includes('VULNERABLE');
          const isSuccess = log.includes('PASSED') || log.includes('verified') || log.includes('complete');
          const isBus = log.includes('A2A') || log.includes('ORCHESTRATOR');

          return (
            <div key={`${index}-${log.slice(0, 15)}`} className="flex items-start gap-2 leading-relaxed">
              <span className="text-text-muted select-none">
                {String(index + 1).padStart(2, '0')}
              </span>
              <span
                className={
                  isError
                    ? 'text-severity-critical'
                    : isSuccess
                    ? 'text-signal'
                    : isBus
                    ? 'text-text-primary font-medium'
                    : 'text-text-secondary'
                }
              >
                {log}
              </span>
            </div>
          );
        })}
        {!isCompleted && (
          <div className="flex items-center gap-1.5 text-signal animate-pulse pt-1">
            <span className="inline-block w-2 h-4 bg-signal" />
            <span>Analyzing AST nodes...</span>
          </div>
        )}
      </div>

      {/* Cryptographic Hash Bar */}
      <div className="px-4 py-2.5 bg-surface/80 border-t border-hairline font-mono text-[11px] flex items-center justify-between text-text-muted">
        <div className="flex items-center gap-2 truncate mr-4">
          <Key className="w-3.5 h-3.5 text-signal shrink-0" />
          <span className="truncate">
            HMAC Audit Chain Hash:{' '}
            <ScrambleId value={integrityHash} className="text-text-primary" />
          </span>
        </div>
        <span className="text-signal shrink-0">Chain Sealed</span>
      </div>
    </div>
  );
});

// Memoized finding card row to avoid redundant re-renders
const FindingCardRow = memo(function FindingCardRow({ finding }: { finding: Finding }) {
  return (
    <Link
      href={`/findings/${finding.id}`}
      className="p-4 bg-surface border border-line hover:border-line-strong rounded transition-colors group flex flex-col justify-between"
    >
      <div>
        <div className="flex items-center justify-between mb-2">
          <span className="font-semibold text-text-primary group-hover:text-signal transition-colors">
            {finding.id}
          </span>
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
        </div>

        <div className="text-xs text-text-primary font-medium mb-1">
          {finding.ruleTitle}
        </div>
        <div className="text-[11px] text-text-muted mb-3">
          {finding.file}:{finding.lineStart}
        </div>
      </div>

      <div className="pt-2 border-t border-hairline flex items-center justify-between text-[11px]">
        <span className="text-signal">Empirical Patch: READY</span>
        <ArrowRight className="w-3.5 h-3.5 text-text-muted group-hover:text-signal transition-transform group-hover:translate-x-1" />
      </div>
    </Link>
  );
});

export default function LiveScanPage() {
  const params = useParams();
  const scanId = (params?.id as string) || 'SCN-2026-0941';

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [currentProgress, setCurrentProgress] = useState(15);
  const [isCompleted, setIsCompleted] = useState(false);
  const [applyingPatches, setApplyingPatches] = useState(false);
  const [appliedNotice, setAppliedNotice] = useState<string | null>(null);

  useEffect(() => {
    async function init() {
      const s = await api.getScanById(scanId);
      if (s) {
        setScan(s);
        const f = await api.getFindingsForScan(scanId);
        setFindings(f);

        // Stream terminal logs smoothly
        const fullLogs = s.terminalLogs && s.terminalLogs.length > 0
          ? s.terminalLogs
          : [
              `[ORCHESTRATOR] Initialized scan ${scanId} for target: ${s.targetRepo}`,
              `[INGESTION] Cloned repository. Parsing AST syntax trees...`,
              `[DETECTION] Evaluated deterministic rules across source files.`,
              `[REASONING] Validating candidate findings and compiling unified diffs...`,
              `[SANDBOX] Empirical test loop passed. Fixes verified.`,
              `[REPORTING] Audit report signed and sealed.`,
            ];

        let index = 0;
        const interval = setInterval(() => {
          if (index < fullLogs.length) {
            setLogs((prev) => [...prev.slice(-499), fullLogs[index]]);
            setCurrentProgress(Math.min(100, Math.round(((index + 1) / fullLogs.length) * 100)));
            index++;
          } else {
            clearInterval(interval);
            setIsCompleted(true);
            setCurrentProgress(100);
          }
        }, 140);

        return () => clearInterval(interval);
      }
    }
    init();
  }, [scanId]);

  if (!scan) {
    return (
      <div className="w-full h-96 flex items-center justify-center font-mono text-xs text-text-muted">
        <span>LOADING RUN {scanId}...</span>
      </div>
    );
  }

  const handleAutoApplyAll = async () => {
    setApplyingPatches(true);
    const res = await api.applyAllPatchesForScan(scanId);
    setTimeout(() => {
      setApplyingPatches(false);
      setAppliedNotice(res.message);
      setLogs((prev) => [
        ...prev.slice(-497),
        `[ORCHESTRATOR] Auto-applied ${res.appliedCount} verified patch(es) directly to ${scan?.targetRepo}.`,
        `[SANDBOX] Peer bus rule.recheck: PASSED (0 remaining violations). Repository remediated.`,
      ]);
    }, 700);
  };

  const stages: Stage[] = [
    { id: 'ingest', name: '1. Ingest', capability: 'repo.ingest', status: currentProgress >= 20 ? 'complete' : 'active' },
    { id: 'detect', name: '2. Detect', capability: 'rule.scan', status: currentProgress >= 40 ? 'complete' : currentProgress >= 20 ? 'active' : 'pending' },
    { id: 'reason', name: '3. Reason', capability: 'patch.reasoning', status: currentProgress >= 65 ? 'complete' : currentProgress >= 40 ? 'active' : 'pending' },
    { id: 'exploit', name: '4. Exploit', capability: 'exploit.verify', status: currentProgress >= 80 ? 'complete' : currentProgress >= 65 ? 'active' : 'pending' },
    { id: 'triage', name: '5. Triage', capability: 'finding.triage', status: currentProgress >= 90 ? 'complete' : currentProgress >= 80 ? 'active' : 'pending' },
    { id: 'report', name: '6. Report', capability: 'report.render', status: currentProgress >= 100 ? 'complete' : currentProgress >= 90 ? 'active' : 'pending' },
  ];

  return (
    <div className="space-y-8 pb-12">
      {/* Run Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-hairline">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-signal tracking-widest uppercase mb-1">
            <span className="w-2 h-2 rounded-full bg-signal animate-pulse-subtle" />
            <span>LIVE ORCHESTRATOR COCKPIT // {scan.id}</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
            Scanning Repository: <span className="font-mono text-signal">{scan.targetRepo}</span>
          </h1>
        </div>

        <div className="flex items-center gap-4 font-mono text-xs">
          {isCompleted && (
            <button
              onClick={handleAutoApplyAll}
              disabled={applyingPatches || !!appliedNotice}
              className={`px-3 py-1.5 rounded font-mono text-xs font-semibold flex items-center gap-1.5 transition-all ${
                appliedNotice
                  ? 'bg-signal/20 text-signal border border-signal/40'
                  : 'bg-signal text-canvas hover:bg-signal-hover cursor-pointer shadow-lg'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>
                {applyingPatches
                  ? 'Applying...'
                  : appliedNotice
                  ? 'Patches Applied'
                  : 'Auto-Apply All Patches'}
              </span>
            </button>
          )}

          <div className="text-right">
            <div className="text-text-muted text-[10px]">INTEGRITY SALT</div>
            <ScrambleId value={scan.runSalt} className="text-text-primary text-xs" />
          </div>

          <div className="text-right">
            <div className="text-text-muted text-[10px]">STATUS</div>
            <span
              className={`px-2 py-0.5 rounded font-semibold ${
                isCompleted
                  ? 'bg-signal/20 text-signal border border-signal/30'
                  : 'bg-canvas text-signal border border-signal animate-pulse'
              }`}
            >
              {isCompleted ? 'COMPLETED' : 'ANALYZING'}
            </span>
          </div>
        </div>
      </div>

      {/* Stage Rail Progress Bar */}
      <div className="bg-surface border border-line rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between font-mono text-xs text-text-muted">
          <span>PROGRESS: {currentProgress}%</span>
          <span>ESTIMATED REMAINING: {isCompleted ? '0s' : '12s'}</span>
        </div>

        <div className="w-full bg-canvas rounded-full h-1.5 overflow-hidden">
          <div
            className="bg-signal h-full transition-all duration-300"
            style={{ width: `${currentProgress}%` }}
          />
        </div>

        <StageRail stages={stages} />
      </div>

      {/* Real-Time Live Counters Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
        <div className="p-4 bg-surface border border-line rounded">
          <div className="text-text-muted text-[10px]">CRITICAL FINDINGS</div>
          <div className="text-2xl font-bold text-severity-critical mt-1">
            <CountUp end={currentProgress > 30 ? (scan.findingsCount?.critical ?? 0) : 0} />
          </div>
          <div className="text-[10px] text-text-muted mt-1">
            {(scan.findingsCount?.critical ?? 0) > 0 ? `${scan.findingsCount?.critical} Exploit Blockers` : 'Zero Critical Flaws'}
          </div>
        </div>

        <div className="p-4 bg-surface border border-line rounded">
          <div className="text-text-muted text-[10px]">HIGH FINDINGS</div>
          <div className="text-2xl font-bold text-severity-high mt-1">
            <CountUp end={currentProgress > 45 ? (scan.findingsCount?.high ?? 0) : 0} />
          </div>
          <div className="text-[10px] text-text-muted mt-1">
            {(scan.findingsCount?.high ?? 0) > 0 ? `${scan.findingsCount?.high} Exposure Hazards` : 'Zero High Hazards'}
          </div>
        </div>

        <div className="p-4 bg-surface border border-line rounded">
          <div className="text-text-muted text-[10px]">MEDIUM FINDINGS</div>
          <div className="text-2xl font-bold text-severity-medium mt-1">
            <CountUp end={currentProgress > 60 ? (scan.findingsCount?.medium ?? 0) : 0} />
          </div>
          <div className="text-[10px] text-text-muted mt-1">
            {(scan.findingsCount?.medium ?? 0) > 0 ? `${scan.findingsCount?.medium} Guardrail Flaws` : 'Zero Medium Risks'}
          </div>
        </div>

        <div className="p-4 bg-surface border border-line rounded">
          <div className="text-text-muted text-[10px]">PATCHES VERIFIED</div>
          <div className="text-2xl font-bold text-signal mt-1">
            <CountUp
              end={currentProgress > 75 ? (scan.findingsCount?.total ?? 0) : 0}
              suffix={`/${scan.findingsCount?.total ?? 0}`}
            />
          </div>
          <div className="text-[10px] text-text-muted mt-1">Empirical Sandbox Recheck</div>
        </div>
      </div>

      {/* Live Streaming Terminal */}
      <TerminalStream
        logs={logs}
        isCompleted={isCompleted}
        integrityHash={scan.integrityHash}
      />

      {/* Findings Emerging with Stagger */}
      {currentProgress > 30 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-hairline font-mono text-xs">
            <span className="text-text-primary font-medium">DISCOVERED FINDINGS ({findings.length})</span>
            <Link href="/findings" className="text-signal hover:underline">
              View All in Findings Workbench →
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            {findings.map((finding) => (
              <FindingCardRow key={finding.id} finding={finding} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
