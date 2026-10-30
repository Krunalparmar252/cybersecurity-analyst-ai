'use client';

import React, { useRef, useState } from 'react';
import { gsap, ScrollTrigger, useGSAP } from '@/lib/motion';
import {
  FolderSearch,
  SearchCode,
  SlidersHorizontal,
  BrainCircuit,
  ShieldCheck,
  FileKey2,
} from 'lucide-react';

interface PipelineStageData {
  id: string;
  number: string;
  title: string;
  agent: string;
  capability: string;
  icon: React.ComponentType<{ className?: string }>;
  telemetry: string;
  outputPreview: string;
  keyMetric: string;
}

const STAGES: PipelineStageData[] = [
  {
    id: 'ingest',
    number: '01',
    title: 'AST Repository Ingestion',
    agent: 'AgentID.INGESTION',
    capability: 'repo.ingest',
    icon: FolderSearch,
    telemetry: 'Tree-sitter grammar loaded. Walking 18 Python source files in seeded-vuln-repo...',
    outputPreview: 'Parsed AST symbol tables, import hierarchy, manifest quality score: SUFFICIENT (100%)',
    keyMetric: '85ms Ingestion Latency',
  },
  {
    id: 'detect',
    number: '02',
    title: 'Deterministic Detection',
    agent: 'AgentID.DETECTION',
    capability: 'rule.scan',
    icon: SearchCode,
    telemetry: 'Scanning with 32 deterministic AST taint & Shannon entropy security rules...',
    outputPreview: 'Identified 6 candidate findings: 2 CRITICAL, 2 HIGH, 2 MEDIUM. Secrets masked at inception.',
    keyMetric: '0 Token Cost / 100% Deterministic',
  },
  {
    id: 'analyze',
    number: '03',
    title: 'Attack Surface Triage',
    agent: 'AgentID.TRIAGE',
    capability: 'finding.triage',
    icon: SlidersHorizontal,
    telemetry: 'Correlating candidate findings with CWE-89, CWE-502, CWE-798 taxonomy...',
    outputPreview: 'Prioritized P1 (SQLi AST taint) & P1 (Insecure pickle session). High blast radius flagged.',
    keyMetric: 'Severity Matrix Weighted',
  },
  {
    id: 'reason',
    number: '04',
    title: 'LLM Reasoning & Diff Generation',
    agent: 'AgentID.REASONING',
    capability: 'patch.reasoning',
    icon: BrainCircuit,
    telemetry: 'Groq Llama-3.3-70B confirming exploitability & assembling minimal unified git diff...',
    outputPreview: 'Confirmed vulnerable code in src/database.py:42. Proposing parameterized query replacement.',
    keyMetric: 'Zero Hallucination Filter',
  },
  {
    id: 'patch',
    number: '05',
    title: 'Sandbox Validation Loop',
    agent: 'AgentID.REASONING ↔ DETECTION',
    capability: 'rule.recheck',
    icon: ShieldCheck,
    telemetry: 'Cloning code to /tmp/sandbox_0941. Applying patch diff. Requesting rule.recheck on peer bus...',
    outputPreview: 'DETECT confirmed: 0 matches remaining for RULE-PY-SQLI-AST. Sandbox test suite passed (2/2).',
    keyMetric: '100% Empirical Fix Guarantee',
  },
  {
    id: 'report',
    number: '06',
    title: 'Cryptographic Audit Seal',
    agent: 'AgentID.REPORTING',
    capability: 'report.render',
    icon: FileKey2,
    telemetry: 'Computing HMAC-SHA256 signature chain across all 24 state transitions and run salt...',
    outputPreview: 'Rendered report_llm.md sealed with report_llm.md.integrity.json. Cryptographic audit verified.',
    keyMetric: 'Tamper-Proof Audit Trail',
  },
];

export default function PinnedPipeline() {
  const containerRef = useRef<HTMLDivElement>(null);
  const pinRef = useRef<HTMLDivElement>(null);
  const pathRef = useRef<SVGPathElement>(null);
  const packetRef = useRef<SVGCircleElement>(null);
  const [activeStage, setActiveStage] = useState(0);
  const activeStageRef = useRef(0);

  useGSAP(
    () => {
      const container = containerRef.current;
      const pin = pinRef.current;
      const path = pathRef.current;
      const packet = packetRef.current;
      if (!container || !pin) return;

      const isReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      if (isReduced) return;

      const mm = gsap.matchMedia();

      mm.add('(min-width: 769px)', () => {
        const totalStages = STAGES.length;
        // Cache path length once to eliminate layout thrashing
        const pathLength = path ? path.getTotalLength() : 0;

        const tl = gsap.timeline({
          scrollTrigger: {
            trigger: container,
            start: 'top top',
            end: `+=${window.innerHeight * 3.5}`,
            pin: pin,
            scrub: 0.5,
            anticipatePin: 1,
            onUpdate: (self) => {
              const progress = self.progress;
              const stageIdx = Math.min(
                totalStages - 1,
                Math.floor(progress * totalStages)
              );
              // Only trigger state update when stage index actually changes
              if (stageIdx !== activeStageRef.current) {
                activeStageRef.current = stageIdx;
                setActiveStage(stageIdx);
              }

              // Directly update SVG attributes without GSAP tween allocation
              if (packet && path && pathLength > 0) {
                const point = path.getPointAtLength(progress * pathLength);
                packet.setAttribute('cx', point.x.toFixed(2));
                packet.setAttribute('cy', point.y.toFixed(2));
              }
            },
          },
        });

        return () => {
          tl.kill();
        };
      });

      return () => mm.revert();
    },
    { scope: containerRef }
  );

  const current = STAGES[activeStage] || STAGES[0];
  const Icon = current.icon;

  return (
    <div
      ref={containerRef}
      id="pipeline"
      className="relative w-full h-auto md:h-[240vh]"
    >
      <div
        ref={pinRef}
        className="w-full md:h-screen flex flex-col justify-center px-4 sm:px-6 py-12 md:py-0 overflow-hidden"
      >
        <div className="max-w-6xl mx-auto w-full">
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-end justify-between mb-8 pb-4 border-b border-hairline">
            <div>
              <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-text-primary">
                Ingest to report. <span className="font-serif italic font-normal">Step by step.</span>
              </h2>
            </div>
            <div className="mt-2 md:mt-0 font-mono text-sm text-text-muted">
              Stage <span className="text-signal font-semibold">{current.number}</span> of 06 ·{' '}
              <span className="text-text-primary font-medium">{current.title}</span>
            </div>
          </div>

          {/* Interactive DrawSVG Conduit & Stage Rail */}
          <div className="relative mb-8 hidden md:block">
            <svg
              viewBox="0 0 900 60"
              fill="none"
              className="w-full h-12 overflow-visible"
            >
              <path
                ref={pathRef}
                d="M 20 30 L 880 30"
                stroke="rgba(255, 255, 255, 0.12)"
                strokeWidth="2"
                strokeDasharray="4 4"
              />
              <circle
                ref={packetRef}
                cx="20"
                cy="30"
                r="6"
                fill="#C6FF3D"
              />
            </svg>

            <div className="flex justify-between items-center px-4 -mt-9">
              {STAGES.map((stage, idx) => (
                <button
                  key={stage.id}
                  onClick={() => setActiveStage(idx)}
                  className={`flex flex-col items-center transition-all ${
                    idx === activeStage
                      ? 'scale-110 text-signal'
                      : idx < activeStage
                      ? 'text-text-primary opacity-80'
                      : 'text-text-muted opacity-40'
                  }`}
                >
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center font-mono text-xs border ${
                      idx === activeStage
                        ? 'bg-signal/20 border-signal text-signal font-bold'
                        : 'bg-surface border-line'
                    }`}
                  >
                    {stage.number}
                  </div>
                  <span className="text-xs font-mono mt-1 tracking-tight">
                    {stage.title.split(' ')[0]}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Active Stage Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 bg-surface border border-line rounded-lg p-6 sm:p-8 relative">
            <div className="lg:col-span-7 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded bg-signal/10 border border-signal/30 flex items-center justify-center text-signal">
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <div className="font-mono text-xs text-text-muted">
                    Capability: <span className="text-text-primary font-medium">{current.capability}</span>
                  </div>
                  <div className="font-mono text-xs text-signal font-semibold">
                    {current.agent}
                  </div>
                </div>
              </div>

              <h3 className="text-2xl font-semibold text-text-primary tracking-tight">
                {current.title}
              </h3>

              <p className="text-base text-text-secondary leading-relaxed">
                {current.outputPreview}
              </p>

              <div className="pt-2 text-xs text-text-muted flex items-center gap-2 font-mono">
                <span className="w-2 h-2 rounded-full bg-signal" />
                <span>Metric: {current.keyMetric}</span>
              </div>
            </div>

            {/* Live Telemetry Panel */}
            <div className="lg:col-span-5 bg-canvas border border-line rounded p-5 font-mono text-xs flex flex-col justify-between">
              <div className="space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-hairline text-text-muted text-xs">
                  <span>A2A Telemetry</span>
                  <span className="text-signal font-medium">STATUS: 200 OK</span>
                </div>
                <div className="text-text-secondary text-xs leading-relaxed">
                  &gt; {current.telemetry}
                </div>
                <div className="text-signal/90 text-xs leading-relaxed bg-signal/5 p-3 rounded border border-signal/15">
                  payload.status = VERIFIED_PASS<br />
                  capability.lookup = &quot;{current.capability}&quot;<br />
                  agent.bus.state = &quot;TRANSITION_OK&quot;
                </div>
              </div>

              <div className="text-xs text-text-muted pt-3 border-t border-hairline">
                HMAC Salt: <span className="text-text-primary">salt_a849f10928374a</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
