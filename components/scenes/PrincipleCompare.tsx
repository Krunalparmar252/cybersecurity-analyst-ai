'use client';

import React, { useRef, useState } from 'react';
import { gsap, useGSAP } from '@/lib/motion';
import { Draggable } from 'gsap/Draggable';

if (typeof window !== 'undefined') {
  gsap.registerPlugin(Draggable);
}
import { ArrowLeftRight, CheckCircle2 } from 'lucide-react';

export default function PrincipleCompare() {
  const containerRef = useRef<HTMLDivElement>(null);
  const handleRef = useRef<HTMLDivElement>(null);
  const dividerRef = useRef<HTMLDivElement>(null);
  const rightPanelRef = useRef<HTMLDivElement>(null);
  const [sliderPos, setSliderPos] = useState(50); // percentage
  const [mobileTab, setMobileTab] = useState<'rules' | 'llm'>('rules');

  useGSAP(
    () => {
      const handle = handleRef.current;
      const container = containerRef.current;
      const rightPanel = rightPanelRef.current;
      if (!handle || !container || !rightPanel) return;

      const containerWidth = container.offsetWidth;

      const draggable = Draggable.create(handle, {
        type: 'x',
        bounds: container,
        edgeResistance: 0.85,
        onDrag: function () {
          const x = this.x;
          const pct = Math.max(10, Math.min(90, (x / containerWidth) * 100));
          setSliderPos(pct);
          gsap.set(rightPanel, {
            clipPath: `polygon(${pct}% 0, 100% 0, 100% 100%, ${pct}% 100%)`,
          });
        },
      })[0];

      return () => {
        draggable.kill();
      };
    },
    { scope: containerRef }
  );

  return (
    <div className="w-full py-20">
      <div className="text-center max-w-2xl mx-auto mb-12">
        <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-text-primary">
          Rule engine originates. <span className="font-serif italic font-normal">AI validates.</span>
        </h2>
        <p className="mt-3 text-base text-text-secondary leading-relaxed">
          LLMs never guess or hallucinate security flaws in this architecture. Every single finding
          must first trigger a deterministic AST or entropy rule.
        </p>
      </div>

      {/* Mobile Stacking / Switcher (avoids clip-path overlap on small screens) */}
      <div className="sm:hidden space-y-4">
        <div className="flex rounded bg-surface p-1 border border-line">
          <button
            onClick={() => setMobileTab('rules')}
            className={`flex-1 py-2 text-xs rounded font-medium transition-colors ${
              mobileTab === 'rules' ? 'bg-canvas text-signal' : 'text-text-muted'
            }`}
          >
            Deterministic Rule Engine
          </button>
          <button
            onClick={() => setMobileTab('llm')}
            className={`flex-1 py-2 text-xs rounded font-medium transition-colors ${
              mobileTab === 'llm' ? 'bg-canvas text-[#5BC0FF]' : 'text-text-muted'
            }`}
          >
            LLM Reasoning &amp; Patch
          </button>
        </div>

        {mobileTab === 'rules' ? (
          <div className="p-6 bg-surface rounded-lg border border-line space-y-4">
            <h3 className="text-xl font-semibold text-text-primary">
              Rule engine originates every finding
            </h3>
            <p className="text-sm text-text-secondary leading-relaxed">
              Tree-sitter AST queries and Shannon entropy scanners analyze code structures deterministically. Zero network calls, zero token costs, zero hallucinations.
            </p>
            <div className="space-y-2 text-sm">
              <div className="flex items-start gap-2 text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-signal shrink-0 mt-0.5" />
                <span>Tree-sitter AST parse across 1,840 lines in 142ms</span>
              </div>
              <div className="flex items-start gap-2 text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-signal shrink-0 mt-0.5" />
                <span>Secrets masked at inception before prompt assembly</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-6 bg-surface rounded-lg border border-line space-y-4">
            <h3 className="text-xl font-semibold text-text-primary">
              LLM confirms, scores &amp; patches
            </h3>
            <p className="text-sm text-text-secondary leading-relaxed">
              Llama-3.3-70B / Claude analyzes candidate findings, evaluates exploitability, writes non-regressive diffs, and triggers automated sandbox re-verification.
            </p>
            <div className="space-y-2 text-sm">
              <div className="flex items-start gap-2 text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-[#5BC0FF] shrink-0 mt-0.5" />
                <span>Discards false positives with explicit reasoning traces</span>
              </div>
              <div className="flex items-start gap-2 text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-[#5BC0FF] shrink-0 mt-0.5" />
                <span>Re-executes DETECT rule: 0 matches required for approval</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Desktop Interactive Split Compare Box */}
      <div
        ref={containerRef}
        className="hidden sm:block relative w-full max-w-5xl mx-auto h-[400px] rounded-lg border border-line bg-surface overflow-hidden select-none"
      >
        {/* Left Side: Rule Engine */}
        <div className="absolute inset-0 p-8 sm:p-10 flex flex-col justify-between bg-surface">
          <div>
            <div className="flex items-center gap-2 text-xs text-text-muted mb-2 font-mono">
              <span className="w-2 h-2 rounded-full bg-signal" />
              <span>DETERMINISTIC SUBSYSTEM</span>
            </div>
            <h3 className="text-2xl font-semibold text-text-primary tracking-tight">
              Rule engine originates every finding
            </h3>
            <p className="mt-2 text-sm text-text-secondary max-w-md leading-relaxed">
              Tree-sitter AST queries and Shannon entropy scanners analyze code structures deterministically.
              Zero network calls, zero token costs, zero hallucinations.
            </p>

            <div className="mt-6 space-y-2.5 max-w-sm text-sm">
              <div className="flex items-start gap-2.5 text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-signal shrink-0 mt-0.5" />
                <span>Tree-sitter grammar parse across 1,840 lines in 142ms</span>
              </div>
              <div className="flex items-start gap-2.5 text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-signal shrink-0 mt-0.5" />
                <span>Secrets masked at inception before LLM prompt assembly</span>
              </div>
              <div className="flex items-start gap-2.5 text-text-primary">
                <CheckCircle2 className="w-4 h-4 text-signal shrink-0 mt-0.5" />
                <span>Provides <code className="font-mono text-xs text-signal">rule.recheck</code> capability to verify fixes</span>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-hairline text-xs text-text-muted">
            <span className="font-mono">Capability: rule.scan</span>
            <span className="text-signal font-medium">Deterministic Ground Truth</span>
          </div>
        </div>

        {/* Right Side: LLM Reasoning Layer */}
        <div
          ref={rightPanelRef}
          className="absolute inset-0 p-8 sm:p-10 flex flex-col justify-between bg-surface-subtle"
          style={{
            clipPath: `polygon(${sliderPos}% 0, 100% 0, 100% 100%, ${sliderPos}% 100%)`,
          }}
        >
          <div className="ml-auto text-right max-w-md">
            <div className="flex items-center justify-end gap-2 text-xs text-text-muted mb-2 font-mono">
              <span>REASONING SUBSYSTEM</span>
              <span className="w-2 h-2 rounded-full bg-[#5BC0FF]" />
            </div>
            <h3 className="text-2xl font-semibold text-text-primary tracking-tight">
              LLM confirms, scores &amp; patches
            </h3>
            <p className="mt-2 text-sm text-text-secondary leading-relaxed">
              Llama-3.3-70B / Claude analyzes candidate findings, evaluates exploitability, writes non-regressive
              diffs, and triggers automated sandbox re-verification.
            </p>

            <div className="mt-6 space-y-2.5 text-right text-sm">
              <div className="flex items-start justify-end gap-2.5 text-text-primary">
                <span>Discards false positives with explicit reasoning traces</span>
                <CheckCircle2 className="w-4 h-4 text-[#5BC0FF] shrink-0 mt-0.5" />
              </div>
              <div className="flex items-start justify-end gap-2.5 text-text-primary">
                <span>Clones repository to isolated sandbox for patch testing</span>
                <CheckCircle2 className="w-4 h-4 text-[#5BC0FF] shrink-0 mt-0.5" />
              </div>
              <div className="flex items-start justify-end gap-2.5 text-text-primary">
                <span>Re-executes DETECT rule: 0 matches required for approval</span>
                <CheckCircle2 className="w-4 h-4 text-[#5BC0FF] shrink-0 mt-0.5" />
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-hairline text-xs text-text-muted">
            <span className="text-[#5BC0FF] font-medium">Empirical Sandbox Loop</span>
            <span className="font-mono">Capability: patch.reasoning</span>
          </div>
        </div>

        {/* Draggable Divider Handle */}
        <div
          ref={dividerRef}
          className="absolute top-0 bottom-0 w-[1px] bg-signal pointer-events-none z-20"
          style={{ left: `${sliderPos}%` }}
        />
        <div
          ref={handleRef}
          className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 z-30 cursor-ew-resize flex items-center justify-center w-8 h-8 rounded-full bg-signal text-canvas shadow-lg"
          style={{ left: `${sliderPos}%` }}
          aria-label="Drag to compare rule engine vs LLM reasoning"
        >
          <ArrowLeftRight className="w-3.5 h-3.5" />
        </div>
      </div>
    </div>
  );
}
