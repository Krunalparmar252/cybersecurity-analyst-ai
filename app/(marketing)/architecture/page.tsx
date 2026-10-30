'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Workflow,
  Cpu,
  Layers,
  ArrowRight,
  ShieldCheck,
  FileCode,
  CheckCircle2,
  Terminal,
  Activity,
  X,
} from 'lucide-react';
import { api } from '@/lib/api';
import { SystemModule } from '@/lib/types';
import Reveal from '@/components/motion/Reveal';

export default function ArchitecturePage() {
  const [modules, setModules] = useState<SystemModule[]>([]);
  const [selectedModule, setSelectedModule] = useState<SystemModule | null>(null);

  useEffect(() => {
    async function load() {
      const data = await api.getSystemModules();
      setModules(data);
      if (data.length > 0) setSelectedModule(data[0]);
    }
    load();
  }, []);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-12 space-y-10">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-hairline">
        <div>
          <div className="font-mono text-xs text-signal tracking-widest uppercase mb-1">
            AGENT-TO-AGENT (A2A) CAPABILITY BUS // INTERACTIVE ARCHITECTURE
          </div>
          <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight text-text-primary">
            Autonomous Pipeline Specification
          </h1>
          <p className="mt-2 text-xs sm:text-sm text-text-secondary font-mono leading-relaxed max-w-2xl">
            Agents never directly invoke or import one another. All communication occurs over a typed,
            HMAC-signed message bus using dynamic capability discovery. Click any node to inspect contracts.
          </p>
        </div>

        <Link
          href="/dashboard"
          className="px-4 py-2 bg-signal text-canvas font-mono text-xs font-semibold rounded hover:bg-signal-hover transition-colors flex items-center gap-1.5 self-start"
        >
          <span>Open Cockpit</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>

      {/* Interactive System Architecture Canvas */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Interactive Node Diagram */}
        <div className="lg:col-span-8 bg-surface border border-line rounded-xl p-6 sm:p-8 font-mono relative overflow-hidden shadow-2xl">
          <div className="flex items-center justify-between pb-4 mb-6 border-b border-hairline text-xs text-text-muted">
            <span className="text-text-primary font-medium flex items-center gap-2">
              <Workflow className="w-4 h-4 text-signal" />
              TOPOLOGY: ZERO-IMPORT CAPABILITY BUS
            </span>
            <span className="text-signal text-[11px]">Click module to inspect</span>
          </div>

          {/* Orchestrator Master Node */}
          <div className="mb-8 p-4 bg-canvas border border-line rounded-lg text-center max-w-md mx-auto relative z-10">
            <div className="text-[10px] text-signal font-semibold tracking-wider uppercase mb-1">
              COORDINATION LAYER
            </div>
            <div className="text-sm font-bold text-text-primary">
              Orchestrator: pipeline.py / graph.py
            </div>
            <div className="text-[11px] text-text-muted mt-1">
              Linear State Machine or LangGraph Directed Acyclic Graph
            </div>
          </div>

          {/* SVG Animated Bus Conduits */}
          <svg viewBox="0 0 600 240" fill="none" className="w-full h-44 my-2 overflow-visible">
            {/* Bus Central Trunk */}
            <path
              d="M 50 120 L 550 120"
              stroke="#C6FF3D"
              strokeWidth="2"
              strokeDasharray="6 6"
              className="animate-pulse-subtle"
            />
            {/* Connection Verticals */}
            <line x1="80" y1="20" x2="80" y2="120" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5" />
            <line x1="180" y1="20" x2="180" y2="120" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5" />
            <line x1="300" y1="120" x2="300" y2="220" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5" />
            <line x1="420" y1="20" x2="420" y2="120" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5" />
            <line x1="520" y1="120" x2="520" y2="220" stroke="rgba(255,255,255,0.2)" strokeWidth="1.5" />
            {/* Bus Packet */}
            <circle cx="300" cy="120" r="5" fill="#C6FF3D" />
          </svg>

          {/* Modules Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 relative z-10 text-xs">
            {modules.map((mod) => {
              const isSelected = selectedModule?.id === mod.id;
              return (
                <div
                  key={mod.id}
                  onClick={() => setSelectedModule(mod)}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-signal/15 border-signal text-signal ring-1 ring-signal shadow-lg'
                      : 'bg-canvas/60 border-line text-text-primary hover:border-line-strong'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-xs">{mod.code}</span>
                    <span className="text-[10px] text-text-muted">{mod.latencyAvgMs}ms</span>
                  </div>
                  <div className="font-medium text-[11px] truncate">{mod.name.split(' ')[0]}</div>
                  <div className="text-[10px] text-text-muted truncate mt-1">{mod.capability}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Node Inspector Drawer */}
        <div className="lg:col-span-4 bg-surface border border-line rounded-xl p-6 font-mono text-xs flex flex-col justify-between shadow-xl">
          {selectedModule ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-hairline">
                <div>
                  <span className="text-[10px] text-signal font-semibold uppercase">
                    MODULE SPECIFICATION
                  </span>
                  <h3 className="text-base font-bold text-text-primary mt-0.5">
                    {selectedModule.name}
                  </h3>
                </div>
                <span className="px-2 py-0.5 rounded bg-signal/20 text-signal border border-signal/30 text-[10px]">
                  {selectedModule.code}
                </span>
              </div>

              <div className="space-y-3 text-[11px]">
                <div>
                  <span className="text-text-muted block text-[10px] uppercase">CAPABILITY KEY</span>
                  <code className="text-signal bg-canvas px-2 py-0.5 rounded border border-line block mt-1">
                    {selectedModule.capability}
                  </code>
                </div>

                <div>
                  <span className="text-text-muted block text-[10px] uppercase">SOURCE MODULE FILE</span>
                  <code className="text-text-primary bg-canvas px-2 py-0.5 rounded border border-line block mt-1">
                    {selectedModule.sourceFile}
                  </code>
                </div>

                <div>
                  <span className="text-text-muted block text-[10px] uppercase">PRIMARY TECHNOLOGY</span>
                  <div className="text-text-secondary mt-0.5">{selectedModule.primaryTech}</div>
                </div>

                <div>
                  <span className="text-text-muted block text-[10px] uppercase">INPUT CONTRACT</span>
                  <p className="text-text-secondary mt-0.5 leading-relaxed">
                    {selectedModule.inputDescription}
                  </p>
                </div>

                <div>
                  <span className="text-text-muted block text-[10px] uppercase">OUTPUT ARTIFACT</span>
                  <p className="text-text-secondary mt-0.5 leading-relaxed">
                    {selectedModule.outputDescription}
                  </p>
                </div>

                <div>
                  <span className="text-text-muted block text-[10px] uppercase">DETERMINISTIC FALLBACK</span>
                  <p className="text-text-secondary mt-0.5 leading-relaxed">
                    {selectedModule.fallbackStrategy}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-text-muted">
              Select a module from the topology diagram to inspect its interface.
            </div>
          )}

          <div className="pt-4 mt-6 border-t border-hairline flex items-center justify-between text-[11px] text-text-muted">
            <span>Owner: <strong className="text-text-primary">{selectedModule?.owner || 'Team'}</strong></span>
            <span className="text-signal">Zero Direct Imports</span>
          </div>
        </div>
      </div>
    </div>
  );
}

