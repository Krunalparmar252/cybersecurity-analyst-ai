'use client';

import React from 'react';
import { Check, ShieldAlert, Cpu, GitCommit, FileText, Activity } from 'lucide-react';

export interface Stage {
  id: string;
  name: string;
  capability: string;
  status: 'complete' | 'active' | 'pending';
}

interface StageRailProps {
  stages?: Stage[];
  activeStageIndex?: number;
  className?: string;
}

const DEFAULT_STAGES: Stage[] = [
  { id: 'ingest', name: '1. Ingest', capability: 'repo.ingest', status: 'complete' },
  { id: 'detect', name: '2. Detect', capability: 'rule.scan', status: 'complete' },
  { id: 'reason', name: '3. Reason', capability: 'patch.reasoning', status: 'active' },
  { id: 'exploit', name: '4. Exploit', capability: 'exploit.verify', status: 'pending' },
  { id: 'triage', name: '5. Triage', capability: 'finding.triage', status: 'pending' },
  { id: 'report', name: '6. Report', capability: 'report.render', status: 'pending' },
];

export default function StageRail({
  stages = DEFAULT_STAGES,
  activeStageIndex,
  className = '',
}: StageRailProps) {
  return (
    <div className={`w-full overflow-x-auto py-3 ${className}`}>
      <div className="flex items-center min-w-[620px] justify-between relative">
        {/* Track Line */}
        <div className="absolute left-6 right-6 top-1/2 -translate-y-1/2 h-[1px] bg-line z-0" />

        {stages.map((stage, idx) => {
          const isComplete = stage.status === 'complete';
          const isActive = stage.status === 'active';

          return (
            <div key={stage.id} className="relative z-10 flex flex-col items-center group">
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center font-mono text-xs border transition-all duration-300 ${
                  isComplete
                    ? 'bg-signal/20 border-signal text-signal'
                    : isActive
                    ? 'bg-canvas border-signal text-signal ring-2 ring-signal/30 animate-pulse-subtle'
                    : 'bg-surface border-line text-text-muted'
                }`}
              >
                {isComplete ? (
                  <Check className="w-3.5 h-3.5 stroke-[2.5]" />
                ) : (
                  <span>{idx + 1}</span>
                )}
              </div>

              <div className="mt-2 text-center">
                <div
                  className={`font-mono text-xs font-medium tracking-tight ${
                    isActive ? 'text-signal' : isComplete ? 'text-text-primary' : 'text-text-muted'
                  }`}
                >
                  {stage.name.replace(/^\d+\.\s*/, '')}
                </div>
                <div className="font-mono text-[10px] text-text-muted opacity-80">
                  {stage.capability}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

