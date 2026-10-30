'use client';

import React from 'react';
import Link from 'next/link';
import { ArrowRight, ShieldCheck, Terminal, Cpu, CheckCircle2, Lock, GitBranch } from 'lucide-react';
import CountUp from '@/components/motion/CountUp';
import Magnetic from '@/components/motion/Magnetic';

export default function MetricsAndTeam() {
  const techStack = [
    'Python 3.12',
    'Tree-sitter AST',
    'Groq (Llama-3.3-70B)',
    'Claude 3.5 Sonnet',
    'LangGraph',
    'SQLite Taint Sinks',
    'HMAC-SHA256 Audit Chain',
    'Pydantic v2',
    'Click & Rich CLI',
    'Isolated Docker / Subprocess Sandbox',
  ];

  const teamMembers = [
    {
      name: 'Zeno',
      role: 'Lead Architect & Core Systems',
      modules: ['Repository Ingestion (`repo.ingest`)', 'Cryptographic Audit & Reporting (`report.render`)', 'A2A Protocol & Bus Architecture'],
      contribution: 'Designed the zero-import Agent-to-Agent message bus, Tree-sitter AST grammar pipeline, and the HMAC chained audit integrity sidecar format.',
    },
    {
      name: 'Sumit Trapasiya',
      role: 'Detection & Risk Engineering',
      modules: ['Deterministic Detection Engine (`rule.scan`)', 'Shannon Entropy Secret Masking', 'Triage & Risk Matrix (`finding.triage`)'],
      contribution: 'Engineered 32 deterministic AST taint rules in rules.yaml, in-flight secret masking at inception, and multi-variable CVSS attack surface scoring.',
    },
    {
      name: 'Rushi Divecha',
      role: 'Reasoning & Autonomous Patching',
      modules: ['LLM Reasoning & Diff Synthesis (`patch.reasoning`)', 'Ephemeral Sandbox Validation Harness', 'Exploit Verification Agent (`exploit.verify`)'],
      contribution: 'Created the ReAct LLM patch loop with zero-key fallback circuit breaker, isolated sandbox test harness, and active black-box exploit payload verification.',
    },
  ];

  return (
    <div className="w-full py-20 px-4 sm:px-6">
      <div className="max-w-6xl mx-auto space-y-24">
        {/* Metrics Counter Section */}
        <div>
          <div className="text-center max-w-xl mx-auto mb-14">
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-text-primary">
              Engineered for <span className="font-serif italic font-normal">provable reliability.</span>
            </h2>
            <p className="mt-3 text-base text-text-secondary leading-relaxed">
              Every metric reflects empirical execution in reproducible sandboxes, not synthetic simulations.
            </p>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
            <div className="p-6 bg-surface border border-line rounded-lg flex flex-col justify-between">
              <div>
                <div className="text-3xl sm:text-4xl font-semibold text-signal tracking-tight font-mono">
                  <CountUp end={0} suffix="%" />
                </div>
                <div className="text-sm font-semibold text-text-primary mt-2">
                  Zero Hallucinations
                </div>
              </div>
              <div className="text-xs text-text-secondary mt-3 leading-relaxed">
                100% of candidate findings originate from deterministic AST rules.
              </div>
            </div>

            <div className="p-6 bg-surface border border-line rounded-lg flex flex-col justify-between">
              <div>
                <div className="text-3xl sm:text-4xl font-semibold text-text-primary tracking-tight font-mono">
                  <CountUp end={142} suffix="ms" />
                </div>
                <div className="text-sm font-semibold text-text-primary mt-2">
                  AST Scan Latency
                </div>
              </div>
              <div className="text-xs text-text-secondary mt-3 leading-relaxed">
                32 rules evaluated across 1,840 lines with zero LLM token delay.
              </div>
            </div>

            <div className="p-6 bg-surface border border-line rounded-lg flex flex-col justify-between">
              <div>
                <div className="text-3xl sm:text-4xl font-semibold text-[#5BC0FF] tracking-tight font-mono">
                  <CountUp end={100} suffix="%" />
                </div>
                <div className="text-sm font-semibold text-text-primary mt-2">
                  Sandbox Verification
                </div>
              </div>
              <div className="text-xs text-text-secondary mt-3 leading-relaxed">
                Every suggested diff is re-tested against DETECT in an isolated clone.
              </div>
            </div>

            <div className="p-6 bg-surface border border-line rounded-lg flex flex-col justify-between">
              <div>
                <div className="text-3xl sm:text-4xl font-semibold text-text-primary tracking-tight font-mono">
                  <CountUp end={24} suffix=" hops" />
                </div>
                <div className="text-sm font-semibold text-text-primary mt-2">
                  Audit Chain Length
                </div>
              </div>
              <div className="text-xs text-text-secondary mt-3 leading-relaxed">
                Tamper-evident HMAC-SHA256 signature chain sealed with sidecar.
              </div>
            </div>
          </div>
        </div>

        {/* Tech Stack Marquee */}
        <div className="py-10 border-y border-hairline overflow-hidden">
          <div className="text-sm font-medium text-text-primary text-center mb-6">
            Core Foundation · Zero Third-Party Cloud Lock-In
          </div>
          <div className="flex gap-3 items-center justify-center flex-wrap max-w-4xl mx-auto">
            {techStack.map((tech) => (
              <span
                key={tech}
                className="font-mono text-xs px-3.5 py-1.5 rounded bg-surface border border-line text-text-secondary hover:text-text-primary hover:border-line-strong transition-colors"
              >
                {tech}
              </span>
            ))}
          </div>
        </div>

        {/* Team Module Ownership Section */}
        <div>
          <div className="text-center max-w-xl mx-auto mb-14">
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-text-primary">
              Module ownership &amp; <span className="font-serif italic font-normal">architecture.</span>
            </h2>
            <p className="mt-3 text-base text-text-secondary leading-relaxed">
              Final Year Project development team with dedicated agent subsystem accountability.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {teamMembers.map((member) => (
              <div
                key={member.name}
                className="bg-surface border border-line rounded-lg p-6 flex flex-col justify-between hover:border-line-strong transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between pb-3 border-b border-hairline mb-4">
                    <span className="text-text-primary font-semibold text-lg">{member.name}</span>
                    <span className="text-xs font-mono text-signal px-2 py-0.5 rounded bg-signal/10 border border-signal/20">
                      Module Owner
                    </span>
                  </div>

                  <div className="text-sm text-text-primary font-medium mb-4">{member.role}</div>

                  <div className="space-y-2 mb-6 text-xs text-text-muted">
                    <div className="text-xs font-medium text-text-secondary uppercase">Assigned Modules:</div>
                    {member.modules.map((m) => (
                      <div key={m} className="flex items-start gap-2 text-text-secondary font-mono">
                        <span className="text-signal">▪</span>
                        <span className="text-xs leading-tight">{m}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="pt-4 border-t border-hairline text-xs text-text-secondary leading-relaxed">
                  {member.contribution}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Final CTA Banner */}
        <div className="relative rounded-xl border border-line bg-surface p-8 sm:p-14 text-center overflow-hidden">
          <div className="relative z-10 max-w-2xl mx-auto space-y-6">
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-text-primary">
              Zero hallucination. <span className="font-serif italic font-normal">Provable security.</span>
            </h2>
            <p className="text-base text-text-secondary max-w-lg mx-auto leading-relaxed">
              Run offline with deterministic rules, or engage Groq and Claude with empirical sandbox patch verification.
            </p>

            <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-4">
              <Magnetic strength={0.25}>
                <Link
                  href="/dashboard"
                  className="px-6 py-3 bg-signal text-canvas font-medium text-sm rounded hover:bg-signal-hover transition-colors flex items-center gap-2"
                >
                  <span>Launch Live Security Console</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </Magnetic>

              <Link
                href="/architecture"
                className="px-6 py-3 bg-canvas border border-line text-text-primary text-sm hover:border-line-strong rounded transition-colors"
              >
                View System Architecture
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
