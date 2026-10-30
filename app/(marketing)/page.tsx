'use client';

import React from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { ArrowRight, ChevronDown } from 'lucide-react';
import SplitHeading from '@/components/motion/SplitHeading';
import Magnetic from '@/components/motion/Magnetic';
import Reveal from '@/components/motion/Reveal';

const PinnedPipeline = dynamic(() => import('@/components/scenes/PinnedPipeline'), {
  loading: () => <div className="w-full min-h-[50vh] bg-canvas" />,
});

const PrincipleCompare = dynamic(() => import('@/components/scenes/PrincipleCompare'), {
  loading: () => <div className="w-full min-h-[50vh] bg-canvas" />,
});

const LiveCodeDemo = dynamic(() => import('@/components/scenes/LiveCodeDemo'), {
  loading: () => <div className="w-full min-h-[50vh] bg-canvas" />,
});

const MetricsAndTeam = dynamic(() => import('@/components/scenes/MetricsAndTeam'), {
  loading: () => <div className="w-full min-h-[40vh] bg-canvas" />,
});

// Lazy-load the Three.js R3F Canvas scene on client only
const HeroScene = dynamic(() => import('@/components/scenes/HeroScene'), {
  ssr: false,
  loading: () => (
    <div className="absolute inset-0 flex items-center justify-center opacity-30">
      <div className="w-48 h-48 rounded-full border border-signal/40 animate-pulse-subtle" />
    </div>
  ),
});

export default function LandingPage() {
  return (
    <div className="w-full flex flex-col items-center">
      {/* Hero Section */}
      <section className="relative w-full min-h-[92vh] flex flex-col items-center justify-center px-4 sm:px-6 overflow-hidden border-b border-hairline">
        {/* Three.js R3F Particle Node Scene (Desktop) / Background Ambient */}
        <HeroScene />

        {/* Ambient Grid Accent */}
        <div
          className="absolute inset-0 pointer-events-none opacity-20"
          style={{
            backgroundImage: `radial-gradient(rgba(255, 255, 255, 0.08) 1px, transparent 1px)`,
            backgroundSize: '36px 36px',
          }}
        />

        <div className="relative z-10 max-w-4xl mx-auto text-center flex flex-col items-center space-y-7 pt-16 pb-20">
          {/* Primary Split Headline with Instrument Serif italic emphasis */}
          <SplitHeading
            text="Rules find. AI explains."
            italicWord="explains"
            as="h1"
            className="text-4xl sm:text-6xl md:text-7xl font-semibold tracking-tight text-text-primary"
            delay={0.1}
          />

          {/* Clean 18px Supporting Sentence */}
          <Reveal delay={0.25}>
            <p className="max-w-2xl text-base sm:text-lg text-text-secondary leading-relaxed mx-auto">
              Deterministic Tree-sitter AST queries originate every candidate finding.
              The LLM acts solely as a verification engine — confirming exploitability,
              generating minimal diffs, and proving immunity inside an isolated sandbox.
            </p>
          </Reveal>

          {/* Action CTAs */}
          <Reveal delay={0.35}>
            <div className="flex flex-col sm:flex-row items-center gap-4 pt-3">
              <Magnetic strength={0.25}>
                <Link
                  href="/dashboard"
                  className="px-6 py-3 bg-signal text-canvas font-medium text-sm rounded hover:bg-signal-hover transition-colors flex items-center gap-2"
                >
                  <span>Launch Live Security Cockpit</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>
              </Magnetic>

              <Magnetic strength={0.2}>
                <Link
                  href="/architecture"
                  className="px-6 py-3 bg-surface border border-line text-text-primary text-sm hover:border-line-strong rounded transition-colors"
                >
                  Inspect A2A Architecture
                </Link>
              </Magnetic>
            </div>
          </Reveal>

          {/* Scroll Down Indicator */}
          <Reveal delay={0.5}>
            <div className="pt-8 text-text-muted flex flex-col items-center gap-2 text-xs">
              <span>Scroll to inspect pipeline</span>
              <ChevronDown className="w-4 h-4 animate-bounce text-signal" />
            </div>
          </Reveal>
        </div>
      </section>

      {/* Pinned Pipeline Scrub Scene */}
      <PinnedPipeline />

      {/* Core Principle Comparison with Draggable Slider */}
      <section id="principles" className="w-full px-4 sm:px-6">
        <PrincipleCompare />
      </section>

      {/* Live Vulnerable Code Taint & Sandbox Diff Demo */}
      <LiveCodeDemo />

      {/* Metrics, Tech Stack Marquee, Team Module Attribution & Final CTA */}
      <MetricsAndTeam />
    </div>
  );
}
