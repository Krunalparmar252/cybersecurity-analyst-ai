'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Terminal, Search, Sun, Moon, ArrowRight, Github } from 'lucide-react';
import { useAppStore } from '@/lib/store';
import Magnetic from '@/components/motion/Magnetic';
import SmoothScroll from '@/components/motion/SmoothScroll';
import CustomCursor from '@/components/motion/CustomCursor';
import RouteTransition from '@/components/motion/RouteTransition';

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { theme, toggleTheme, setCommandPaletteOpen } = useAppStore();

  return (
    <SmoothScroll>
      <CustomCursor />
      <RouteTransition>
        <div className="min-h-screen flex flex-col bg-canvas text-text-primary selection:bg-signal selection:text-canvas">
          {/* Precision Top Bar */}
          <header className="sticky top-0 z-50 w-full bg-canvas/95 border-b border-hairline">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          {/* Brand Mark */}
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-5 h-5 border border-signal/60 flex items-center justify-center bg-signal/10 group-hover:border-signal transition-colors">
              <div className="w-1.5 h-1.5 bg-signal" />
            </div>
            <span className="font-mono text-xs tracking-wider uppercase text-text-primary font-medium">
              Analyst <span className="text-signal">AI</span>
            </span>
            <span className="hidden sm:inline-block text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface border border-line text-text-muted">
              v2.1·FYP
            </span>
          </Link>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center gap-6 font-mono text-xs text-text-secondary">
            <Link
              href="/#pipeline"
              className="hover:text-text-primary transition-colors"
            >
              Pipeline
            </Link>
            <Link
              href="/#principles"
              className="hover:text-text-primary transition-colors"
            >
              Principles
            </Link>
            <Link
              href="/#demo"
              className="hover:text-text-primary transition-colors"
            >
              Live Demo
            </Link>
            <Link
              href="/architecture"
              className={`hover:text-text-primary transition-colors ${
                pathname === '/architecture' ? 'text-signal' : ''
              }`}
            >
              Architecture
            </Link>
            <Link
              href="/dashboard"
              className="hover:text-text-primary transition-colors"
            >
              Dashboard
            </Link>
          </nav>

          {/* Action Tools */}
          <div className="flex items-center gap-2.5">
            {/* Search Command Palette Trigger */}
            <button
              onClick={() => setCommandPaletteOpen(true)}
              className="hidden sm:flex items-center gap-2 px-2.5 py-1 text-xs font-mono text-text-muted bg-surface border border-line hover:border-line-strong rounded transition-colors"
              title="Search commands (⌘K)"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Search</span>
              <kbd className="text-[10px] bg-canvas px-1 rounded border border-line">⌘K</kbd>
            </button>

            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className="w-8 h-8 flex items-center justify-center rounded text-text-muted hover:text-text-primary hover:bg-surface border border-transparent hover:border-line transition-colors"
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
            </button>

            {/* Launch Console CTA */}
            <Magnetic strength={0.2}>
              <Link
                href="/dashboard"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-signal text-canvas font-mono text-xs font-medium rounded hover:bg-signal-hover transition-colors"
              >
                <span>Console</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            </Magnetic>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 w-full">{children}</main>

      {/* Minimal Editorial Footer */}
      <footer className="border-t border-hairline bg-surface/40 py-12 px-4 sm:px-6">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-6 font-mono text-xs text-text-muted">
          <div>
            <div className="text-text-primary font-medium tracking-tight mb-1">
              Autonomous Cybersecurity Analyst AI
            </div>
            <p className="max-w-md text-[11px] leading-relaxed">
              Deterministic AST taint & entropy detection with LLM confirmation, scoring, and empirical sandbox validation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-6 text-[11px]">
            <Link href="/architecture" className="hover:text-text-primary transition-colors">
              System Specification
            </Link>
            <Link href="/findings" className="hover:text-text-primary transition-colors">
              CWE Taxonomy
            </Link>
            <Link href="/reports" className="hover:text-text-primary transition-colors">
              Audit Chains
            </Link>
            <span>Team: Zeno · Sumit Trapasiya · Rushi Divecha</span>
          </div>
        </div>
      </footer>
    </div>
      </RouteTransition>
    </SmoothScroll>
  );
}

