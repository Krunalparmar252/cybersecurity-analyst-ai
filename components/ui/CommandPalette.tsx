'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { Search, ShieldAlert, Cpu, Terminal, FileCode, Sliders, Moon, Sun, ArrowRight, CornerDownLeft } from 'lucide-react';
import { useAppStore } from '@/lib/store';
import { MOCK_FINDINGS, MOCK_SCANS } from '@/data/mock/security-data';

export default function CommandPalette() {
  const router = useRouter();
  const { commandPaletteOpen, setCommandPaletteOpen, toggleTheme, theme } = useAppStore();
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandPaletteOpen(!commandPaletteOpen);
      }
      if (e.key === 'Escape' && commandPaletteOpen) {
        setCommandPaletteOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [commandPaletteOpen, setCommandPaletteOpen]);

  useEffect(() => {
    if (commandPaletteOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
      setSelectedIndex(0);
    } else {
      setQuery('');
    }
  }, [commandPaletteOpen]);

  if (!commandPaletteOpen) return null;

  // Static commands
  const baseActions = [
    { id: 'act-dash', title: 'Go to Dashboard', category: 'Navigation', icon: Cpu, action: () => router.push('/dashboard') },
    { id: 'act-scan-new', title: 'Launch New Scan', category: 'Actions', icon: Terminal, action: () => router.push('/scan/new') },
    { id: 'act-findings', title: 'View Vulnerability Findings', category: 'Navigation', icon: ShieldAlert, action: () => router.push('/findings') },
    { id: 'act-traffic', title: 'Traffic & Anomaly Telemetry', category: 'Navigation', icon: Sliders, action: () => router.push('/traffic') },
    { id: 'act-reports', title: 'Audit Reports & Cryptographic Seals', category: 'Navigation', icon: FileCode, action: () => router.push('/reports') },
    { id: 'act-arch', title: 'Interactive System Architecture', category: 'Navigation', icon: Cpu, action: () => router.push('/architecture') },
    { id: 'act-settings', title: 'Engine & Provider Settings', category: 'Navigation', icon: Sliders, action: () => router.push('/settings') },
    { id: 'act-theme', title: `Toggle Theme (${theme === 'dark' ? 'Light' : 'Dark'})`, category: 'Preferences', icon: theme === 'dark' ? Sun : Moon, action: () => toggleTheme() },
  ];

  // Dynamic search items from findings & scans
  const dynamicItems = [
    ...MOCK_FINDINGS.map((f) => ({
      id: f.id,
      title: `${f.id} — ${f.ruleTitle} (${f.file}:${f.lineStart})`,
      category: 'Vulnerabilities',
      icon: ShieldAlert,
      action: () => router.push(`/findings/${f.id}`),
    })),
    ...MOCK_SCANS.map((s) => ({
      id: s.id,
      title: `Scan ${s.id} [${s.targetRepo}] (${s.findingsCount.total} findings)`,
      category: 'Scans',
      icon: Terminal,
      action: () => router.push(`/scan/${s.id}`),
    })),
  ];

  const allItems = [...baseActions, ...dynamicItems];
  const filtered = query.trim()
    ? allItems.filter(
        (it) =>
          it.title.toLowerCase().includes(query.toLowerCase()) ||
          it.category.toLowerCase().includes(query.toLowerCase())
      )
    : baseActions;

  const handleSelect = (idx: number) => {
    const item = filtered[idx];
    if (item) {
      setCommandPaletteOpen(false);
      item.action();
    }
  };

  const handleKeyNavigation = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % filtered.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filtered.length) % filtered.length);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      handleSelect(selectedIndex);
    }
  };

  return (
    <div
      className="fixed inset-0 z-[9995] bg-black/70 backdrop-blur-sm flex items-start justify-center pt-24 px-4"
      onClick={() => setCommandPaletteOpen(false)}
    >
      <div
        className="w-full max-w-xl bg-surface border border-line rounded-lg shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3.5 border-b border-line bg-canvas/40">
          <Search className="w-4 h-4 text-text-muted mr-3 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command, CVE, file or rule ID... (e.g. SQLi, AST, scan)"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleKeyNavigation}
            className="w-full bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none font-mono"
          />
          <kbd className="hidden sm:inline-block px-1.5 py-0.5 text-[10px] font-mono bg-surface-subtle border border-line text-text-muted rounded">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto py-2 px-1">
          {filtered.length === 0 ? (
            <div className="py-8 text-center text-xs font-mono text-text-muted">
              No matching modules, findings or commands found.
            </div>
          ) : (
            filtered.map((item, index) => {
              const Icon = item.icon;
              const isSelected = index === selectedIndex;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelect(index)}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded text-left transition-colors font-mono text-xs ${
                    isSelected
                      ? 'bg-signal/10 text-signal border border-signal/20'
                      : 'text-text-primary hover:bg-surface-subtle border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <Icon className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'text-signal' : 'text-text-muted'}`} />
                    <span className="truncate">{item.title}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    <span className="text-[10px] text-text-muted">{item.category}</span>
                    {isSelected && <CornerDownLeft className="w-3 h-3 text-signal" />}
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="px-4 py-2 border-t border-line bg-canvas/30 flex items-center justify-between text-[11px] font-mono text-text-muted">
          <div className="flex items-center gap-3">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
            <span>ESC Dismiss</span>
          </div>
          <span className="text-signal/80">Autonomous Security Bus v2.1</span>
        </div>
      </div>
    </div>
  );
}

