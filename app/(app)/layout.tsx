'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  PlusCircle,
  Terminal,
  ShieldAlert,
  Activity,
  FileCheck2,
  Workflow,
  Settings,
  Search,
  Sun,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  CheckCircle2,
  AlertTriangle,
  Menu,
  X,
} from 'lucide-react';
import { useAppStore } from '@/lib/store';
import CommandPalette from '@/components/ui/CommandPalette';

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'New Ingestion', href: '/scan/new', icon: PlusCircle },
  { name: 'Live Cockpit', href: '/scan/SCN-2026-0941', icon: Terminal, badge: 'RUN' },
  { name: 'Findings', href: '/findings', icon: ShieldAlert, badge: '6' },
  { name: 'Traffic / Logs', href: '/traffic', icon: Activity },
  { name: 'Audit Reports', href: '/reports', icon: FileCheck2 },
  { name: 'Architecture', href: '/architecture', icon: Workflow },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const {
    theme,
    toggleTheme,
    setCommandPaletteOpen,
    sidebarCollapsed,
    toggleSidebar,
    offlineMode,
  } = useAppStore();

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-canvas text-text-primary flex flex-col md:flex-row">
      <CommandPalette />

      {/* Mobile Top Header */}
      <header className="md:hidden flex items-center justify-between px-5 h-14 bg-surface border-b border-line">
        <Link href="/" className="flex items-center gap-2">
          <div className="w-4 h-4 bg-signal" />
          <span className="text-sm font-semibold uppercase tracking-wider font-sans">
            Analyst <span className="text-signal">AI</span>
          </span>
        </Link>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCommandPaletteOpen(true)}
            className="p-1.5 text-text-muted hover:text-text-primary"
            aria-label="Search"
          >
            <Search className="w-4 h-4" />
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-1.5 text-text-muted hover:text-text-primary"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </header>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-50 bg-black/80 flex flex-col pt-14">
          <div className="bg-surface border-b border-line p-5 space-y-1">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setMobileMenuOpen(false)}
                  className={`flex items-center justify-between px-3.5 py-2.5 rounded text-sm ${
                    isActive ? 'bg-signal/15 text-signal font-medium' : 'text-text-secondary hover:bg-canvas'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className="w-4 h-4" />
                    <span>{item.name}</span>
                  </div>
                  {item.badge && (
                    <span className="text-xs px-2 py-0.5 rounded bg-canvas border border-line text-text-muted font-mono">
                      {item.badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        </div>
      )}

      {/* Desktop Studio Sidebar */}
      <aside
        className={`hidden md:flex flex-col border-r border-hairline bg-surface/95 transition-all duration-300 shrink-0 select-none ${
          sidebarCollapsed ? 'w-16' : 'w-64'
        }`}
      >
        {/* Brand & Collapse Header */}
        <div className="h-14 px-5 flex items-center justify-between border-b border-hairline">
          {!sidebarCollapsed ? (
            <Link href="/" className="flex items-center gap-2.5 group">
              <div className="w-4 h-4 bg-signal border border-signal/40 group-hover:bg-signal-hover transition-colors" />
              <span className="text-sm font-semibold tracking-wider uppercase text-text-primary font-sans">
                ANALYST <span className="text-signal">AI</span>
              </span>
            </Link>
          ) : (
            <Link href="/" className="mx-auto" title="Home">
              <div className="w-4 h-4 bg-signal" />
            </Link>
          )}

          <button
            onClick={toggleSidebar}
            className="text-text-muted hover:text-text-primary p-1.5 rounded hover:bg-surface-subtle transition-colors"
            title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {sidebarCollapsed ? (
              <PanelLeftOpen className="w-4 h-4" />
            ) : (
              <PanelLeftClose className="w-4 h-4" />
            )}
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive =
              pathname === item.href ||
              (item.href !== '/dashboard' && pathname.startsWith(item.href));

            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center justify-between px-3 py-2 rounded text-sm transition-colors relative group ${
                  isActive
                    ? 'bg-signal/15 text-signal font-semibold'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-subtle'
                }`}
                title={sidebarCollapsed ? item.name : undefined}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      isActive ? 'text-signal' : 'text-text-muted group-hover:text-text-primary'
                    }`}
                  />
                  {!sidebarCollapsed && <span className="truncate">{item.name}</span>}
                </div>

                {!sidebarCollapsed && item.badge && (
                  <span
                    className={`text-xs px-2 py-0.5 rounded font-mono ${
                      item.badge === 'RUN'
                        ? 'bg-signal/20 text-signal border border-signal/30 font-medium'
                        : 'bg-surface-subtle border border-line text-text-muted'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}

                {isActive && (
                  <div className="absolute left-0 top-1.5 bottom-1.5 w-[2px] bg-signal rounded-r" />
                )}
              </Link>
            );
          })}
        </nav>

        {/* Engine Telemetry Badge with >20px safe edge margin */}
        <div className="px-5 py-4 border-t border-hairline bg-canvas/30 text-xs">
          {!sidebarCollapsed ? (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-text-muted">
                <span>Capability Bus:</span>
                <span className="flex items-center gap-1.5 text-signal font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-signal animate-pulse" />
                  ACTIVE
                </span>
              </div>
              <div className="text-xs text-text-secondary truncate font-mono">
                {offlineMode ? 'Mode: Deterministic (0-Key)' : 'LLM: Groq Llama-3.3-70B'}
              </div>
            </div>
          ) : (
            <div className="flex justify-center" title="Bus Active">
              <div className="w-2.5 h-2.5 rounded-full bg-signal" />
            </div>
          )}
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Desktop Top Bar */}
        <header className="hidden md:flex items-center justify-between h-14 px-6 border-b border-hairline bg-surface/95 sticky top-0 z-40">
          <div className="flex items-center gap-2 text-xs text-text-muted font-mono">
            <span className="text-text-primary font-semibold uppercase">
              {NAV_ITEMS.find((it) => pathname.startsWith(it.href))?.name || 'ANALYSIS WORKSPACE'}
            </span>
            <span>/</span>
            <span className="text-text-muted">A2A TELEMETRY BUS</span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setCommandPaletteOpen(true)}
              className="flex items-center gap-2 px-3 py-1.5 text-xs text-text-secondary bg-surface border border-line hover:border-line-strong rounded transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              <span>Search findings, rules, logs...</span>
              <kbd className="text-xs bg-canvas px-1.5 py-0.5 rounded border border-line font-mono">⌘K</kbd>
            </button>

            <button
              onClick={toggleTheme}
              className="w-8 h-8 flex items-center justify-center rounded text-text-muted hover:text-text-primary hover:bg-surface border border-transparent hover:border-line transition-colors"
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
        </header>

        {/* Page Content Viewport */}
        <main className="flex-1 p-5 sm:p-7 lg:p-8 overflow-y-auto max-w-[1600px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
