'use client';

import React, { useState } from 'react';
import {
  Settings,
  Key,
  Sliders,
  Shield,
  Sun,
  Moon,
  Sparkles,
  Save,
  CheckCircle2,
  Terminal,
} from 'lucide-react';
import { useAppStore } from '@/lib/store';

export default function SettingsPage() {
  const {
    theme,
    setTheme,
    motionPreference,
    setMotionPreference,
    offlineMode,
    setOfflineMode,
    dynamicExploitMode,
    setDynamicExploitMode,
  } = useAppStore();

  const [provider, setProvider] = useState<'groq' | 'claude' | 'offline'>('groq');
  const [apiKey, setApiKey] = useState('gsk_••••••••••••••••••••••••••••••••');
  const [model, setModel] = useState('llama-3.3-70b-versatile');
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12 font-mono text-xs">
      {/* Title */}
      <div className="pb-4 border-b border-hairline">
        <div className="text-signal tracking-widest uppercase mb-1">
          SYSTEM PREFERENCES // ENGINE CONFIGURATION
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
          Engine &amp; Environment Settings
        </h1>
        <p className="mt-2 text-xs text-text-secondary leading-relaxed">
          Manage LLM provider credentials, AST rule-pack defaults, presentation themes, and motion constraints.
        </p>
      </div>

      {saved && (
        <div className="p-4 bg-signal/15 border border-signal/30 text-signal rounded flex items-center gap-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>Engine configuration successfully saved and persisted to local store.</span>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* 1. LLM Provider & Credentials */}
        <div className="bg-surface border border-line rounded-lg p-6 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-hairline text-text-primary font-medium">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-signal" />
              <span>1. LLM REASONING ENGINE PROVIDER</span>
            </div>
            <span className="text-[11px] text-text-muted">A2A Handoff Agent</span>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <button
              type="button"
              onClick={() => {
                setProvider('groq');
                setOfflineMode(false);
              }}
              className={`p-3 rounded border text-left flex flex-col justify-between transition-colors ${
                provider === 'groq' && !offlineMode
                  ? 'bg-signal/15 border-signal text-signal'
                  : 'bg-canvas/50 border-line text-text-secondary hover:text-text-primary'
              }`}
            >
              <div className="font-semibold mb-1">Groq (Llama 3.3)</div>
              <div className="text-[10px] text-text-muted">Ultra-fast inference (default)</div>
            </button>

            <button
              type="button"
              onClick={() => {
                setProvider('claude');
                setOfflineMode(false);
              }}
              className={`p-3 rounded border text-left flex flex-col justify-between transition-colors ${
                provider === 'claude' && !offlineMode
                  ? 'bg-signal/15 border-signal text-signal'
                  : 'bg-canvas/50 border-line text-text-secondary hover:text-text-primary'
              }`}
            >
              <div className="font-semibold mb-1">Anthropic (Claude 3.5)</div>
              <div className="text-[10px] text-text-muted">High-depth semantic analysis</div>
            </button>

            <button
              type="button"
              onClick={() => {
                setProvider('offline');
                setOfflineMode(true);
              }}
              className={`p-3 rounded border text-left flex flex-col justify-between transition-colors ${
                offlineMode
                  ? 'bg-signal/15 border-signal text-signal'
                  : 'bg-canvas/50 border-line text-text-secondary hover:text-text-primary'
              }`}
            >
              <div className="font-semibold mb-1">Offline (0-Key)</div>
              <div className="text-[10px] text-text-muted">Deterministic regex fallback</div>
            </button>
          </div>

          {!offlineMode && (
            <div className="space-y-4 pt-2">
              <div>
                <label className="block text-text-secondary text-[11px] mb-1.5 uppercase">
                  API Key ({provider.toUpperCase()})
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full px-3 py-2 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none"
                />
              </div>

              <div>
                <label className="block text-text-secondary text-[11px] mb-1.5 uppercase">
                  Active Model Checkpoint
                </label>
                <input
                  type="text"
                  value={provider === 'groq' ? 'llama-3.3-70b-versatile' : 'claude-3-5-sonnet-20241022'}
                  readOnly
                  className="w-full px-3 py-2 bg-canvas/40 border border-hairline text-text-muted rounded outline-none"
                />
              </div>
            </div>
          )}
        </div>

        {/* 2. Appearance & Motion */}
        <div className="bg-surface border border-line rounded-lg p-6 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-hairline text-text-primary font-medium">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-signal" />
              <span>2. PRESENTATION &amp; MOTION SYSTEM</span>
            </div>
            <span className="text-[11px] text-text-muted">60 FPS Standards</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Theme Toggle */}
            <div className="p-4 bg-canvas/40 border border-hairline rounded flex items-center justify-between">
              <div>
                <div className="font-semibold text-text-primary">Color Theme</div>
                <div className="text-[11px] text-text-muted">
                  Dark canvas default or high-contrast light parity
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setTheme('dark')}
                  className={`px-3 py-1.5 rounded text-xs border ${
                    theme === 'dark'
                      ? 'bg-signal text-canvas font-semibold border-signal'
                      : 'bg-surface text-text-muted border-line'
                  }`}
                >
                  Dark
                </button>
                <button
                  type="button"
                  onClick={() => setTheme('light')}
                  className={`px-3 py-1.5 rounded text-xs border ${
                    theme === 'light'
                      ? 'bg-signal text-canvas font-semibold border-signal'
                      : 'bg-surface text-text-muted border-line'
                  }`}
                >
                  Light
                </button>
              </div>
            </div>

            {/* Motion Preference */}
            <div className="p-4 bg-canvas/40 border border-hairline rounded flex items-center justify-between">
              <div>
                <div className="font-semibold text-text-primary">Motion Engine</div>
                <div className="text-[11px] text-text-muted">
                  GSAP smooth scroll &amp; clip-wipes or reduced motion
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setMotionPreference('full')}
                  className={`px-3 py-1.5 rounded text-xs border ${
                    motionPreference === 'full'
                      ? 'bg-signal text-canvas font-semibold border-signal'
                      : 'bg-surface text-text-muted border-line'
                  }`}
                >
                  Full 60fps
                </button>
                <button
                  type="button"
                  onClick={() => setMotionPreference('reduced')}
                  className={`px-3 py-1.5 rounded text-xs border ${
                    motionPreference === 'reduced'
                      ? 'bg-signal text-canvas font-semibold border-signal'
                      : 'bg-surface text-text-muted border-line'
                  }`}
                >
                  Reduced
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Save button */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            className="px-6 py-2.5 bg-signal text-canvas font-semibold rounded hover:bg-signal-hover transition-colors flex items-center gap-2"
          >
            <Save className="w-3.5 h-3.5" />
            <span>Save Preferences</span>
          </button>
        </div>
      </form>
    </div>
  );
}

