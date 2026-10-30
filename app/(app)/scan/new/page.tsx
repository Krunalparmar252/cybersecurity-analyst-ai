'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  UploadCloud,
  FolderGit2,
  Terminal,
  ShieldAlert,
  Sliders,
  Check,
  Play,
  ArrowRight,
  FileCode,
  AlertCircle,
} from 'lucide-react';
import { api } from '@/lib/api';
import { useAppStore } from '@/lib/store';

export default function NewScanPage() {
  const router = useRouter();
  const { offlineMode, setOfflineMode, dynamicExploitMode, setDynamicExploitMode } = useAppStore();

  const [sourceType, setSourceType] = useState<'local' | 'git' | 'upload'>('git');
  const [repoPath, setRepoPath] = useState('https://github.com/Krunalparmar252/seeded-vuln-repo');
  const [branch, setBranch] = useState('main');
  const [dragActive, setDragActive] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);

  const [selectedRules, setSelectedRules] = useState<Record<string, boolean>>({
    'RULE-PY-SQLI-AST': true,
    'RULE-PY-DESERIAL-PICKLE': true,
    'RULE-PY-SECRET-JWT': true,
    'RULE-PY-PATH-TRAVERSAL': true,
    'RULE-PY-XSS-TEMPLATE': true,
    'RULE-PY-AUTH-MISSING': true,
  });

  const [launching, setLaunching] = useState(false);

  const handleToggleRule = (ruleId: string) => {
    setSelectedRules((prev) => ({ ...prev, [ruleId]: !prev[ruleId] }));
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setLaunching(true);

    const activeRules = Object.entries(selectedRules)
      .filter(([_, active]) => active)
      .map(([id]) => id);

    const target = sourceType === 'upload' && uploadedFileName ? uploadedFileName : repoPath;

    const newScan = await api.startScan({
      targetRepo: target,
      branch,
      rules: activeRules,
      enableDynamicExploit: dynamicExploitMode,
      offlineMode,
    });

    setTimeout(() => {
      router.push(`/scan/${newScan.id}`);
    }, 400);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 pb-12">
      {/* Title */}
      <div className="pb-4 border-b border-hairline">
        <div className="font-mono text-xs text-signal tracking-widest uppercase mb-1">
          INGESTION &amp; ORCHESTRATION // STEP 01
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
          Configure Security Analysis Run
        </h1>
        <p className="mt-2 text-xs sm:text-sm text-text-secondary font-mono leading-relaxed">
          Select target code source, activate deterministic AST rule packs, and launch the autonomous pipeline.
        </p>
      </div>

      <form onSubmit={handleLaunch} className="space-y-6">
        {/* Source Selector Tabs */}
        <div className="bg-surface border border-line rounded-lg p-6 space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-hairline font-mono text-xs text-text-primary font-medium">
            <span>1. INGESTION SOURCE</span>
            <span className="text-text-muted text-[11px]">Tree-sitter Parser Target</span>
          </div>

          <div className="grid grid-cols-3 gap-3 font-mono text-xs">
            <button
              type="button"
              onClick={() => setSourceType('local')}
              className={`p-3 rounded border text-left flex flex-col justify-between transition-colors ${
                sourceType === 'local'
                  ? 'bg-signal/15 border-signal text-signal'
                  : 'bg-canvas/50 border-line text-text-secondary hover:text-text-primary'
              }`}
            >
              <div className="font-semibold mb-1">Local Directory</div>
              <div className="text-[10px] text-text-muted">Direct path on host filesystem</div>
            </button>

            <button
              type="button"
              onClick={() => setSourceType('git')}
              className={`p-3 rounded border text-left flex flex-col justify-between transition-colors ${
                sourceType === 'git'
                  ? 'bg-signal/15 border-signal text-signal'
                  : 'bg-canvas/50 border-line text-text-secondary hover:text-text-primary'
              }`}
            >
              <div className="font-semibold mb-1">Git Repository</div>
              <div className="text-[10px] text-text-muted">Shallow clone via HTTPS/SSH</div>
            </button>

            <button
              type="button"
              onClick={() => setSourceType('upload')}
              className={`p-3 rounded border text-left flex flex-col justify-between transition-colors ${
                sourceType === 'upload'
                  ? 'bg-signal/15 border-signal text-signal'
                  : 'bg-canvas/50 border-line text-text-secondary hover:text-text-primary'
              }`}
            >
              <div className="font-semibold mb-1">Upload Archive / Logs</div>
              <div className="text-[10px] text-text-muted">Zip, tar.gz or access.log</div>
            </button>
          </div>

          {sourceType === 'local' && (
            <div className="space-y-4 pt-2 font-mono text-xs">
              <div>
                <label className="block text-text-secondary text-[11px] mb-1.5 uppercase">
                  Target Directory Path
                </label>
                <input
                  type="text"
                  value={repoPath}
                  onChange={(e) => setRepoPath(e.target.value)}
                  placeholder="e.g. demo_app or ./workspace/my-service"
                  required
                  className="w-full px-3 py-2 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none"
                />
              </div>

              <div>
                <label className="block text-text-secondary text-[11px] mb-1.5 uppercase">
                  Branch / Revision
                </label>
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className="w-full px-3 py-2 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none"
                />
              </div>
            </div>
          )}

          {sourceType === 'git' && (
            <div className="space-y-4 pt-2 font-mono text-xs">
              <div>
                <label className="block text-text-secondary text-[11px] mb-1.5 uppercase">
                  Repository Clone URL
                </label>
                <input
                  type="text"
                  value={repoPath}
                  onChange={(e) => setRepoPath(e.target.value)}
                  placeholder="https://github.com/organization/secure-api.git"
                  required
                  className="w-full px-3 py-2 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none"
                />
              </div>

              <div>
                <label className="block text-text-secondary text-[11px] mb-1.5 uppercase">
                  Git Branch
                </label>
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className="w-full px-3 py-2 bg-canvas border border-line focus:border-signal text-text-primary rounded outline-none"
                />
              </div>
            </div>
          )}

          {sourceType === 'upload' && (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragActive(false);
                if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                  setUploadedFileName(e.dataTransfer.files[0].name);
                }
              }}
              className={`border-2 border-dashed rounded-lg p-8 text-center font-mono text-xs transition-colors ${
                dragActive
                  ? 'border-signal bg-signal/10'
                  : 'border-line hover:border-line-strong bg-canvas/30'
              }`}
            >
              <UploadCloud className="w-8 h-8 mx-auto text-text-muted mb-2" />
              {uploadedFileName ? (
                <div className="text-signal font-semibold">
                  Loaded Archive: {uploadedFileName}
                </div>
              ) : (
                <>
                  <div className="text-text-primary font-medium mb-1">
                    Drop repository archive or server log file here
                  </div>
                  <div className="text-[11px] text-text-muted">
                    Supports .zip, .tar.gz, .py, .log (up to 250MB)
                  </div>
                </>
              )}
            </div>
          )}

          {/* Quick Target Presets */}
          <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-hairline font-mono text-[11px]">
            <span className="text-text-muted">Target Presets:</span>
            <button
              type="button"
              onClick={() => {
                setSourceType('git');
                setRepoPath('https://github.com/Krunalparmar252/seeded-vuln-repo');
                setBranch('main');
              }}
              className="px-2.5 py-1 rounded bg-canvas border border-line hover:border-signal hover:text-signal text-text-primary transition-colors flex items-center gap-1.5"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-signal" />
              <span>Krunalparmar252/seeded-vuln-repo (Active Target)</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setSourceType('git');
                setRepoPath('https://github.com/guilatrova/flask-sqlinjection-vulnerable');
                setBranch('main');
              }}
              className="px-2.5 py-1 rounded bg-canvas border border-line hover:border-line-strong text-text-secondary hover:text-text-primary transition-colors"
            >
              guilatrova/flask-sqlinjection-vulnerable
            </button>
            <button
              type="button"
              onClick={() => {
                setSourceType('local');
                setRepoPath('demo_app');
                setBranch('main');
              }}
              className="px-2.5 py-1 rounded bg-canvas border border-line hover:border-line-strong text-text-secondary hover:text-text-primary transition-colors"
            >
              ./demo_app (Local Fixture)
            </button>
          </div>
        </div>

        {/* Rule Sets Configuration */}
        <div className="bg-surface border border-line rounded-lg p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-hairline font-mono text-xs text-text-primary font-medium">
            <span>2. DETERMINISTIC AST &amp; ENTROPY RULES</span>
            <span className="text-signal text-[11px]">Zero-Token Origin</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
            {Object.keys(selectedRules).map((ruleId) => {
              const checked = selectedRules[ruleId];
              return (
                <div
                  key={ruleId}
                  onClick={() => handleToggleRule(ruleId)}
                  className={`p-3 rounded border flex items-center justify-between cursor-pointer transition-colors ${
                    checked
                      ? 'bg-canvas border-signal/50 text-text-primary'
                      : 'bg-canvas/30 border-line text-text-muted'
                  }`}
                >
                  <div className="truncate mr-2">
                    <div className="font-semibold text-[11px] text-signal truncate">{ruleId}</div>
                    <div className="text-[10px] text-text-secondary truncate">
                      {ruleId.includes('SQLI') && 'AST Taint: User input to SQLite cursor'}
                      {ruleId.includes('PICKLE') && 'Code Exec: Insecure pickle.loads()'}
                      {ruleId.includes('SECRET') && 'Shannon Entropy: Leaked private tokens'}
                      {ruleId.includes('PATH') && 'Traversal: Unnormalized os.path.join'}
                      {ruleId.includes('XSS') && 'Injection: Unescaped Markup rendering'}
                      {ruleId.includes('AUTH') && 'Logic: Missing role checking decorator'}
                    </div>
                  </div>
                  <div
                    className={`w-4 h-4 rounded flex items-center justify-center shrink-0 border ${
                      checked ? 'bg-signal border-signal text-canvas' : 'border-line'
                    }`}
                  >
                    {checked && <Check className="w-3 h-3 stroke-[3]" />}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Execution & Sandbox Flags */}
        <div className="bg-surface border border-line rounded-lg p-6 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between pb-3 border-b border-hairline text-text-primary font-medium">
            <span>3. EXECUTION MODE &amp; SANDBOX HARNESS</span>
            <span className="text-text-muted text-[11px]">Runtime Guarantees</span>
          </div>

          <div className="space-y-3">
            {/* Dynamic Exploit Toggle */}
            <div className="flex items-center justify-between p-3 rounded bg-canvas/40 border border-hairline">
              <div>
                <div className="font-semibold text-text-primary">
                  Dynamic Exploit Verification (`--dynamic`)
                </div>
                <div className="text-[11px] text-text-muted">
                  Fires HTTP attack payloads in sandboxed subprocess before &amp; after patching to empirically prove fix immunity.
                </div>
              </div>
              <button
                type="button"
                onClick={() => setDynamicExploitMode(!dynamicExploitMode)}
                className={`w-11 h-6 rounded-full transition-colors relative flex items-center px-1 ${
                  dynamicExploitMode ? 'bg-signal' : 'bg-surface-subtle border border-line'
                }`}
              >
                <div
                  className={`w-4 h-4 rounded-full bg-canvas transition-transform ${
                    dynamicExploitMode ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Offline Deterministic Mode Toggle */}
            <div className="flex items-center justify-between p-3 rounded bg-canvas/40 border border-hairline">
              <div>
                <div className="font-semibold text-text-primary">
                  Deterministic Offline Mode (`--offline`)
                </div>
                <div className="text-[11px] text-text-muted">
                  Runs 100% locally with zero external API calls, using pre-compiled regex and deterministic template engines.
                </div>
              </div>
              <button
                type="button"
                onClick={() => setOfflineMode(!offlineMode)}
                className={`w-11 h-6 rounded-full transition-colors relative flex items-center px-1 ${
                  offlineMode ? 'bg-signal' : 'bg-surface-subtle border border-line'
                }`}
              >
                <div
                  className={`w-4 h-4 rounded-full bg-canvas transition-transform ${
                    offlineMode ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Submit Launcher Button */}
        <div className="flex items-center justify-end gap-4 pt-2">
          <button
            type="submit"
            disabled={launching}
            className="px-6 py-3 bg-signal text-canvas font-mono text-xs font-semibold rounded hover:bg-signal-hover transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            {launching ? (
              <>
                <div className="w-3.5 h-3.5 rounded-full border-2 border-canvas border-t-transparent animate-spin" />
                <span>Initializing Ingestion...</span>
              </>
            ) : (
              <>
                <span>Launch Analysis Orchestrator</span>
                <Play className="w-3.5 h-3.5 fill-current" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}

