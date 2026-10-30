'use client';

import React, { useState } from 'react';
import { Check, ShieldAlert, Cpu, Sparkles, Terminal, FileCode, CheckCircle2 } from 'lucide-react';

export default function LiveCodeDemo() {
  const [stage, setStage] = useState<'vulnerable' | 'flagged' | 'patched'>('flagged');

  return (
    <div id="demo" className="w-full py-24 px-4 sm:px-6 border-t border-hairline bg-surface/30">
      <div className="max-w-5xl mx-auto">
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-8 pb-4 border-b border-hairline">
          <div>
            <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight text-text-primary">
              Taint flagged to <span className="font-serif italic font-normal">empirical fix.</span>
            </h2>
            <p className="mt-2 text-base text-text-secondary">
              Observe real AST taint detection and subsequent non-regressive sandbox verification.
            </p>
          </div>

          {/* Interactive Stage Switcher */}
          <div className="mt-4 md:mt-0 flex items-center gap-1.5 bg-surface border border-line p-1 rounded font-mono text-xs">
            <button
              onClick={() => setStage('vulnerable')}
              className={`px-3 py-1.5 rounded transition-colors ${
                stage === 'vulnerable' ? 'bg-canvas text-text-primary border border-line font-medium' : 'text-text-muted hover:text-text-primary'
              }`}
            >
              1. Raw AST
            </button>
            <button
              onClick={() => setStage('flagged')}
              className={`px-3 py-1.5 rounded transition-colors ${
                stage === 'flagged' ? 'bg-severity-critical/20 text-severity-critical border border-severity-critical/30 font-semibold' : 'text-text-muted hover:text-text-primary'
              }`}
            >
              2. AST Flagged
            </button>
            <button
              onClick={() => setStage('patched')}
              className={`px-3 py-1.5 rounded transition-colors ${
                stage === 'patched' ? 'bg-signal/20 text-signal border border-signal/30 font-semibold' : 'text-text-muted hover:text-text-primary'
              }`}
            >
              3. Sandbox Patched
            </button>
          </div>
        </div>

        {/* Code Diff Display Container */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 bg-surface border border-line rounded-lg overflow-hidden">
          {/* Left Column: Code Editor */}
          <div className="lg:col-span-7 p-6 font-mono text-xs border-b lg:border-b-0 lg:border-r border-line bg-canvas">
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-hairline text-text-muted">
              <span className="flex items-center gap-2 text-text-primary">
                <FileCode className="w-4 h-4 text-signal" />
                src/database.py
              </span>
              <span className="text-xs text-text-muted">Python 3.12 (Tree-sitter)</span>
            </div>

            <div className="space-y-1.5 leading-relaxed select-text text-text-primary">
              <div className="text-text-muted">39:  import sqlite3</div>
              <div className="text-text-muted">40:  </div>
              <div className="text-text-primary">41:  def query_user_profile(db_cursor, username: str) -&gt; dict:</div>
              <div className="text-text-muted pl-4">42:      # Execute user lookup by username</div>

              {stage === 'patched' ? (
                <>
                  <div className="pl-4 py-1.5 bg-signal/15 text-signal border-l-2 border-signal font-semibold">
                    43: +    query = &quot;SELECT id, username, role FROM users WHERE username = ?&quot;
                  </div>
                  <div className="pl-4 py-1.5 bg-signal/15 text-signal border-l-2 border-signal font-semibold">
                    44: +    db_cursor.execute(query, (username,))
                  </div>
                </>
              ) : stage === 'flagged' ? (
                <>
                  <div className="pl-4 py-1.5 bg-severity-critical/15 text-severity-critical border-l-2 border-severity-critical font-semibold">
                    43: !    query = f&quot;SELECT id, username, role FROM users WHERE username = &apos;&#123;username&#125;&apos;&quot;
                  </div>
                  <div className="pl-4 py-1.5 bg-severity-critical/15 text-severity-critical border-l-2 border-severity-critical font-semibold">
                    44: !    db_cursor.execute(query)  # AST Taint Sink Identified
                  </div>
                </>
              ) : (
                <>
                  <div className="pl-4">
                    43:      query = f&quot;SELECT id, username, role FROM users WHERE username = &apos;&#123;username&#125;&apos;&quot;
                  </div>
                  <div className="pl-4">
                    44:      db_cursor.execute(query)
                  </div>
                </>
              )}

              <div className="text-text-primary pl-4">45:      record = db_cursor.fetchone()</div>
              <div className="text-text-primary pl-4">46:      return dict(record) if record else None</div>
            </div>
          </div>

          {/* Right Column: Reasoning & Sandbox Verification Telemetry */}
          <div className="lg:col-span-5 p-6 flex flex-col justify-between bg-surface-subtle">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-hairline mb-4 font-mono text-xs">
                <span className="text-text-muted font-medium">EMPIRICAL RECHECK</span>
                <span
                  className={`px-2 py-0.5 rounded ${
                    stage === 'patched'
                      ? 'bg-signal/20 text-signal border border-signal/30 font-semibold'
                      : stage === 'flagged'
                      ? 'bg-severity-critical/20 text-severity-critical border border-severity-critical/30 font-semibold'
                      : 'bg-canvas text-text-muted border border-line'
                  }`}
                >
                  {stage === 'patched' ? 'IMMUNE (PASS)' : stage === 'flagged' ? 'CONFIRMED VULNERABLE' : 'UNSCANNED'}
                </span>
              </div>

              {stage === 'patched' ? (
                <div className="space-y-3">
                  <div className="text-text-primary font-semibold text-sm">
                    Sandbox Validation: PASSED
                  </div>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    The generated patch was applied to an ephemeral sandbox copy of <code className="text-signal font-mono text-xs">seeded-vuln-repo</code>.
                    The Detection engine re-scanned the target file with AST rule <code className="text-signal font-mono text-xs">RULE-PY-SQLI-AST</code>.
                  </p>
                  <div className="bg-canvas p-3 rounded border border-line text-xs font-mono space-y-1 text-text-secondary">
                    <div className="text-signal">&gt; peer_bus.request(&quot;rule.recheck&quot;)</div>
                    <div>&gt; tree_sitter_recheck.matches = 0</div>
                    <div>&gt; unit_test_suite: 2 passed, 0 failures</div>
                    <div className="text-signal">&gt; STATUS: PROCEED_TO_MERGE</div>
                  </div>
                </div>
              ) : stage === 'flagged' ? (
                <div className="space-y-3">
                  <div className="text-severity-critical font-semibold text-sm">
                    CWE-89: SQL Injection (Critical · 0.98 Conf)
                  </div>
                  <p className="text-sm text-text-secondary leading-relaxed">
                    AST taint tracker traced user input parameter <code className="text-text-primary font-mono text-xs">username</code> to an interpolated string sink.
                    Groq LLM verified that payload <code className="text-severity-critical font-mono text-xs">&apos; OR 1=1--</code> grants full database exfiltration.
                  </p>
                  <div className="bg-canvas p-3 rounded border border-line text-xs font-mono space-y-1 text-text-secondary">
                    <div className="text-severity-critical">&gt; AST Sink: Cursor.execute()</div>
                    <div>&gt; Taint Source: Function Parameter</div>
                    <div>&gt; Exploit Verification: VERIFIED_EXPLOITABLE</div>
                  </div>
                </div>
              ) : (
                <div className="space-y-3 text-text-secondary text-sm">
                  <div>Select &quot;2. AST Flagged&quot; to inspect rule triggering, or &quot;3. Sandbox Patched&quot; to observe the empirical fix.</div>
                </div>
              )}
            </div>

            <div className="pt-4 mt-6 border-t border-hairline flex items-center justify-between text-xs text-text-muted font-mono">
              <span>Agent: AgentID.REASONING</span>
              <span className="text-signal">Deterministic Chain</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
