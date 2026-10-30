'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default function AppError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('App route error boundary:', error);
  }, [error]);

  return (
    <div className="w-full min-h-[50vh] flex flex-col items-center justify-center p-6 font-mono text-xs">
      <div className="p-6 max-w-lg w-full bg-surface border border-line rounded-lg text-center space-y-4">
        <div className="w-10 h-10 mx-auto rounded-full bg-severity-critical/10 border border-severity-critical/30 flex items-center justify-center text-severity-critical">
          <AlertTriangle className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-text-primary uppercase tracking-wider">
            Workspace Fault Isolated
          </h2>
          <p className="text-[11px] text-text-muted mt-1 leading-relaxed">
            {error.message || 'An error occurred during state telemetry synchronization.'}
          </p>
        </div>
        <div className="flex items-center justify-center gap-3 pt-2">
          <button
            onClick={() => reset()}
            className="px-3.5 py-1.5 bg-signal text-canvas font-semibold rounded hover:bg-signal-hover transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Reset Workspace</span>
          </button>
          <Link
            href="/dashboard"
            className="px-3.5 py-1.5 bg-surface-subtle border border-line text-text-secondary hover:text-text-primary rounded transition-colors"
          >
            Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
