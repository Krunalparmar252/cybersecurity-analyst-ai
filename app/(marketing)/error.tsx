'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default function MarketingError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Marketing route error caught:', error);
  }, [error]);

  return (
    <div className="w-full min-h-[60vh] flex flex-col items-center justify-center px-4 bg-canvas font-mono text-xs">
      <div className="p-6 max-w-md bg-surface border border-line rounded-lg text-center space-y-4">
        <div className="w-10 h-10 mx-auto rounded-full bg-severity-critical/10 border border-severity-critical/30 flex items-center justify-center text-severity-critical">
          <AlertTriangle className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-text-primary uppercase tracking-wider">
            Rendering Boundary Interruption
          </h2>
          <p className="text-[11px] text-text-muted mt-1">
            {error.message || 'An unexpected runtime error occurred while mounting this view.'}
          </p>
        </div>
        <div className="flex items-center justify-center gap-3 pt-2">
          <button
            onClick={() => reset()}
            className="px-3 py-1.5 bg-signal text-canvas font-semibold rounded hover:bg-signal-hover transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry Mount</span>
          </button>
          <Link
            href="/"
            className="px-3 py-1.5 bg-surface-subtle border border-line text-text-secondary hover:text-text-primary rounded transition-colors"
          >
            Home
          </Link>
        </div>
      </div>
    </div>
  );
}
