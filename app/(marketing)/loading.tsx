export default function MarketingLoading() {
  return (
    <div className="w-full min-h-[60vh] flex items-center justify-center bg-canvas font-mono text-xs text-text-muted">
      <div className="flex items-center gap-3">
        <div className="w-2 h-2 rounded-full bg-signal animate-pulse" />
        <span>Loading pipeline specification...</span>
      </div>
    </div>
  );
}
