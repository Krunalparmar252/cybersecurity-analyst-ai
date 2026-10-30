export default function AppLoading() {
  return (
    <div className="w-full min-h-[50vh] flex items-center justify-center font-mono text-xs text-text-muted">
      <div className="flex items-center gap-3">
        <div className="w-2 h-2 rounded-full bg-signal animate-pulse" />
        <span>Synchronizing A2A telemetry bus...</span>
      </div>
    </div>
  );
}
