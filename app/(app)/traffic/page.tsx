'use client';

import React, { useState, useEffect } from 'react';
import {
  Activity,
  ShieldAlert,
  AlertTriangle,
  Clock,
  Filter,
  CheckCircle2,
  XCircle,
  Search,
  ExternalLink,
} from 'lucide-react';
import { api } from '@/lib/api';
import { TrafficEvent } from '@/lib/types';
import CountUp from '@/components/motion/CountUp';

export default function TrafficPage() {
  const [events, setEvents] = useState<TrafficEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<TrafficEvent | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    async function load() {
      const data = await api.getTrafficEvents();
      setEvents(data);
      if (data.length > 0) setSelectedEvent(data[0]);
    }
    load();
  }, []);

  const filteredEvents = events.filter((e) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.path.toLowerCase().includes(q) ||
      e.sourceIp.toLowerCase().includes(q) ||
      (e.signatureMatched && e.signatureMatched.toLowerCase().includes(q))
    );
  });

  // 24-hour anomaly heat strip mock buckets
  const heatStrip = [
    { hour: '00:00', score: 4 },
    { hour: '01:00', score: 2 },
    { hour: '02:00', score: 0 },
    { hour: '03:00', score: 8 },
    { hour: '04:00', score: 12 },
    { hour: '05:00', score: 5 },
    { hour: '06:00', score: 18 },
    { hour: '07:00', score: 24 },
    { hour: '08:00', score: 35 },
    { hour: '09:00', score: 42 },
    { hour: '10:00', score: 55 },
    { hour: '11:00', score: 78 },
    { hour: '12:00', score: 65 },
    { hour: '13:00', score: 40 },
    { hour: '14:00', score: 58 },
    { hour: '15:00', score: 82 },
    { hour: '16:00', score: 71 },
    { hour: '17:00', score: 63 },
    { hour: '18:00', score: 48 },
    { hour: '19:00', score: 52 },
    { hour: '20:00', score: 88 },
    { hour: '21:00', score: 96 },
    { hour: '22:00', score: 92 },
    { hour: '23:00', score: 38 },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-hairline">
        <div>
          <div className="font-mono text-xs text-signal tracking-widest uppercase mb-1">
            NETWORK TELEMETRY // REAL-TIME INGESTION
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-text-primary">
            Traffic &amp; Log Anomaly Analyzer
          </h1>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs text-text-muted">
          <span className="w-2 h-2 rounded-full bg-signal animate-ping" />
          <span>INSPECTOR LISTENING: PORT 8000</span>
        </div>
      </div>

      {/* KPI Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
        <div className="p-4 bg-surface border border-line rounded-lg">
          <div className="text-text-muted text-[10px]">TOTAL REQUESTS ANALYZED</div>
          <div className="text-2xl font-bold text-text-primary mt-1">
            <CountUp end={148920} />
          </div>
          <div className="text-[10px] text-text-muted mt-1">Last 24 Hours</div>
        </div>

        <div className="p-4 bg-surface border border-line rounded-lg">
          <div className="text-text-muted text-[10px]">ANOMALIES FLAGGED</div>
          <div className="text-2xl font-bold text-severity-critical mt-1">
            <CountUp end={4} />
          </div>
          <div className="text-[10px] text-text-muted mt-1">SQLi, Traversal, Deser</div>
        </div>

        <div className="p-4 bg-surface border border-line rounded-lg">
          <div className="text-text-muted text-[10px]">PAYLOADS QUARANTINED</div>
          <div className="text-2xl font-bold text-signal mt-1">
            <CountUp end={2} />
          </div>
          <div className="text-[10px] text-text-muted mt-1">Dropped at Ingress</div>
        </div>

        <div className="p-4 bg-surface border border-line rounded-lg">
          <div className="text-text-muted text-[10px]">AVG INSPECTION LATENCY</div>
          <div className="text-2xl font-bold text-text-primary mt-1">
            <CountUp end={11} suffix="ms" />
          </div>
          <div className="text-[10px] text-text-muted mt-1">Regex + AST Signature</div>
        </div>
      </div>

      {/* 24-Hour Anomaly Heat Strip */}
      <div className="bg-surface border border-line rounded-lg p-5 font-mono text-xs space-y-3">
        <div className="flex items-center justify-between text-text-primary font-medium">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-signal" />
            <span>24-HOUR ANOMALY ACTIVITY HEAT STRIP</span>
          </div>
          <span className="text-[11px] text-text-muted">Peak Spike: 21:00 UTC (Score: 96)</span>
        </div>

        {/* Heat Bars */}
        <div className="grid grid-cols-24 gap-1 h-14 items-end pt-2">
          {heatStrip.map((item) => {
            const isHigh = item.score > 70;
            const isMedium = item.score > 30;

            return (
              <div
                key={item.hour}
                title={`${item.hour}: Anomaly Score ${item.score}`}
                className="group relative flex flex-col items-center h-full justify-end cursor-pointer"
              >
                <div
                  className={`w-full rounded-t transition-all group-hover:opacity-100 ${
                    isHigh
                      ? 'bg-severity-critical opacity-85'
                      : isMedium
                      ? 'bg-severity-high opacity-70'
                      : 'bg-signal/40 opacity-40'
                  }`}
                  style={{ height: `${Math.max(12, (item.score / 100) * 100)}%` }}
                />
              </div>
            );
          })}
        </div>

        <div className="flex items-center justify-between text-[10px] text-text-muted pt-1 border-t border-hairline">
          <span>00:00 UTC</span>
          <span>12:00 UTC</span>
          <span>23:00 UTC (Current)</span>
        </div>
      </div>

      {/* Events Table & Drill-Down Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Flagged Events List */}
        <div className="lg:col-span-7 bg-surface border border-line rounded-lg overflow-hidden font-mono text-xs">
          <div className="p-4 border-b border-hairline flex items-center justify-between bg-canvas/40">
            <span className="font-medium text-text-primary">FLAGGED NETWORK EVENTS</span>
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-text-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search IP, path..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-2 py-1 bg-surface border border-line rounded text-xs text-text-primary outline-none focus:border-signal"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-hairline text-text-muted text-[10px] bg-canvas/20">
                  <th className="py-2.5 px-3">TIMESTAMP</th>
                  <th className="py-2.5 px-3">IP</th>
                  <th className="py-2.5 px-3">METHOD &amp; PATH</th>
                  <th className="py-2.5 px-3">SCORE</th>
                  <th className="py-2.5 px-3">STATUS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {filteredEvents.map((ev) => {
                  const isSelected = selectedEvent?.id === ev.id;
                  return (
                    <tr
                      key={ev.id}
                      onClick={() => setSelectedEvent(ev)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-signal/10' : 'hover:bg-canvas/50'
                      }`}
                    >
                      <td className="py-3 px-3 text-text-muted whitespace-nowrap text-[11px]">
                        {ev.timestamp.split('T')[1].replace('Z', '')}
                      </td>
                      <td className="py-3 px-3 font-semibold text-text-primary">
                        {ev.sourceIp}
                      </td>
                      <td className="py-3 px-3 max-w-[200px] truncate text-text-secondary">
                        <span className="text-signal mr-1">{ev.method}</span>
                        <span>{ev.path}</span>
                      </td>
                      <td className="py-3 px-3 tabular-nums">
                        <span
                          className={`font-semibold ${
                            ev.anomalyScore > 80
                              ? 'text-severity-critical'
                              : ev.anomalyScore > 40
                              ? 'text-severity-high'
                              : 'text-signal'
                          }`}
                        >
                          {ev.anomalyScore}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`text-[10px] px-1.5 py-0.2 rounded uppercase ${
                            ev.status === 'quarantined'
                              ? 'bg-severity-critical/20 text-severity-critical border border-severity-critical/30'
                              : ev.status === 'flagged'
                              ? 'bg-severity-high/20 text-severity-high border border-severity-high/30'
                              : 'bg-signal/15 text-signal border border-signal/20'
                          }`}
                        >
                          {ev.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Drill-Down Side Panel */}
        <div className="lg:col-span-5 bg-surface border border-line rounded-lg p-5 font-mono text-xs flex flex-col justify-between">
          {selectedEvent ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-hairline">
                <span className="text-text-primary font-medium">EVENT DETAILS // {selectedEvent.id}</span>
                <span className="text-signal text-[11px]">{selectedEvent.statusCode} HTTP</span>
              </div>

              <div className="space-y-2 text-[11px]">
                <div className="text-text-muted">SOURCE IP: <span className="text-text-primary font-semibold">{selectedEvent.sourceIp}</span></div>
                <div className="text-text-muted">SIGNATURE MATCH: <span className="text-signal">{selectedEvent.signatureMatched || 'None'}</span></div>
                <div className="text-text-muted">REQUEST PATH: <code className="text-text-secondary break-all">{selectedEvent.path}</code></div>
                <div className="text-text-muted">LATENCY: <span className="text-text-primary">{selectedEvent.latencyMs}ms</span></div>
              </div>

              {selectedEvent.payloadSample && (
                <div>
                  <div className="text-text-muted text-[10px] uppercase mb-1">Extracted Payload Sample</div>
                  <pre className="p-3 bg-canvas rounded border border-line text-severity-critical break-all text-[11px]">
                    {selectedEvent.payloadSample}
                  </pre>
                </div>
              )}

              <div className="p-3 bg-canvas/40 border border-hairline rounded text-[11px] text-text-secondary leading-relaxed">
                Taint analysis correlation identified SQL injection / directory traversal attempt matching rule specifications.
              </div>
            </div>
          ) : (
            <div className="text-text-muted py-8 text-center">
              Select an event from the table to drill down into payload telemetry.
            </div>
          )}

          <div className="pt-4 mt-6 border-t border-hairline flex items-center justify-between text-[11px] text-text-muted">
            <span>Inspector: `AgentID.TRAFFIC`</span>
            <span className="text-signal">Live Ingress Active</span>
          </div>
        </div>
      </div>
    </div>
  );
}

