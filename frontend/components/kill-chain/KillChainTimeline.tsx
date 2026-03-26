"use client";

import { useEffect, useState } from "react";

interface KillChainPhase {
  phase: string;
  label: string;
  count: number;
  color: string;
}

interface TimelineEvent {
  id: string;
  phase: string;
  description: string;
  timestamp: string;
}

const PHASES: KillChainPhase[] = [
  { phase: "recon", label: "RECON", count: 23, color: "#0088ff" },
  { phase: "weaponize", label: "WEAPON", count: 8, color: "#0088ff" },
  { phase: "deliver", label: "DELIVER", count: 15, color: "#00ffd5" },
  { phase: "exploit", label: "EXPLOIT", count: 18, color: "#ffaa00" },
  { phase: "install", label: "INSTALL", count: 12, color: "#ff6b35" },
  { phase: "c2", label: "C2", count: 22, color: "#ff2d55" },
  { phase: "actions", label: "ACTIONS", count: 11, color: "#ff2d55" },
];

const MOCK_EVENTS: TimelineEvent[] = [
  { id: "1", phase: "recon", description: "Active scan from 223.71.x.x", timestamp: new Date(Date.now() - 120000).toISOString() },
  { id: "2", phase: "deliver", description: "Malware payload via HTTPS", timestamp: new Date(Date.now() - 90000).toISOString() },
  { id: "3", phase: "exploit", description: "Brute force on 10.0.2.10:22", timestamp: new Date(Date.now() - 60000).toISOString() },
  { id: "4", phase: "c2", description: "Beacon to 185.220.x.x:443", timestamp: new Date(Date.now() - 30000).toISOString() },
  { id: "5", phase: "actions", description: "Data exfil 2.4GB outbound", timestamp: new Date().toISOString() },
];

export default function KillChainTimeline() {
  const [phases, setPhases] = useState(PHASES);
  const [events, setEvents] = useState(MOCK_EVENTS);

  // Simulate activity
  useEffect(() => {
    const interval = setInterval(() => {
      setPhases((prev) =>
        prev.map((p) => ({
          ...p,
          count: p.count + (Math.random() > 0.7 ? 1 : 0),
        }))
      );
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <div className="h-full flex flex-col p-2">
      {/* Kill Chain Pipeline */}
      <div className="flex items-center gap-0.5 mb-3">
        {phases.map((p, i) => (
          <div key={p.phase} className="flex items-center flex-1 min-w-0">
            <div
              className="relative flex-1 py-2 px-1 text-center"
              style={{
                background: `linear-gradient(135deg, ${p.color}15, ${p.color}08)`,
                borderLeft: `2px solid ${p.color}60`,
                clipPath: i < phases.length - 1
                  ? "polygon(0 0, 90% 0, 100% 50%, 90% 100%, 0 100%, 10% 50%)"
                  : "polygon(0 0, 100% 0, 100% 100%, 0 100%, 10% 50%)",
              }}
            >
              <div className="text-[7px] font-bold tracking-wider" style={{ color: p.color }}>
                {p.label}
              </div>
              <div className="text-[10px] font-bold text-white tabular-nums">{p.count}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Timeline Events */}
      <div className="flex-1 overflow-y-auto space-y-1">
        <div className="text-[9px] text-slate-500 uppercase tracking-wider mb-1">Recent Activity</div>
        {events.map((event) => {
          const phase = phases.find((p) => p.phase === event.phase);
          return (
            <div
              key={event.id}
              className="flex items-center gap-2 px-2 py-1.5 bg-navy-800/40 border border-navy-700/30 rounded-sm"
            >
              <div
                className="w-1.5 h-6 rounded-full shrink-0"
                style={{ backgroundColor: phase?.color ?? "#0088ff" }}
              />
              <div className="min-w-0 flex-1">
                <div className="text-[10px] text-slate-300 truncate">{event.description}</div>
                <div className="flex items-center gap-2 text-[8px]">
                  <span style={{ color: phase?.color ?? "#0088ff" }}>{phase?.label}</span>
                  <span className="text-slate-600">{formatTime(event.timestamp)}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
