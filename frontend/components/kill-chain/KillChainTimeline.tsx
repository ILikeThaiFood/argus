"use client";

import type { KillChainPhase, KillChainEvent } from "@/lib/types";

interface KillChainTimelineProps {
  phases: KillChainPhase[];
  recentEvents: KillChainEvent[];
}

const PHASE_COLORS: Record<string, string> = {
  recon: "#0088ff",
  weaponize: "#0088ff",
  deliver: "#00ffd5",
  exploit: "#ffaa00",
  install: "#ff6b35",
  c2: "#ff2d55",
  actions: "#ff2d55",
};

export default function KillChainTimeline({ phases, recentEvents }: KillChainTimelineProps) {
  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  if (phases.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-slate-600 text-[11px]">
        Loading kill chain data...
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col p-2">
      {/* Kill Chain Pipeline */}
      <div className="flex items-center gap-0.5 mb-3">
        {phases.map((p, i) => {
          const color = PHASE_COLORS[p.phase] ?? "#0088ff";
          return (
            <div key={p.phase} className="flex items-center flex-1 min-w-0">
              <div
                className="relative flex-1 py-2 px-1 text-center"
                style={{
                  background: `linear-gradient(135deg, ${color}15, ${color}08)`,
                  borderLeft: `2px solid ${color}60`,
                  clipPath: i < phases.length - 1
                    ? "polygon(0 0, 90% 0, 100% 50%, 90% 100%, 0 100%, 10% 50%)"
                    : "polygon(0 0, 100% 0, 100% 100%, 0 100%, 10% 50%)",
                }}
              >
                <div className="text-[7px] font-bold tracking-wider" style={{ color }}>
                  {p.label}
                </div>
                <div className="text-[10px] font-bold text-white tabular-nums">{p.count}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Timeline Events */}
      <div className="flex-1 overflow-y-auto space-y-1">
        <div className="text-[9px] text-slate-500 uppercase tracking-wider mb-1">Recent Activity</div>
        {recentEvents.length === 0 && (
          <div className="text-[10px] text-slate-600 text-center mt-2">No recent events</div>
        )}
        {recentEvents.map((event) => {
          const color = PHASE_COLORS[event.phase] ?? "#0088ff";
          const phaseData = phases.find((p) => p.phase === event.phase);
          return (
            <div
              key={event.id}
              className="flex items-center gap-2 px-2 py-1.5 bg-navy-800/40 border border-navy-700/30 rounded-sm"
            >
              <div
                className="w-1.5 h-6 rounded-full shrink-0"
                style={{ backgroundColor: color }}
              />
              <div className="min-w-0 flex-1">
                <div className="text-[10px] text-slate-300 truncate">{event.description}</div>
                <div className="flex items-center gap-2 text-[8px]">
                  <span style={{ color }}>{phaseData?.label ?? event.phase}</span>
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
