"use client";

import { useEffect, useState } from "react";
import { Shield, Activity, Database, Brain, Rss, AlertTriangle } from "lucide-react";
import type { DashboardStats } from "@/lib/types";
import type { ConnectionState } from "@/lib/websocket";

const SYSTEMS = [
  { name: "API", icon: Activity },
  { name: "Database", icon: Database },
  { name: "ML Engine", icon: Brain },
  { name: "Threat Feed", icon: Rss },
];

const DEFCON_LEVELS = [
  { level: 5, label: "NORMAL", color: "text-cyber-green" },
  { level: 4, label: "ELEVATED", color: "text-cyber-cyan" },
  { level: 3, label: "HIGH", color: "text-yellow-400" },
  { level: 2, label: "SEVERE", color: "text-cyber-amber" },
  { level: 1, label: "CRITICAL", color: "text-cyber-red" },
];

interface HeaderProps {
  stats: DashboardStats | null;
  connectionState: ConnectionState;
}

function computeDefcon(stats: DashboardStats | null): number {
  if (!stats) return 5;
  if (stats.critical_count >= 10) return 1;
  if (stats.critical_count >= 5) return 2;
  if (stats.high_count >= 10) return 3;
  if (stats.active_alerts >= 20) return 4;
  return 5;
}

export default function Header({ stats, connectionState }: HeaderProps) {
  const [clock, setClock] = useState("");

  useEffect(() => {
    const tick = () => {
      const now = new Date();
      setClock(
        now.toLocaleTimeString("en-US", {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }) +
          " UTC" +
          (now.getTimezoneOffset() === 0 ? "" : `${now.getTimezoneOffset() > 0 ? "-" : "+"}${String(Math.abs(Math.floor(now.getTimezoneOffset() / 60))).padStart(2, "0")}:${String(Math.abs(now.getTimezoneOffset() % 60)).padStart(2, "0")}`)
      );
    };
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  const defcon = computeDefcon(stats);
  const defconInfo = DEFCON_LEVELS.find((d) => d.level === defcon)!;
  const isConnected = connectionState === "connected";

  return (
    <header className="flex items-center justify-between px-4 py-2 bg-navy-800/80 border-b border-navy-600/50 backdrop-blur-sm">
      {/* Logo & Title */}
      <div className="flex items-center gap-3">
        <div className="relative">
          <Shield className="w-8 h-8 text-cyber-cyan" />
          <div className="absolute inset-0 animate-ping opacity-20">
            <Shield className="w-8 h-8 text-cyber-cyan" />
          </div>
        </div>
        <div>
          <h1 className="text-lg font-bold tracking-[0.3em] text-cyber-cyan text-glow">
            ARGUS
          </h1>
          <p className="text-[9px] tracking-[0.15em] text-slate-500 uppercase">
            Cyber Threat Detection Platform
          </p>
        </div>
      </div>

      {/* System Status */}
      <div className="flex items-center gap-4">
        {SYSTEMS.map((sys) => (
          <div
            key={sys.name}
            className="flex items-center gap-1.5 text-[10px] text-slate-400"
          >
            <div className="relative">
              <div className={`w-2 h-2 rounded-full ${isConnected ? "bg-cyber-green status-pulse" : "bg-slate-600"}`} />
            </div>
            <sys.icon className="w-3 h-3" />
            <span className="hidden lg:inline">{sys.name}</span>
          </div>
        ))}
      </div>

      {/* DEFCON Level */}
      <div className="flex items-center gap-2 px-3 py-1 border border-navy-600/50 rounded-sm">
        <AlertTriangle className={`w-4 h-4 ${defconInfo.color}`} />
        <div className="text-[10px]">
          <div className="text-slate-500 uppercase tracking-wider">DEFCON</div>
          <div className={`font-bold ${defconInfo.color}`}>
            {defcon} - {defconInfo.label}
          </div>
        </div>
      </div>

      {/* Clock & Events */}
      <div className="flex items-center gap-6">
        <div className="text-right">
          <div className="text-sm font-bold text-cyber-cyan tabular-nums">
            {clock}
          </div>
          <div className="text-[9px] text-slate-500 uppercase tracking-wider">
            System Time
          </div>
        </div>
        <div className="text-right border-l border-navy-600/50 pl-4">
          <div className="text-sm font-bold text-cyber-green tabular-nums count-animate">
            {(stats?.total_events ?? 0).toLocaleString()}
          </div>
          <div className="text-[9px] text-slate-500 uppercase tracking-wider">
            Events Processed
          </div>
        </div>
      </div>
    </header>
  );
}
