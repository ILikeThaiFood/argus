"use client";

import { useEffect, useState } from "react";
import { Shield, Activity, Database, Brain, Rss, AlertTriangle } from "lucide-react";

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

export default function Header() {
  const [clock, setClock] = useState("");
  const [eventCount, setEventCount] = useState(14832);
  const [defcon] = useState(3);

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

  // Simulate increasing event count
  useEffect(() => {
    const interval = setInterval(() => {
      setEventCount((c) => c + Math.floor(Math.random() * 5) + 1);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const defconInfo = DEFCON_LEVELS.find((d) => d.level === defcon)!;

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
              <div className="w-2 h-2 rounded-full bg-cyber-green status-pulse" />
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
            {eventCount.toLocaleString()}
          </div>
          <div className="text-[9px] text-slate-500 uppercase tracking-wider">
            Events Processed
          </div>
        </div>
      </div>
    </header>
  );
}
