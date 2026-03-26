"use client";

import { useEffect, useState } from "react";
import { Activity, AlertTriangle, ShieldAlert, ShieldCheck, Zap, TrendingUp } from "lucide-react";

interface StatCard {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
  glowClass: string;
}

export default function StatsCards() {
  const [stats, setStats] = useState({
    total_events: 14832,
    active_alerts: 47,
    critical_count: 8,
    high_count: 15,
    medium_count: 24,
    events_per_second: 12.4,
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setStats((prev) => ({
        total_events: prev.total_events + Math.floor(Math.random() * 8) + 1,
        active_alerts: prev.active_alerts + (Math.random() > 0.7 ? 1 : 0),
        critical_count: prev.critical_count + (Math.random() > 0.9 ? 1 : 0),
        high_count: prev.high_count + (Math.random() > 0.85 ? 1 : 0),
        medium_count: prev.medium_count + (Math.random() > 0.8 ? 1 : 0),
        events_per_second: Math.round((8 + Math.random() * 10) * 10) / 10,
      }));
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const cards: StatCard[] = [
    { label: "Total Events", value: stats.total_events, icon: Activity, color: "text-cyber-cyan", glowClass: "text-glow" },
    { label: "Active Alerts", value: stats.active_alerts, icon: AlertTriangle, color: "text-cyber-amber", glowClass: "text-glow-amber" },
    { label: "Critical", value: stats.critical_count, icon: ShieldAlert, color: "text-cyber-red", glowClass: "text-glow-red" },
    { label: "High", value: stats.high_count, icon: ShieldAlert, color: "text-cyber-amber", glowClass: "text-glow-amber" },
    { label: "Medium", value: stats.medium_count, icon: ShieldCheck, color: "text-yellow-400", glowClass: "" },
    { label: "Events/sec", value: stats.events_per_second, icon: Zap, color: "text-cyber-green", glowClass: "" },
  ];

  return (
    <div className="grid grid-cols-6 gap-2">
      {cards.map((card) => (
        <div
          key={card.label}
          className="panel-glow hud-bracket rounded-sm p-3 flex items-center gap-3"
        >
          <card.icon className={`w-5 h-5 ${card.color} shrink-0`} />
          <div className="min-w-0">
            <div className={`text-lg font-bold tabular-nums ${card.color} ${card.glowClass}`}>
              {typeof card.value === "number" && card.value > 999
                ? card.value.toLocaleString()
                : card.value}
            </div>
            <div className="text-[9px] uppercase tracking-wider text-slate-500 truncate">
              {card.label}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
