"use client";

import { Activity, AlertTriangle, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import type { DashboardStats } from "@/lib/types";

interface StatCard {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
  glowClass: string;
}

interface StatsCardsProps {
  stats: DashboardStats | null;
}

export default function StatsCards({ stats }: StatsCardsProps) {
  const s = stats ?? {
    total_events: 0,
    active_alerts: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    events_per_second: 0,
    top_attack_types: [],
    threat_origins: [],
  };

  const cards: StatCard[] = [
    { label: "Total Events", value: s.total_events, icon: Activity, color: "text-cyber-cyan", glowClass: "text-glow" },
    { label: "Active Alerts", value: s.active_alerts, icon: AlertTriangle, color: "text-cyber-amber", glowClass: "text-glow-amber" },
    { label: "Critical", value: s.critical_count, icon: ShieldAlert, color: "text-cyber-red", glowClass: "text-glow-red" },
    { label: "High", value: s.high_count, icon: ShieldAlert, color: "text-cyber-amber", glowClass: "text-glow-amber" },
    { label: "Medium", value: s.medium_count, icon: ShieldCheck, color: "text-yellow-400", glowClass: "" },
    { label: "Events/sec", value: s.events_per_second, icon: Zap, color: "text-cyber-green", glowClass: "" },
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
