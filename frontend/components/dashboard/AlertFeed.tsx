"use client";

import { useRef, useState } from "react";
import Badge from "@/components/ui/Badge";
import { ArrowRight } from "lucide-react";
import type { Alert } from "@/lib/types";

interface AlertFeedProps {
  alerts: Alert[];
}

export default function AlertFeed({ alerts }: AlertFeedProps) {
  const [filter, setFilter] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  const filtered = filter ? alerts.filter((a) => a.severity === filter) : alerts;

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <div className="flex flex-col h-full">
      {/* Severity Filters */}
      <div className="flex gap-1 px-3 pt-2 pb-1">
        {(["critical", "high", "medium", "low"] as const).map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(filter === sev ? null : sev)}
            className={`text-[9px] uppercase px-2 py-0.5 rounded-sm border transition-all ${
              filter === sev
                ? sev === "critical" ? "border-cyber-red/60 bg-cyber-red/20 text-cyber-red"
                : sev === "high" ? "border-cyber-amber/60 bg-cyber-amber/20 text-cyber-amber"
                : sev === "medium" ? "border-yellow-500/60 bg-yellow-500/20 text-yellow-400"
                : "border-cyber-cyan/60 bg-cyber-cyan/20 text-cyber-cyan"
                : "border-navy-600/50 text-slate-500 hover:text-slate-300"
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Alert List */}
      <div ref={feedRef} className="flex-1 overflow-y-auto px-2 pb-2 space-y-1">
        {filtered.length === 0 && (
          <div className="text-center text-slate-600 text-[11px] mt-8">
            {alerts.length === 0 ? "Waiting for alerts..." : "No alerts match filter"}
          </div>
        )}
        {filtered.map((alert) => (
          <div
            key={alert.id}
            className="p-2 rounded-sm bg-navy-800/60 border border-navy-600/30 hover:border-navy-500/50 cursor-pointer transition-all animate-slide-in"
            onClick={() => setExpandedId(expandedId === alert.id ? null : alert.id)}
          >
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <Badge severity={alert.severity}>{alert.severity}</Badge>
                <span className="text-[11px] text-slate-300 truncate font-medium">
                  {alert.title}
                </span>
              </div>
              <span className="text-[9px] text-slate-500 tabular-nums shrink-0">
                {formatTime(alert.timestamp)}
              </span>
            </div>
            <div className="flex items-center gap-1 mt-1 text-[10px] text-slate-500">
              <span className="text-cyber-red">{alert.source_ip}</span>
              <ArrowRight className="w-3 h-3" />
              <span className="text-cyber-cyan">{alert.dest_ip}</span>
              <span className="ml-auto text-[9px] text-slate-600">
                {Math.round(alert.confidence * 100)}% conf
              </span>
            </div>

            {/* Expanded SHAP values */}
            {expandedId === alert.id && alert.shap_values && (
              <div className="mt-2 pt-2 border-t border-navy-600/30">
                <div className="text-[9px] text-slate-500 uppercase tracking-wider mb-1">
                  SHAP Feature Attribution
                </div>
                {Object.entries(alert.shap_values)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 5)
                  .map(([feature, value]) => (
                    <div key={feature} className="flex items-center gap-2 mb-0.5">
                      <span className="text-[9px] text-slate-400 w-32 truncate">{feature}</span>
                      <div className="flex-1 h-1.5 bg-navy-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-cyber-cyan to-cyber-blue rounded-full"
                          style={{ width: `${Math.min(value * 250, 100)}%` }}
                        />
                      </div>
                      <span className="text-[9px] text-cyber-cyan tabular-nums w-8 text-right">
                        {value.toFixed(2)}
                      </span>
                    </div>
                  ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
