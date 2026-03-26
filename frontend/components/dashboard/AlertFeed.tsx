"use client";

import { useEffect, useRef, useState } from "react";
import Badge from "@/components/ui/Badge";
import { ArrowRight, ChevronDown, ChevronUp } from "lucide-react";

interface AlertItem {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  source_ip: string;
  dest_ip: string;
  mitre_technique: string;
  timestamp: string;
  confidence: number;
  shap_values?: Record<string, number>;
}

const MOCK_ALERTS: AlertItem[] = [
  { id: "1", severity: "critical", title: "C2 Communication - T1071", source_ip: "223.71.167.42", dest_ip: "10.0.1.5", mitre_technique: "T1071", timestamp: new Date().toISOString(), confidence: 0.96, shap_values: { src_ip_reputation: 0.35, dst_port_anomaly: 0.22, packet_rate: 0.18 } },
  { id: "2", severity: "high", title: "Brute Force - T1110", source_ip: "5.188.62.15", dest_ip: "10.0.2.10", mitre_technique: "T1110", timestamp: new Date().toISOString(), confidence: 0.89, shap_values: { num_failed_logins: 0.41, src_ip_reputation: 0.28, connection_frequency: 0.15 } },
  { id: "3", severity: "critical", title: "Data Exfiltration - T1041", source_ip: "10.0.1.15", dest_ip: "185.220.101.42", mitre_technique: "T1041", timestamp: new Date().toISOString(), confidence: 0.94 },
  { id: "4", severity: "medium", title: "Port Scan - T1046", source_ip: "61.160.224.88", dest_ip: "10.0.3.8", mitre_technique: "T1046", timestamp: new Date().toISOString(), confidence: 0.78 },
  { id: "5", severity: "high", title: "Lateral Movement - T1021", source_ip: "10.0.1.5", dest_ip: "10.0.2.50", mitre_technique: "T1021", timestamp: new Date().toISOString(), confidence: 0.87 },
  { id: "6", severity: "medium", title: "DNS Tunneling - T1572", source_ip: "10.0.3.25", dest_ip: "8.8.8.8", mitre_technique: "T1572", timestamp: new Date().toISOString(), confidence: 0.72 },
  { id: "7", severity: "critical", title: "Privilege Escalation - T1068", source_ip: "10.0.2.100", dest_ip: "10.0.1.20", mitre_technique: "T1068", timestamp: new Date().toISOString(), confidence: 0.93 },
  { id: "8", severity: "high", title: "Malware Delivery - T1204", source_ip: "91.240.118.55", dest_ip: "10.0.1.10", mitre_technique: "T1204", timestamp: new Date().toISOString(), confidence: 0.91 },
];

export default function AlertFeed() {
  const [alerts, setAlerts] = useState<AlertItem[]>(MOCK_ALERTS);
  const [filter, setFilter] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  // Simulate new alerts
  useEffect(() => {
    const interval = setInterval(() => {
      const severities: AlertItem["severity"][] = ["critical", "high", "medium", "low"];
      const techniques = ["T1071", "T1110", "T1046", "T1021", "T1041", "T1572", "T1068", "T1498", "T1204"];
      const names = ["C2 Communication", "Brute Force", "Port Scan", "Lateral Movement", "Data Exfiltration", "DNS Tunneling", "Privilege Escalation", "DDoS", "Malware Delivery"];
      const idx = Math.floor(Math.random() * techniques.length);
      const sev = severities[Math.floor(Math.random() * 3)];
      const newAlert: AlertItem = {
        id: Date.now().toString(),
        severity: sev,
        title: `${names[idx]} - ${techniques[idx]}`,
        source_ip: `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
        dest_ip: `10.0.${Math.floor(Math.random() * 4)}.${Math.floor(Math.random() * 254) + 1}`,
        mitre_technique: techniques[idx],
        timestamp: new Date().toISOString(),
        confidence: Math.round((0.7 + Math.random() * 0.29) * 100) / 100,
      };
      setAlerts((prev) => [newAlert, ...prev].slice(0, 100));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

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
