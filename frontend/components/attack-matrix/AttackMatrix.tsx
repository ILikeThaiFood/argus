"use client";

import { useState } from "react";

interface Technique {
  id: string;
  name: string;
  tactic: string;
  count: number;
}

const TACTICS = [
  "Reconnaissance",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "C2",
  "Exfiltration",
  "Impact",
];

const TECHNIQUES: Technique[] = [
  { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance", count: 23 },
  { id: "T1592", name: "Gather Host Info", tactic: "Reconnaissance", count: 8 },
  { id: "T1589", name: "Gather Identity", tactic: "Reconnaissance", count: 5 },
  { id: "T1190", name: "Exploit Public App", tactic: "Initial Access", count: 15 },
  { id: "T1566", name: "Phishing", tactic: "Initial Access", count: 12 },
  { id: "T1133", name: "External Remote Svc", tactic: "Initial Access", count: 7 },
  { id: "T1059", name: "Scripting Interpreter", tactic: "Execution", count: 18 },
  { id: "T1204", name: "User Execution", tactic: "Execution", count: 11 },
  { id: "T1547", name: "Autostart Execution", tactic: "Persistence", count: 6 },
  { id: "T1053", name: "Scheduled Task", tactic: "Persistence", count: 4 },
  { id: "T1068", name: "Priv Esc Exploit", tactic: "Privilege Escalation", count: 14 },
  { id: "T1548", name: "Abuse Elevation", tactic: "Privilege Escalation", count: 9 },
  { id: "T1070", name: "Indicator Removal", tactic: "Defense Evasion", count: 7 },
  { id: "T1036", name: "Masquerading", tactic: "Defense Evasion", count: 5 },
  { id: "T1027", name: "Obfuscated Files", tactic: "Defense Evasion", count: 3 },
  { id: "T1110", name: "Brute Force", tactic: "Credential Access", count: 26 },
  { id: "T1003", name: "Credential Dumping", tactic: "Credential Access", count: 10 },
  { id: "T1046", name: "Network Svc Discovery", tactic: "Discovery", count: 19 },
  { id: "T1082", name: "System Info Discovery", tactic: "Discovery", count: 8 },
  { id: "T1021", name: "Remote Services", tactic: "Lateral Movement", count: 16 },
  { id: "T1570", name: "Lateral Tool Xfer", tactic: "Lateral Movement", count: 7 },
  { id: "T1005", name: "Data from Local Sys", tactic: "Collection", count: 4 },
  { id: "T1071", name: "App Layer Protocol", tactic: "C2", count: 22 },
  { id: "T1572", name: "Protocol Tunneling", tactic: "C2", count: 13 },
  { id: "T1573", name: "Encrypted Channel", tactic: "C2", count: 9 },
  { id: "T1041", name: "Exfil Over C2", tactic: "Exfiltration", count: 11 },
  { id: "T1048", name: "Exfil Alt Protocol", tactic: "Exfiltration", count: 5 },
  { id: "T1498", name: "Network DoS", tactic: "Impact", count: 20 },
  { id: "T1486", name: "Data Encrypted", tactic: "Impact", count: 3 },
];

const maxCount = Math.max(...TECHNIQUES.map((t) => t.count));

function cellColor(count: number): string {
  if (count === 0) return "bg-navy-800/40";
  const intensity = count / maxCount;
  if (intensity > 0.7) return "bg-cyber-red/40 border-cyber-red/30";
  if (intensity > 0.4) return "bg-cyber-amber/30 border-cyber-amber/20";
  if (intensity > 0.15) return "bg-cyber-cyan/20 border-cyber-cyan/15";
  return "bg-cyber-blue/15 border-cyber-blue/10";
}

export default function AttackMatrix() {
  const [hoveredTech, setHoveredTech] = useState<Technique | null>(null);

  return (
    <div className="w-full h-full flex flex-col p-2">
      {/* Hover tooltip */}
      {hoveredTech && (
        <div className="mb-2 px-2 py-1 bg-navy-700 border border-navy-500/50 rounded-sm text-[10px]">
          <span className="text-cyber-cyan font-bold">{hoveredTech.id}</span>
          <span className="text-slate-400"> - {hoveredTech.name}</span>
          <span className="text-slate-500"> | {hoveredTech.tactic}</span>
          <span className="text-cyber-green ml-2">{hoveredTech.count} detections</span>
        </div>
      )}

      {/* Matrix grid */}
      <div className="flex-1 overflow-x-auto overflow-y-auto">
        <div className="grid gap-0.5" style={{ gridTemplateColumns: `repeat(${TACTICS.length}, minmax(70px, 1fr))` }}>
          {/* Tactic headers */}
          {TACTICS.map((tactic) => (
            <div
              key={tactic}
              className="text-[7px] text-center uppercase tracking-wider text-cyber-cyan/70 py-1 px-0.5 border-b border-navy-600/30 font-semibold truncate"
              title={tactic}
            >
              {tactic}
            </div>
          ))}

          {/* Technique cells */}
          {TACTICS.map((tactic) => {
            const techs = TECHNIQUES.filter((t) => t.tactic === tactic);
            return (
              <div key={tactic} className="flex flex-col gap-0.5">
                {techs.length > 0 ? techs.map((tech) => (
                  <div
                    key={tech.id}
                    className={`px-1 py-1.5 rounded-sm border cursor-pointer transition-all hover:scale-105 ${cellColor(tech.count)}`}
                    onMouseEnter={() => setHoveredTech(tech)}
                    onMouseLeave={() => setHoveredTech(null)}
                  >
                    <div className="text-[7px] text-slate-400 truncate">{tech.id}</div>
                    <div className="text-[8px] text-slate-300 truncate font-medium">{tech.name}</div>
                    {tech.count > 0 && (
                      <div className="text-[8px] text-cyber-cyan tabular-nums mt-0.5">{tech.count}</div>
                    )}
                  </div>
                )) : (
                  <div className="px-1 py-2 text-[8px] text-slate-600 text-center">-</div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
