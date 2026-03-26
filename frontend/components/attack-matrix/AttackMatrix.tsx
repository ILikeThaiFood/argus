"use client";

import { useState } from "react";
import type { AttackTechnique } from "@/lib/types";

interface AttackMatrixProps {
  techniques: AttackTechnique[];
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

function cellColor(count: number, maxCount: number): string {
  if (count === 0 || maxCount === 0) return "bg-navy-800/40";
  const intensity = count / maxCount;
  if (intensity > 0.7) return "bg-cyber-red/40 border-cyber-red/30";
  if (intensity > 0.4) return "bg-cyber-amber/30 border-cyber-amber/20";
  if (intensity > 0.15) return "bg-cyber-cyan/20 border-cyber-cyan/15";
  return "bg-cyber-blue/15 border-cyber-blue/10";
}

export default function AttackMatrix({ techniques }: AttackMatrixProps) {
  const [hoveredTech, setHoveredTech] = useState<AttackTechnique | null>(null);

  const maxCount = techniques.length > 0
    ? Math.max(...techniques.map((t) => t.detection_count))
    : 1;

  return (
    <div className="w-full h-full flex flex-col p-2">
      {/* Hover tooltip */}
      {hoveredTech && (
        <div className="mb-2 px-2 py-1 bg-navy-700 border border-navy-500/50 rounded-sm text-[10px]">
          <span className="text-cyber-cyan font-bold">{hoveredTech.technique_id}</span>
          <span className="text-slate-400"> - {hoveredTech.name}</span>
          <span className="text-slate-500"> | {hoveredTech.tactic}</span>
          <span className="text-cyber-green ml-2">{hoveredTech.detection_count} detections</span>
        </div>
      )}

      {techniques.length === 0 && (
        <div className="flex-1 flex items-center justify-center text-slate-600 text-[11px]">
          Loading ATT&CK matrix...
        </div>
      )}

      {/* Matrix grid */}
      {techniques.length > 0 && (
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
              const techs = techniques.filter((t) => t.tactic === tactic);
              return (
                <div key={tactic} className="flex flex-col gap-0.5">
                  {techs.length > 0 ? techs.map((tech) => (
                    <div
                      key={tech.technique_id}
                      className={`px-1 py-1.5 rounded-sm border cursor-pointer transition-all hover:scale-105 ${cellColor(tech.detection_count, maxCount)}`}
                      onMouseEnter={() => setHoveredTech(tech)}
                      onMouseLeave={() => setHoveredTech(null)}
                    >
                      <div className="text-[7px] text-slate-400 truncate">{tech.technique_id}</div>
                      <div className="text-[8px] text-slate-300 truncate font-medium">{tech.name}</div>
                      {tech.detection_count > 0 && (
                        <div className="text-[8px] text-cyber-cyan tabular-nums mt-0.5">{tech.detection_count}</div>
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
      )}
    </div>
  );
}
