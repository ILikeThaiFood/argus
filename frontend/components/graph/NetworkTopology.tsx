"use client";

import { useEffect, useRef } from "react";
import * as d3 from "d3";
import type { NetworkTopology as NetworkTopologyType, NetworkEntity, NetworkEdge } from "@/lib/types";

interface NetworkTopologyProps {
  topology: NetworkTopologyType | null;
}

// Fallback mock data used when backend is unavailable
const FALLBACK_NODES: NetworkEntity[] = [
  { id: "fw-01", type: "service", name: "Firewall", properties: {}, risk_score: 15 },
  { id: "ids-01", type: "service", name: "IDS-Sensor", properties: {}, risk_score: 10 },
  { id: "web-01", type: "host", name: "Web-01", properties: {}, risk_score: 45 },
  { id: "db-01", type: "host", name: "DB-Primary", properties: {}, risk_score: 55 },
  { id: "dc-01", type: "host", name: "Domain-Controller", properties: {}, risk_score: 70 },
  { id: "attacker-1", type: "ip", name: "223.71.x.x", properties: {}, risk_score: 95 },
];

const FALLBACK_EDGES: NetworkEdge[] = [
  { source: "attacker-1", target: "fw-01", label: "scan", weight: 3 },
  { source: "fw-01", target: "ids-01", label: "mirror", weight: 1 },
  { source: "fw-01", target: "web-01", label: "HTTPS", weight: 2 },
  { source: "web-01", target: "db-01", label: "SQL", weight: 2.5 },
  { source: "dc-01", target: "web-01", label: "lateral SMB", weight: 4 },
];

interface D3Node extends NetworkEntity {
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
}

interface D3Link {
  source: string | D3Node;
  target: string | D3Node;
  label: string;
  weight: number;
}

const riskColor = (score: number): string => {
  if (score >= 80) return "#ff2d55";
  if (score >= 60) return "#ff6b35";
  if (score >= 40) return "#ffaa00";
  if (score >= 20) return "#00ffd5";
  return "#0088ff";
};

export default function NetworkTopology({ topology }: NetworkTopologyProps) {
  const svgRef = useRef<SVGSVGElement>(null);

  const nodes = topology?.nodes ?? FALLBACK_NODES;
  const edges = topology?.edges ?? FALLBACK_EDGES;

  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const container = svgRef.current.parentElement;
    const width = container?.clientWidth ?? 500;
    const height = container?.clientHeight ?? 400;

    svg.attr("width", width).attr("height", height);

    const g = svg.append("g");

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    const d3Nodes: D3Node[] = nodes.map((d) => ({ ...d }));
    const d3Links: D3Link[] = edges.map((d) => ({ ...d }));

    const simulation = d3.forceSimulation(d3Nodes as any)
      .force("link", d3.forceLink(d3Links as any).id((d: any) => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(25));

    const link = g.append("g")
      .selectAll("line")
      .data(d3Links)
      .join("line")
      .attr("stroke", (d) => (d.weight >= 3 ? "#ff2d55" : "#1a1f2e"))
      .attr("stroke-width", (d) => Math.max(1, d.weight * 0.8))
      .attr("stroke-opacity", (d) => (d.weight >= 3 ? 0.6 : 0.3));

    const node = g.append("g")
      .selectAll("g")
      .data(d3Nodes)
      .join("g")
      .call(d3.drag<any, D3Node>()
        .on("start", (event, d: any) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (event, d: any) => { d.fx = event.x; d.fy = event.y; })
        .on("end", (event, d: any) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        })
      );

    node.each(function (d) {
      const el = d3.select(this);
      const color = riskColor(d.risk_score);
      const size = 6 + (d.risk_score / 100) * 8;

      if (d.type === "ip") {
        el.append("circle").attr("r", size).attr("fill", color).attr("opacity", 0.8);
      } else if (d.type === "host") {
        el.append("rect").attr("width", size * 2).attr("height", size * 2)
          .attr("x", -size).attr("y", -size)
          .attr("fill", color).attr("opacity", 0.8).attr("rx", 2);
      } else if (d.type === "user") {
        const s = size * 1.3;
        el.append("polygon")
          .attr("points", `0,${-s} ${s},${s} ${-s},${s}`)
          .attr("fill", color).attr("opacity", 0.8);
      } else {
        const s = size * 1.2;
        el.append("polygon")
          .attr("points", `0,${-s} ${s},0 0,${s} ${-s},0`)
          .attr("fill", color).attr("opacity", 0.8);
      }

      el.append("text")
        .text(d.name)
        .attr("dy", size + 12)
        .attr("text-anchor", "middle")
        .attr("fill", "#94a3b8")
        .attr("font-size", "8px")
        .attr("font-family", "JetBrains Mono, monospace");

      if (d.risk_score >= 70) {
        el.append("circle")
          .attr("r", size + 4)
          .attr("fill", "none")
          .attr("stroke", color)
          .attr("stroke-width", 1)
          .attr("opacity", 0.3);
      }
    });

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);
      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    return () => { simulation.stop(); };
  }, [nodes, edges]);

  return (
    <div className="w-full h-full">
      <svg ref={svgRef} className="w-full h-full" />
    </div>
  );
}
