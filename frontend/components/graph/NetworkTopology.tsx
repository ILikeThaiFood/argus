"use client";

import { useEffect, useRef } from "react";
import * as d3 from "d3";

interface Node {
  id: string;
  type: "ip" | "host" | "user" | "service";
  name: string;
  risk_score: number;
  x?: number;
  y?: number;
}

interface Link {
  source: string | Node;
  target: string | Node;
  label: string;
  weight: number;
}

const MOCK_NODES: Node[] = [
  { id: "fw-01", type: "service", name: "Firewall", risk_score: 15 },
  { id: "ids-01", type: "service", name: "IDS-Sensor", risk_score: 10 },
  { id: "web-01", type: "host", name: "Web-01", risk_score: 45 },
  { id: "web-02", type: "host", name: "Web-02", risk_score: 30 },
  { id: "db-01", type: "host", name: "DB-Primary", risk_score: 55 },
  { id: "app-01", type: "host", name: "App-01", risk_score: 40 },
  { id: "dc-01", type: "host", name: "Domain-Controller", risk_score: 70 },
  { id: "vpn-01", type: "service", name: "VPN-Gateway", risk_score: 20 },
  { id: "mail-01", type: "host", name: "Mail-Server", risk_score: 50 },
  { id: "admin", type: "user", name: "admin@corp", risk_score: 65 },
  { id: "analyst", type: "user", name: "analyst@corp", risk_score: 20 },
  { id: "attacker-1", type: "ip", name: "223.71.x.x", risk_score: 95 },
  { id: "attacker-2", type: "ip", name: "5.188.x.x", risk_score: 90 },
  { id: "dns-01", type: "service", name: "DNS-Server", risk_score: 30 },
  { id: "siem-01", type: "service", name: "SIEM", risk_score: 10 },
];

const MOCK_LINKS: Link[] = [
  { source: "attacker-1", target: "fw-01", label: "scan", weight: 3 },
  { source: "attacker-2", target: "vpn-01", label: "brute force", weight: 4 },
  { source: "fw-01", target: "ids-01", label: "mirror", weight: 1 },
  { source: "fw-01", target: "web-01", label: "HTTPS", weight: 2 },
  { source: "fw-01", target: "web-02", label: "HTTPS", weight: 1.5 },
  { source: "fw-01", target: "mail-01", label: "SMTP", weight: 1 },
  { source: "web-01", target: "app-01", label: "API", weight: 2 },
  { source: "app-01", target: "db-01", label: "SQL", weight: 2.5 },
  { source: "vpn-01", target: "dc-01", label: "LDAP", weight: 2 },
  { source: "admin", target: "dc-01", label: "RDP", weight: 3 },
  { source: "analyst", target: "siem-01", label: "dashboard", weight: 1 },
  { source: "dc-01", target: "app-01", label: "lateral SMB", weight: 4 },
  { source: "ids-01", target: "siem-01", label: "alerts", weight: 1 },
  { source: "web-01", target: "dns-01", label: "DNS", weight: 1 },
];

const typeShape = (type: string): string => {
  switch (type) {
    case "ip": return "circle";
    case "host": return "rect";
    case "user": return "triangle";
    case "service": return "diamond";
    default: return "circle";
  }
};

const riskColor = (score: number): string => {
  if (score >= 80) return "#ff2d55";
  if (score >= 60) return "#ff6b35";
  if (score >= 40) return "#ffaa00";
  if (score >= 20) return "#00ffd5";
  return "#0088ff";
};

export default function NetworkTopology() {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const container = svgRef.current.parentElement;
    const width = container?.clientWidth ?? 500;
    const height = container?.clientHeight ?? 400;

    svg.attr("width", width).attr("height", height);

    const g = svg.append("g");

    // Zoom
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 4])
      .on("zoom", (event) => g.attr("transform", event.transform));
    svg.call(zoom);

    const nodes: Node[] = MOCK_NODES.map((d) => ({ ...d }));
    const links: Link[] = MOCK_LINKS.map((d) => ({ ...d }));

    const simulation = d3.forceSimulation(nodes as any)
      .force("link", d3.forceLink(links as any).id((d: any) => d.id).distance(80))
      .force("charge", d3.forceManyBody().strength(-200))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(25));

    // Links
    const link = g.append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", (d) => (d.weight >= 3 ? "#ff2d55" : "#1a1f2e"))
      .attr("stroke-width", (d) => Math.max(1, d.weight * 0.8))
      .attr("stroke-opacity", (d) => (d.weight >= 3 ? 0.6 : 0.3));

    // Nodes
    const node = g.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .call(d3.drag<SVGGElement, Node>()
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

    // Draw shapes based on type
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

      // Label
      el.append("text")
        .text(d.name)
        .attr("dy", size + 12)
        .attr("text-anchor", "middle")
        .attr("fill", "#94a3b8")
        .attr("font-size", "8px")
        .attr("font-family", "JetBrains Mono, monospace");

      // Glow for high-risk nodes
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
  }, []);

  return (
    <div className="w-full h-full">
      <svg ref={svgRef} className="w-full h-full" />
    </div>
  );
}
