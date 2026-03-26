"use client";

import Header from "@/components/dashboard/Header";
import StatsCards from "@/components/dashboard/StatsCards";
import AlertFeed from "@/components/dashboard/AlertFeed";
import ThreatGlobe from "@/components/globe/ThreatGlobe";
import NetworkTopology from "@/components/graph/NetworkTopology";
import AttackMatrix from "@/components/attack-matrix/AttackMatrix";
import KillChainTimeline from "@/components/kill-chain/KillChainTimeline";
import Panel from "@/components/ui/Panel";

export default function DashboardPage() {
  return (
    <div className="min-h-screen bg-navy-900 grid-bg flex flex-col">
      {/* Top Header Bar */}
      <Header />

      {/* Stats Row */}
      <div className="px-3 pt-3">
        <StatsCards />
      </div>

      {/* Main COP Grid */}
      <div className="flex-1 grid grid-cols-12 grid-rows-[1fr_1fr] gap-3 p-3 min-h-0">
        {/* Top Left: 3D Threat Globe (8 cols) */}
        <div className="col-span-8 row-span-1 min-h-[360px]">
          <Panel title="Global Threat Map" className="h-full" noPad>
            <div className="h-full w-full">
              <ThreatGlobe />
            </div>
          </Panel>
        </div>

        {/* Top Right: Alert Feed (4 cols) */}
        <div className="col-span-4 row-span-1 min-h-[360px]">
          <Panel title="Real-Time Alert Feed" className="h-full flex flex-col" noPad>
            <AlertFeed />
          </Panel>
        </div>

        {/* Bottom Left: Network Topology (4 cols) */}
        <div className="col-span-4 row-span-1 min-h-[300px]">
          <Panel title="Network Topology" className="h-full" noPad>
            <NetworkTopology />
          </Panel>
        </div>

        {/* Bottom Center: ATT&CK Matrix (4 cols) */}
        <div className="col-span-4 row-span-1 min-h-[300px]">
          <Panel title="MITRE ATT&CK Matrix" className="h-full" noPad>
            <AttackMatrix />
          </Panel>
        </div>

        {/* Bottom Right: Kill Chain + Stats (4 cols) */}
        <div className="col-span-4 row-span-1 min-h-[300px]">
          <Panel title="Cyber Kill Chain" className="h-full" noPad>
            <KillChainTimeline />
          </Panel>
        </div>
      </div>
    </div>
  );
}
