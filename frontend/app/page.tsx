"use client";

import { useEffect, useState } from "react";
import dynamic from "next/dynamic";
import Header from "@/components/dashboard/Header";
import StatsCards from "@/components/dashboard/StatsCards";
import AlertFeed from "@/components/dashboard/AlertFeed";
import NetworkTopology from "@/components/graph/NetworkTopology";
import AttackMatrix from "@/components/attack-matrix/AttackMatrix";
import KillChainTimeline from "@/components/kill-chain/KillChainTimeline";
import Panel from "@/components/ui/Panel";

const ThreatGlobe = dynamic(() => import("@/components/globe/ThreatGlobe"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center text-slate-600 text-sm">
      Loading 3D Globe...
    </div>
  ),
});
import { useWebSocket } from "@/lib/websocket";
import {
  fetchAttackMatrix,
  fetchKillChain,
  fetchNetworkTopology,
} from "@/lib/api";
import type {
  AttackTechnique,
  KillChainPhase,
  KillChainEvent,
  NetworkTopology as NetworkTopologyType,
} from "@/lib/types";

export default function DashboardPage() {
  const { events, alerts, stats, connectionState } = useWebSocket();

  const [techniques, setTechniques] = useState<AttackTechnique[]>([]);
  const [killChainPhases, setKillChainPhases] = useState<KillChainPhase[]>([]);
  const [killChainEvents, setKillChainEvents] = useState<KillChainEvent[]>([]);
  const [topology, setTopology] = useState<NetworkTopologyType | null>(null);

  useEffect(() => {
    fetchAttackMatrix()
      .then((d) => setTechniques(d.techniques))
      .catch(() => {});
    fetchKillChain()
      .then((d) => {
        setKillChainPhases(d.phases);
        setKillChainEvents(d.recent_events);
      })
      .catch(() => {});
    fetchNetworkTopology()
      .then((d) => setTopology(d))
      .catch(() => {});
  }, []);

  // Re-fetch attack matrix and kill chain periodically
  useEffect(() => {
    const interval = setInterval(() => {
      fetchAttackMatrix()
        .then((d) => setTechniques(d.techniques))
        .catch(() => {});
      fetchKillChain()
        .then((d) => {
          setKillChainPhases(d.phases);
          setKillChainEvents(d.recent_events);
        })
        .catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-navy-900 grid-bg flex flex-col">
      <Header stats={stats} connectionState={connectionState} />

      <div className="px-3 pt-3">
        <StatsCards stats={stats} />
      </div>

      <div className="flex-1 grid grid-cols-12 grid-rows-[1fr_1fr] gap-3 p-3 min-h-0">
        <div className="col-span-8 row-span-1 min-h-[360px]">
          <Panel title="Global Threat Map" className="h-full" noPad>
            <div className="h-full w-full">
              <ThreatGlobe origins={stats?.threat_origins ?? []} />
            </div>
          </Panel>
        </div>

        <div className="col-span-4 row-span-1 min-h-[360px]">
          <Panel title="Real-Time Alert Feed" className="h-full flex flex-col" noPad>
            <AlertFeed alerts={alerts} />
          </Panel>
        </div>

        <div className="col-span-4 row-span-1 min-h-[300px]">
          <Panel title="Network Topology" className="h-full" noPad>
            <NetworkTopology topology={topology} />
          </Panel>
        </div>

        <div className="col-span-4 row-span-1 min-h-[300px]">
          <Panel title="MITRE ATT&CK Matrix" className="h-full" noPad>
            <AttackMatrix techniques={techniques} />
          </Panel>
        </div>

        <div className="col-span-4 row-span-1 min-h-[300px]">
          <Panel title="Cyber Kill Chain" className="h-full" noPad>
            <KillChainTimeline phases={killChainPhases} recentEvents={killChainEvents} />
          </Panel>
        </div>
      </div>
    </div>
  );
}
