import type {
  Alert,
  AlertListResponse,
  AttackTechnique,
  DashboardStats,
  KillChainResponse,
  NetworkTopology,
  OCSFEvent,
  ThreatIntelIOC,
  ThreatOrigin,
} from "./types";

const BASE_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export async function fetchStats(): Promise<DashboardStats> {
  return apiFetch<DashboardStats>("/api/stats");
}

export async function fetchAlerts(
  page = 1,
  pageSize = 50,
  severity?: string,
): Promise<AlertListResponse> {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });
  if (severity) params.set("severity", severity);
  return apiFetch<AlertListResponse>(`/api/alerts?${params}`);
}

export async function fetchAlert(id: string): Promise<Alert> {
  return apiFetch<Alert>(`/api/alerts/${id}`);
}

export async function fetchEvents(
  page = 1,
  pageSize = 50,
): Promise<{ total: number; events: OCSFEvent[] }> {
  return apiFetch(`/api/events?page=${page}&page_size=${pageSize}`);
}

export async function fetchAttackMatrix(): Promise<{
  techniques: AttackTechnique[];
}> {
  return apiFetch("/api/attack-matrix");
}

export async function fetchKillChain(): Promise<KillChainResponse> {
  return apiFetch<KillChainResponse>("/api/kill-chain");
}

export async function fetchNetworkTopology(): Promise<NetworkTopology> {
  return apiFetch<NetworkTopology>("/api/network/topology");
}

export async function fetchThreatOrigins(): Promise<{
  origins: ThreatOrigin[];
}> {
  return apiFetch("/api/threat-origins");
}

export async function fetchIOCs(): Promise<{
  iocs: ThreatIntelIOC[];
}> {
  return apiFetch("/api/threat-intel/iocs");
}

export async function fetchHealth(): Promise<Record<string, any>> {
  return apiFetch("/api/health");
}
