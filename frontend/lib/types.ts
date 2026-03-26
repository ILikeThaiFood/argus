// Types matching the backend Pydantic schemas exactly

export interface Alert {
  id: string;
  event_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  mitre_tactic: string;
  mitre_technique: string;
  confidence: number;
  shap_values?: Record<string, number>;
  timestamp: string;
  source_ip: string;
  dest_ip: string;
  kill_chain_phase: string;
}

export interface OCSFEvent {
  id: string;
  time: string;
  severity_id: number;
  type_uid: number;
  category_uid: number;
  class_uid: number;
  activity_id: number;
  status: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  metadata: Record<string, any>;
  observables: Array<{ type: string; value: string; reputation?: string }>;
}

export interface ThreatIntelIOC {
  id: string;
  type: "ip" | "domain" | "hash" | "cve" | "malware";
  value: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  tags: string[];
  related_ttps: string[];
}

export interface NetworkEntity {
  id: string;
  type: "ip" | "host" | "user" | "service";
  name: string;
  properties: Record<string, any>;
  risk_score: number;
}

export interface NetworkEdge {
  source: string;
  target: string;
  label: string;
  weight: number;
}

export interface NetworkTopology {
  nodes: NetworkEntity[];
  edges: NetworkEdge[];
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  description?: string;
  detection_count: number;
  severity: "critical" | "high" | "medium" | "low";
}

export interface KillChainPhase {
  phase: string;
  label: string;
  count: number;
}

export interface KillChainEvent {
  id: string;
  alert_id: string;
  phase: string;
  timestamp: string;
  description: string;
}

export interface KillChainResponse {
  phases: KillChainPhase[];
  recent_events: KillChainEvent[];
}

export interface DashboardStats {
  total_events: number;
  active_alerts: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  events_per_second: number;
  top_attack_types: string[];
  threat_origins: ThreatOrigin[];
}

export interface ThreatOrigin {
  lat: number;
  lon: number;
  count: number;
  country: string;
}

export interface AlertListResponse {
  total: number;
  page: number;
  page_size: number;
  alerts: Alert[];
}
