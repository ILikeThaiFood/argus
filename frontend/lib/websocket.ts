"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { Alert, OCSFEvent, DashboardStats } from "./types";

const WS_URL =
  process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000";

export type ConnectionState = "connecting" | "connected" | "disconnected";

interface UseWebSocketReturn {
  events: OCSFEvent[];
  alerts: Alert[];
  stats: DashboardStats | null;
  connectionState: ConnectionState;
}

export function useWebSocket(maxItems = 200): UseWebSocketReturn {
  const [events, setEvents] = useState<OCSFEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [connectionState, setConnectionState] =
    useState<ConnectionState>("disconnected");

  const eventsWsRef = useRef<WebSocket | null>(null);
  const alertsWsRef = useRef<WebSocket | null>(null);
  const statsWsRef = useRef<WebSocket | null>(null);
  const reconnectRefs = useRef<NodeJS.Timeout[]>([]);

  const connectWs = useCallback(
    (
      path: string,
      onMessage: (data: any) => void,
      ref: React.MutableRefObject<WebSocket | null>,
      onOpen?: () => void,
    ) => {
      const connect = () => {
        try {
          const ws = new WebSocket(`${WS_URL}${path}`);
          ref.current = ws;

          ws.onopen = () => {
            if (onOpen) onOpen();
          };

          ws.onmessage = (msg) => {
            try {
              const data = JSON.parse(msg.data);
              onMessage(data);
            } catch {
              /* ignore parse errors */
            }
          };

          ws.onclose = () => {
            const timeout = setTimeout(connect, 3000);
            reconnectRefs.current.push(timeout);
          };

          ws.onerror = () => ws.close();
        } catch {
          const timeout = setTimeout(connect, 3000);
          reconnectRefs.current.push(timeout);
        }
      };
      connect();
    },
    [],
  );

  useEffect(() => {
    setConnectionState("connecting");

    connectWs(
      "/api/ws/events",
      (event: OCSFEvent) => {
        setEvents((prev) => [event, ...prev].slice(0, maxItems));
      },
      eventsWsRef,
      () => setConnectionState("connected"),
    );

    connectWs(
      "/api/ws/alerts",
      (alert: Alert) => {
        setAlerts((prev) => [alert, ...prev].slice(0, maxItems));
      },
      alertsWsRef,
    );

    connectWs(
      "/api/ws/stats",
      (data: DashboardStats) => {
        setStats(data);
      },
      statsWsRef,
    );

    return () => {
      eventsWsRef.current?.close();
      alertsWsRef.current?.close();
      statsWsRef.current?.close();
      reconnectRefs.current.forEach(clearTimeout);
    };
  }, [connectWs, maxItems]);

  return { events, alerts, stats, connectionState };
}
