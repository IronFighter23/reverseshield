/**
 * Typed API client. One function per SPEC §3.5 endpoint. Kept deliberately thin — no
 * caching, no retries, no react-query. If we grow real state complexity, that's when a
 * library earns its place.
 */

export type EventType =
  | "honeypot_triggered"
  | "canary_embedded"
  | "rate_limit_exceeded"
  | "behavioral_score"
  | "attestation_failed"
  | "request_fingerprint";

export interface Site {
  site_id: string;
  name: string;
  created_at: string;
}

export interface Summary {
  site_id: string;
  range: string;
  since: string;
  total_events: number;
  by_type: Record<EventType, number>;
  score_bands: {
    likely_human: number;
    suspicious: number;
    likely_bot: number;
  };
}

export interface EventRecord {
  event_id: string;
  site_id: string;
  timestamp: string;
  source: "browser" | "server";
  session_id: string;
  type: EventType;
  score_delta: number;
  details: Record<string, unknown>;
  ip_hash: string | null;
  user_agent: string | null;
  asn: string | null;
  received_at: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    credentials: "include",
  });
  if (!res.ok) {
    const bodyText = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${bodyText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  listSites: () => req<{ sites: Site[] }>("/api/v1/sites"),

  registerSite: (name: string) =>
    req<{ site_id: string; name: string; install_snippet: string }>(
      "/api/v1/sites",
      { method: "POST", body: JSON.stringify({ name }) },
    ),

  summary: (siteId: string, range = "24h") =>
    req<Summary>(`/api/v1/sites/${siteId}/summary?range=${encodeURIComponent(range)}`),

  events: (siteId: string, type?: EventType, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (type) params.set("type", type);
    return req<{ events: EventRecord[]; count: number }>(
      `/api/v1/sites/${siteId}/events?${params}`,
    );
  },
};
