import { useEffect, useState, useCallback } from "react";
import { api, type Site, type Summary, type EventRecord, type EventType } from "./lib/api.js";

const EVENT_TYPE_LABELS: Record<EventType, string> = {
  honeypot_triggered: "Honeypot triggered",
  canary_embedded: "Canary embedded",
  rate_limit_exceeded: "Rate limit exceeded",
  behavioral_score: "Behavioral snapshot",
  attestation_failed: "Attestation failed",
  request_fingerprint: "Request fingerprint",
};

const BAND_STYLES = {
  likely_human: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30",
  suspicious: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  likely_bot: "bg-rose-500/10 text-rose-300 border-rose-500/30",
} as const;

const BAND_LABELS = {
  likely_human: "Likely human",
  suspicious: "Suspicious",
  likely_bot: "Likely bot",
} as const;

export function App(): JSX.Element {
  const [sites, setSites] = useState<Site[]>([]);
  const [selectedSiteId, setSelectedSiteId] = useState<string | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showRegister, setShowRegister] = useState(false);
  const [newSiteName, setNewSiteName] = useState("");
  const [lastInstallSnippet, setLastInstallSnippet] = useState<string | null>(null);

  // Load site list on mount.
  useEffect(() => {
    void refreshSites();
  }, []);

  const refreshSites = useCallback(async () => {
    try {
      const { sites: fetched } = await api.listSites();
      setSites(fetched);
      if (fetched.length > 0 && !selectedSiteId) {
        setSelectedSiteId(fetched[0].site_id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load sites");
    }
  }, [selectedSiteId]);

  // Whenever the selected site changes, reload its summary + events.
  useEffect(() => {
    if (!selectedSiteId) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([api.summary(selectedSiteId, "24h"), api.events(selectedSiteId)])
      .then(([s, e]) => {
        if (cancelled) return;
        setSummary(s);
        setEvents(e.events);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "failed to load site data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedSiteId]);

  async function handleRegister(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    if (!newSiteName.trim()) return;
    try {
      const { site_id, install_snippet } = await api.registerSite(newSiteName.trim());
      setNewSiteName("");
      setShowRegister(false);
      setLastInstallSnippet(install_snippet);
      await refreshSites();
      setSelectedSiteId(site_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "register failed");
    }
  }

  return (
    <div className="min-h-screen p-6 md:p-10">
      <header className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">ReverseShield</h1>
          <p className="text-sm text-slate-400">
            Bot & scraper defense · reporting dashboard
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowRegister((v) => !v)}
          className="rounded-md border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800"
        >
          {showRegister ? "Cancel" : "+ Register site"}
        </button>
      </header>

      {showRegister && (
        <form
          onSubmit={handleRegister}
          className="mb-8 flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/50 p-4"
        >
          <input
            type="text"
            required
            value={newSiteName}
            onChange={(e) => setNewSiteName(e.target.value)}
            placeholder="site name (e.g. example.com)"
            className="flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-slate-500 focus:outline-none"
          />
          <button
            type="submit"
            className="rounded-md bg-slate-100 px-4 py-2 text-sm font-medium text-slate-900 hover:bg-white"
          >
            Register
          </button>
        </form>
      )}

      {lastInstallSnippet && (
        <div className="mb-8 rounded-lg border border-emerald-800/50 bg-emerald-950/30 p-4">
          <div className="mb-2 flex items-center justify-between">
            <p className="text-sm font-medium text-emerald-300">
              Site registered. Copy this snippet into your site&apos;s &lt;head&gt;:
            </p>
            <button
              type="button"
              onClick={() => setLastInstallSnippet(null)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              dismiss
            </button>
          </div>
          <pre className="overflow-x-auto rounded bg-slate-950 p-3 text-xs text-slate-300">
            {lastInstallSnippet}
          </pre>
        </div>
      )}

      {error && (
        <div className="mb-6 rounded-lg border border-rose-800/50 bg-rose-950/30 p-4 text-sm text-rose-300">
          {error}
        </div>
      )}

      {sites.length === 0 ? (
        <EmptyState onClickRegister={() => setShowRegister(true)} />
      ) : (
        <>
          <SiteSelector
            sites={sites}
            selectedSiteId={selectedSiteId}
            onSelect={setSelectedSiteId}
          />
          {loading && <p className="text-sm text-slate-400">Loading…</p>}
          {!loading && summary && (
            <div className="grid gap-6 md:grid-cols-2">
              <SummaryPanel summary={summary} />
              <ScoreBandsPanel summary={summary} />
            </div>
          )}
          {!loading && (
            <div className="mt-8">
              <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">
                Recent events
              </h2>
              <EventsTable events={events} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

function EmptyState({ onClickRegister }: { onClickRegister: () => void }): JSX.Element {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-10 text-center">
      <p className="mb-3 text-slate-300">No sites registered yet.</p>
      <button
        type="button"
        onClick={onClickRegister}
        className="rounded-md bg-slate-100 px-4 py-2 text-sm font-medium text-slate-900 hover:bg-white"
      >
        Register your first site
      </button>
    </div>
  );
}

function SiteSelector({
  sites,
  selectedSiteId,
  onSelect,
}: {
  sites: Site[];
  selectedSiteId: string | null;
  onSelect: (id: string) => void;
}): JSX.Element {
  return (
    <div className="mb-6 flex flex-wrap gap-2">
      {sites.map((s) => (
        <button
          key={s.site_id}
          type="button"
          onClick={() => onSelect(s.site_id)}
          className={
            "rounded-md border px-3 py-1.5 text-sm " +
            (s.site_id === selectedSiteId
              ? "border-slate-500 bg-slate-800 text-slate-100"
              : "border-slate-800 bg-slate-900/50 text-slate-400 hover:text-slate-200")
          }
        >
          {s.name}
        </button>
      ))}
    </div>
  );
}

function SummaryPanel({ summary }: { summary: Summary }): JSX.Element {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-5">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">
        Events by type · last {summary.range}
      </h2>
      <p className="mb-4 text-3xl font-bold text-slate-100">
        {summary.total_events}
        <span className="ml-2 text-sm font-normal text-slate-400">total</span>
      </p>
      <dl className="space-y-2">
        {(Object.keys(summary.by_type) as EventType[]).map((t) => (
          <div key={t} className="flex items-center justify-between text-sm">
            <dt className="text-slate-300">{EVENT_TYPE_LABELS[t]}</dt>
            <dd className="font-mono text-slate-100">{summary.by_type[t]}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function ScoreBandsPanel({ summary }: { summary: Summary }): JSX.Element {
  const bands = summary.score_bands;
  const total = bands.likely_human + bands.suspicious + bands.likely_bot;
  const bandKeys: Array<keyof typeof bands> = [
    "likely_human",
    "suspicious",
    "likely_bot",
  ];
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-5">
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">
        Score bands · last {summary.range}
      </h2>
      <p className="mb-4 text-3xl font-bold text-slate-100">
        {total}
        <span className="ml-2 text-sm font-normal text-slate-400">sessions</span>
      </p>
      <div className="space-y-2">
        {bandKeys.map((k) => (
          <div
            key={k}
            className={
              "flex items-center justify-between rounded-md border px-3 py-2 text-sm " +
              BAND_STYLES[k]
            }
          >
            <span>{BAND_LABELS[k]}</span>
            <span className="font-mono">{bands[k]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function EventsTable({ events }: { events: EventRecord[] }): JSX.Element {
  if (events.length === 0) {
    return (
      <p className="rounded-lg border border-slate-800 bg-slate-900/50 p-5 text-sm text-slate-400">
        No events yet.
      </p>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <thead className="bg-slate-900/50 text-xs uppercase tracking-wider text-slate-400">
          <tr>
            <th className="px-4 py-2 text-left">Time</th>
            <th className="px-4 py-2 text-left">Type</th>
            <th className="px-4 py-2 text-left">Source</th>
            <th className="px-4 py-2 text-right">Δ score</th>
            <th className="px-4 py-2 text-left">IP hash</th>
            <th className="px-4 py-2 text-left">Details</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 bg-slate-950/40">
          {events.map((e) => (
            <tr key={e.event_id}>
              <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-slate-400">
                {new Date(e.timestamp).toLocaleString()}
              </td>
              <td className="px-4 py-2 text-slate-200">
                {EVENT_TYPE_LABELS[e.type]}
              </td>
              <td className="px-4 py-2 text-slate-400">{e.source}</td>
              <td
                className={
                  "px-4 py-2 text-right font-mono " +
                  (e.score_delta < 0 ? "text-rose-400" : "text-slate-400")
                }
              >
                {e.score_delta}
              </td>
              <td className="px-4 py-2 font-mono text-xs text-slate-500">
                {e.ip_hash ?? "—"}
              </td>
              <td className="px-4 py-2 font-mono text-xs text-slate-400">
                {JSON.stringify(e.details).slice(0, 60)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
