import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createTransport, uuidv4 } from "../src/transport.js";
import type { ResolvedConfig } from "../src/config.js";

const baseConfig: ResolvedConfig = {
  siteId: "site-uuid-1234",
  endpoint: "https://reporting.example.com",
  seed: "test-seed",
  honeypotCount: 2,
  debug: false,
  behavioralSnapshotDelayMs: 10_000,
};

describe("uuidv4", () => {
  it("produces valid v4 UUID strings", () => {
    for (let i = 0; i < 20; i++) {
      const id = uuidv4();
      expect(id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    }
  });

  it("is unique across calls", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) ids.add(uuidv4());
    expect(ids.size).toBe(100);
  });
});

describe("createTransport — payload shape", () => {
  it("constructs a payload matching SPEC §3.1", () => {
    const t = createTransport(baseConfig, "session-uuid");
    const payload = t.buildPayload("canary_embedded", 0, { token: "rs_abc_def" });

    // Required keys from SPEC §3.1
    expect(payload).toHaveProperty("event_id");
    expect(payload).toHaveProperty("site_id", baseConfig.siteId);
    expect(payload).toHaveProperty("timestamp");
    expect(payload).toHaveProperty("source", "browser");
    expect(payload).toHaveProperty("session_id", "session-uuid");
    expect(payload).toHaveProperty("type", "canary_embedded");
    expect(payload).toHaveProperty("score_delta", 0);
    expect(payload).toHaveProperty("details");
    expect(payload).toHaveProperty("ip_hash", null);
    expect(payload).toHaveProperty("user_agent");
    expect(payload).toHaveProperty("asn", null);

    expect(payload.event_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(new Date(payload.timestamp).toString()).not.toBe("Invalid Date");
  });

  it("browser-sourced events always carry ip_hash: null and asn: null", () => {
    // These are populated server-side per SPEC §3.1 — never by the client.
    const t = createTransport(baseConfig, "s");
    const payload = t.buildPayload("honeypot_triggered", -80, { field: "email_alt" });
    expect(payload.ip_hash).toBeNull();
    expect(payload.asn).toBeNull();
  });
});

describe("createTransport — fail-silent contract", () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
    consoleWarnSpy.mockRestore();
    vi.unstubAllGlobals();
  });

  it("never throws when fetch rejects", () => {
    vi.stubGlobal("navigator", { sendBeacon: undefined, userAgent: "test-ua" });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("network down"))),
    );
    const t = createTransport(baseConfig, "s");
    expect(() => t.send("canary_embedded", 0, {})).not.toThrow();
  });

  it("never throws when fetch throws synchronously", () => {
    vi.stubGlobal("navigator", { sendBeacon: undefined, userAgent: "test-ua" });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => {
        throw new Error("fetch is broken");
      }),
    );
    const t = createTransport(baseConfig, "s");
    expect(() => t.send("canary_embedded", 0, {})).not.toThrow();
  });

  it("never throws when sendBeacon throws", () => {
    vi.stubGlobal("navigator", {
      sendBeacon: vi.fn(() => {
        throw new Error("beacon broken");
      }),
      userAgent: "test-ua",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.resolve(new Response())),
    );
    const t = createTransport(baseConfig, "s");
    expect(() => t.send("canary_embedded", 0, {})).not.toThrow();
  });

  it("never throws when details contain un-serializable values (BigInt)", () => {
    vi.stubGlobal("navigator", {
      sendBeacon: vi.fn(() => true),
      userAgent: "test-ua",
    });
    const t = createTransport(baseConfig, "s");
    // JSON.stringify throws on BigInt — transport must swallow
    expect(() => t.send("canary_embedded", 0, { big: BigInt(1) })).not.toThrow();
  });

  it("never throws when details contain circular references", () => {
    vi.stubGlobal("navigator", {
      sendBeacon: vi.fn(() => true),
      userAgent: "test-ua",
    });
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const t = createTransport(baseConfig, "s");
    expect(() => t.send("canary_embedded", 0, circular)).not.toThrow();
  });

  it("never emits console.error under any failure condition", () => {
    vi.stubGlobal("navigator", { sendBeacon: undefined, userAgent: "test-ua" });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("boom"))),
    );
    const t = createTransport(baseConfig, "s");
    t.send("canary_embedded", 0, {});
    // Give the rejected promise a tick to settle
    return Promise.resolve().then(() => {
      expect(consoleErrorSpy).not.toHaveBeenCalled();
    });
  });

  it("does NOT warn on failures when debug is false (default)", async () => {
    vi.stubGlobal("navigator", { sendBeacon: undefined, userAgent: "test-ua" });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("boom"))),
    );
    const t = createTransport(baseConfig, "s");
    t.send("canary_embedded", 0, {});
    await Promise.resolve();
    await Promise.resolve();
    expect(consoleWarnSpy).not.toHaveBeenCalled();
  });

  it("DOES warn on failures when debug is true", async () => {
    vi.stubGlobal("navigator", { sendBeacon: undefined, userAgent: "test-ua" });
    vi.stubGlobal(
      "fetch",
      vi.fn(() => Promise.reject(new Error("boom"))),
    );
    const t = createTransport({ ...baseConfig, debug: true }, "s");
    t.send("canary_embedded", 0, {});
    // Await two ticks so the rejected promise handler runs
    await Promise.resolve();
    await Promise.resolve();
    expect(consoleWarnSpy).toHaveBeenCalledTimes(1);
  });
});

describe("createTransport — routing", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("prefers sendBeacon when available", () => {
    const beaconSpy = vi.fn(() => true);
    const fetchSpy = vi.fn(() => Promise.resolve(new Response()));
    vi.stubGlobal("navigator", { sendBeacon: beaconSpy, userAgent: "test-ua" });
    vi.stubGlobal("fetch", fetchSpy);

    const t = createTransport(baseConfig, "s");
    t.send("canary_embedded", 0, { token: "rs_abc_def" });

    expect(beaconSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy).not.toHaveBeenCalled();
    // sendBeacon is called with the events endpoint
    expect(beaconSpy.mock.calls[0][0]).toBe(
      "https://reporting.example.com/api/v1/events",
    );
  });

  it("falls back to fetch when sendBeacon is absent", () => {
    const fetchSpy = vi.fn(() => Promise.resolve(new Response()));
    vi.stubGlobal("navigator", { userAgent: "test-ua" });
    vi.stubGlobal("fetch", fetchSpy);

    const t = createTransport(baseConfig, "s");
    t.send("canary_embedded", 0, {});

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://reporting.example.com/api/v1/events");
    expect(init.method).toBe("POST");
    expect(init.keepalive).toBe(true);
    expect(init.credentials).toBe("omit");
  });
});
