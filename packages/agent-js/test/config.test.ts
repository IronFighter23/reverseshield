import { describe, it, expect } from "vitest";
import { resolveConfig } from "../src/config.js";

describe("resolveConfig", () => {
  it("throws when siteId is missing", () => {
    expect(() => resolveConfig({ endpoint: "https://x.example" } as never)).toThrow(
      /siteId/,
    );
  });

  it("throws when endpoint is missing", () => {
    expect(() => resolveConfig({ siteId: "abc" } as never)).toThrow(/endpoint/);
  });

  it("throws on null/undefined config", () => {
    expect(() => resolveConfig(null as never)).toThrow();
    expect(() => resolveConfig(undefined as never)).toThrow();
  });

  it("fills defaults for optional fields", () => {
    const resolved = resolveConfig({
      siteId: "site-uuid",
      endpoint: "https://reporting.example.com",
    });
    expect(resolved.seed).toBe("rs-seed-site-uuid");
    expect(resolved.honeypotCount).toBe(2);
    expect(resolved.debug).toBe(false);
    expect(resolved.behavioralSnapshotDelayMs).toBe(10_000);
  });

  it("strips trailing slashes from endpoint", () => {
    const resolved = resolveConfig({
      siteId: "s",
      endpoint: "https://reporting.example.com///",
    });
    expect(resolved.endpoint).toBe("https://reporting.example.com");
  });

  it("preserves explicit seed override", () => {
    const resolved = resolveConfig({
      siteId: "s",
      endpoint: "https://x",
      seed: "custom-seed-2026",
    });
    expect(resolved.seed).toBe("custom-seed-2026");
  });

  it("rejects out-of-range honeypotCount", () => {
    expect(() =>
      resolveConfig({ siteId: "s", endpoint: "https://x", honeypotCount: -1 }),
    ).toThrow(/honeypotCount/);
    expect(() =>
      resolveConfig({ siteId: "s", endpoint: "https://x", honeypotCount: 100 }),
    ).toThrow(/honeypotCount/);
    expect(() =>
      resolveConfig({ siteId: "s", endpoint: "https://x", honeypotCount: 1.5 }),
    ).toThrow(/honeypotCount/);
  });

  it("rejects negative behavioralSnapshotDelayMs", () => {
    expect(() =>
      resolveConfig({
        siteId: "s",
        endpoint: "https://x",
        behavioralSnapshotDelayMs: -1,
      }),
    ).toThrow(/behavioralSnapshotDelayMs/);
  });
});
