import { describe, it, expect, beforeEach, vi } from "vitest";
import { deriveHoneypotNames, installHoneypots, fnv1a, mulberry32 } from "../src/honeypot.js";

describe("fnv1a", () => {
  it("produces a 32-bit unsigned integer", () => {
    const h = fnv1a("hello");
    expect(Number.isInteger(h)).toBe(true);
    expect(h).toBeGreaterThanOrEqual(0);
    expect(h).toBeLessThan(2 ** 32);
  });

  it("is deterministic", () => {
    expect(fnv1a("same-input")).toBe(fnv1a("same-input"));
  });

  it("differentiates inputs", () => {
    expect(fnv1a("a")).not.toBe(fnv1a("b"));
  });
});

describe("mulberry32", () => {
  it("produces floats in [0, 1)", () => {
    const prng = mulberry32(12345);
    for (let i = 0; i < 100; i++) {
      const v = prng();
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(1);
    }
  });

  it("is deterministic for the same seed", () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    for (let i = 0; i < 10; i++) expect(a()).toBe(b());
  });
});

describe("deriveHoneypotNames", () => {
  it("returns the requested number of names", () => {
    expect(deriveHoneypotNames("seed", 3)).toHaveLength(3);
    expect(deriveHoneypotNames("seed", 0)).toHaveLength(0);
  });

  it("is deterministic for the same seed", () => {
    const a = deriveHoneypotNames("site-abc", 4);
    const b = deriveHoneypotNames("site-abc", 4);
    expect(a).toEqual(b);
  });

  it("returns different names for different seeds — proves names are NOT hardcoded", () => {
    // This is the load-bearing test for SPEC §8 guardrail: "Never hardcode honeypot
    // field names — always derive from per-site config/seed". If a future refactor
    // reintroduces a hardcoded list, this test fails.
    const a = deriveHoneypotNames("site-alpha", 4);
    const b = deriveHoneypotNames("site-bravo", 4);
    expect(a).not.toEqual(b);
  });

  it("clamps counts above vocabulary size", () => {
    const result = deriveHoneypotNames("seed", 999);
    expect(result.length).toBeGreaterThan(0);
    expect(result.length).toBeLessThanOrEqual(20); // vocab is ~16 items
    // No duplicates within the returned set
    expect(new Set(result).size).toBe(result.length);
  });

  it("returns valid identifier-shaped names (bots see plausible fields)", () => {
    const names = deriveHoneypotNames("seed", 5);
    for (const name of names) {
      expect(name).toMatch(/^[a-z][a-z0-9_]+$/);
    }
  });
});

describe("installHoneypots", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("injects the requested number of hidden fields", () => {
    installHoneypots({ seed: "test-seed", honeypotCount: 3 }, () => undefined);
    const decoys = document.querySelectorAll("[data-rs-decoy]");
    expect(decoys).toHaveLength(3);
  });

  it("injects fields with the derived names", () => {
    const expectedNames = deriveHoneypotNames("test-seed", 2);
    installHoneypots({ seed: "test-seed", honeypotCount: 2 }, () => undefined);
    for (const name of expectedNames) {
      const input = document.querySelector(`input[name="${name}"]`);
      expect(input).not.toBeNull();
    }
  });

  it("positions decoys off-screen and marks aria-hidden", () => {
    installHoneypots({ seed: "s", honeypotCount: 1 }, () => undefined);
    const wrapper = document.querySelector("[data-rs-decoy]") as HTMLElement;
    expect(wrapper.getAttribute("aria-hidden")).toBe("true");
    expect(wrapper.style.position).toBe("absolute");
    expect(wrapper.style.left).toBe("-9999px");
  });

  it("fires onTrigger when a decoy field is filled", () => {
    const onTrigger = vi.fn();
    installHoneypots({ seed: "s", honeypotCount: 1 }, onTrigger);
    const input = document.querySelector("[data-rs-decoy] input") as HTMLInputElement;
    input.value = "bot-fill";
    input.dispatchEvent(new Event("input"));
    expect(onTrigger).toHaveBeenCalledTimes(1);
    expect(onTrigger).toHaveBeenCalledWith(input.name);
  });

  it("fires onTrigger only once per field even under repeated events", () => {
    const onTrigger = vi.fn();
    installHoneypots({ seed: "s", honeypotCount: 1 }, onTrigger);
    const input = document.querySelector("[data-rs-decoy] input") as HTMLInputElement;
    input.value = "x";
    input.dispatchEvent(new Event("input"));
    input.value = "xy";
    input.dispatchEvent(new Event("input"));
    input.value = "xyz";
    input.dispatchEvent(new Event("change"));
    expect(onTrigger).toHaveBeenCalledTimes(1);
  });

  it("does NOT fire on empty value (avoids false positives when a field is created/cleared)", () => {
    const onTrigger = vi.fn();
    installHoneypots({ seed: "s", honeypotCount: 1 }, onTrigger);
    const input = document.querySelector("[data-rs-decoy] input") as HTMLInputElement;
    input.value = "";
    input.dispatchEvent(new Event("input"));
    expect(onTrigger).not.toHaveBeenCalled();
  });

  it("cleanup removes injected DOM", () => {
    const cleanup = installHoneypots({ seed: "s", honeypotCount: 2 }, () => undefined);
    expect(document.querySelectorAll("[data-rs-decoy]")).toHaveLength(2);
    cleanup();
    expect(document.querySelectorAll("[data-rs-decoy]")).toHaveLength(0);
  });

  it("does not throw if the caller's onTrigger throws", () => {
    const onTrigger = vi.fn(() => {
      throw new Error("simulated caller bug");
    });
    installHoneypots({ seed: "s", honeypotCount: 1 }, onTrigger);
    const input = document.querySelector("[data-rs-decoy] input") as HTMLInputElement;
    input.value = "x";
    expect(() => input.dispatchEvent(new Event("input"))).not.toThrow();
  });
});
