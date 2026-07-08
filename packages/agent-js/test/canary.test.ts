import { describe, it, expect, beforeEach } from "vitest";
import {
  generateCanaryToken,
  embedCanaryToken,
  CANARY_TOKEN_REGEX,
} from "../src/canary.js";

describe("generateCanaryToken", () => {
  it("matches SPEC §3.2 format: rs_<siteId first 8>_<random base62 12>", () => {
    const token = generateCanaryToken("abcdef1234567890");
    expect(token).toMatch(CANARY_TOKEN_REGEX);
    expect(token.startsWith("rs_abcdef12_")).toBe(true);
    expect(token.length).toBe("rs_".length + 8 + 1 + 12);
  });

  it("strips dashes from siteId before taking the first 8 chars", () => {
    // A UUID: dashes should NOT count toward the prefix
    const token = generateCanaryToken("12345678-abcd-efgh-ijkl-mnopqrstuvwx");
    expect(token.startsWith("rs_12345678_")).toBe(true);
  });

  it("throws on empty siteId", () => {
    expect(() => generateCanaryToken("")).toThrow();
    expect(() => generateCanaryToken(undefined as never)).toThrow();
  });

  it("produces unique tokens across calls", () => {
    const tokens = new Set<string>();
    for (let i = 0; i < 100; i++) {
      tokens.add(generateCanaryToken("same-site-id"));
    }
    // Vanishingly unlikely to collide across 100 calls with 12-char base62 suffix
    expect(tokens.size).toBe(100);
  });

  it("handles short siteIds without crashing", () => {
    const token = generateCanaryToken("ab");
    expect(token.startsWith("rs_ab_")).toBe(true);
    expect(token).toMatch(CANARY_TOKEN_REGEX);
  });
});

describe("embedCanaryToken", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("injects an element carrying data-rs-token", () => {
    const token = "rs_testsite_abcdef123456";
    embedCanaryToken(token);
    const el = document.querySelector("[data-rs-token]");
    expect(el).not.toBeNull();
    expect(el?.getAttribute("data-rs-token")).toBe(token);
  });

  it("hides the injected element from users and assistive tech", () => {
    embedCanaryToken("rs_x_abcdef123456");
    const el = document.querySelector("[data-rs-token]") as HTMLElement;
    expect(el.style.display).toBe("none");
    expect(el.getAttribute("aria-hidden")).toBe("true");
  });

  it("returns the element for later removal", () => {
    const el = embedCanaryToken("rs_x_abcdef123456");
    expect(el).not.toBeNull();
    el?.remove();
    expect(document.querySelector("[data-rs-token]")).toBeNull();
  });
});
