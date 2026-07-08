import { describe, it, expect, beforeEach } from "vitest";
import { startTelemetry } from "../src/telemetry.js";

describe("startTelemetry", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("returns a zero snapshot with no events observed", () => {
    const t = startTelemetry();
    const snap = t.snapshot();
    expect(snap.mouseMoves).toBe(0);
    expect(snap.mouseDistance).toBe(0);
    expect(snap.scrollEvents).toBe(0);
    expect(snap.keyPresses).toBe(0);
    expect(snap.clickCount).toBe(0);
    expect(snap.timeToFirstInteractionMs).toBeNull();
    expect(snap.durationMs).toBeGreaterThanOrEqual(0);
    t.stop();
  });

  it("counts mousemove events", () => {
    const t = startTelemetry();
    window.dispatchEvent(new MouseEvent("mousemove", { clientX: 10, clientY: 10 }));
    window.dispatchEvent(new MouseEvent("mousemove", { clientX: 20, clientY: 10 }));
    window.dispatchEvent(new MouseEvent("mousemove", { clientX: 20, clientY: 20 }));
    const snap = t.snapshot();
    expect(snap.mouseMoves).toBe(3);
    // Distance: first move sets last position (0 delta), then +10 (x), then +10 (y) = 20
    expect(snap.mouseDistance).toBe(20);
    t.stop();
  });

  it("counts scroll, keydown, and click events", () => {
    const t = startTelemetry();
    window.dispatchEvent(new Event("scroll"));
    window.dispatchEvent(new Event("scroll"));
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "a" }));
    window.dispatchEvent(new MouseEvent("click"));
    const snap = t.snapshot();
    expect(snap.scrollEvents).toBe(2);
    expect(snap.keyPresses).toBe(1);
    expect(snap.clickCount).toBe(1);
    t.stop();
  });

  it("sets timeToFirstInteractionMs on first observed event", () => {
    const t = startTelemetry();
    expect(t.snapshot().timeToFirstInteractionMs).toBeNull();
    window.dispatchEvent(new MouseEvent("click"));
    const snap = t.snapshot();
    expect(snap.timeToFirstInteractionMs).not.toBeNull();
    expect(snap.timeToFirstInteractionMs).toBeGreaterThanOrEqual(0);
    t.stop();
  });

  it("stop() prevents further counts", () => {
    const t = startTelemetry();
    window.dispatchEvent(new MouseEvent("click"));
    t.stop();
    window.dispatchEvent(new MouseEvent("click"));
    window.dispatchEvent(new MouseEvent("click"));
    expect(t.snapshot().clickCount).toBe(1);
  });
});
