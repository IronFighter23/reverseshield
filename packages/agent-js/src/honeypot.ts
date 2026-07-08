import type { ResolvedConfig } from "./config.js";

/**
 * Vocabulary of plausible-looking form field names. Bots that fill every input on a page
 * (a common brute-force strategy) will fill these; humans won't, because the inputs are
 * positioned off-screen and marked aria-hidden.
 *
 * Names deliberately avoid obviously-suspicious tokens like `honeypot`, `bot_trap`, etc.
 * They also avoid names that a legitimate form on the same page might actually use
 * (`email`, `username`, `password`), so we don't false-positive on real submissions.
 *
 * If a name here ever becomes widely footprinted, add to this list rather than replacing —
 * the seeded shuffle handles distribution naturally.
 */
const HONEYPOT_VOCAB: readonly string[] = [
  "email_alt",
  "phone_alt",
  "address_line_two",
  "referral_source",
  "promo_code_alt",
  "website_url",
  "company_website",
  "newsletter_subscription",
  "affiliate_id",
  "fax_number",
  "middle_initial",
  "contact_url",
  "homepage",
  "display_name_alt",
  "backup_email",
  "secondary_phone",
];

/** FNV-1a 32-bit hash. Used only to derive a PRNG seed — not cryptographic. */
export function fnv1a(str: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Mulberry32 PRNG. Produces a stream of [0, 1) floats from a 32-bit seed. */
export function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return function next(): number {
    state = (state + 0x6d2b79f5) | 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Derive N honeypot field names from a per-site seed, deterministically.
 * Same seed → same names, so a visitor sees consistent honeypots across page loads on
 * the same site (a bot can't just retry until it accidentally skips them).
 *
 * @throws never
 */
export function deriveHoneypotNames(seed: string, count: number): string[] {
  const safeCount = Math.max(0, Math.min(count, HONEYPOT_VOCAB.length));
  if (safeCount === 0) return [];

  const prng = mulberry32(fnv1a(seed));
  const pool = [...HONEYPOT_VOCAB];

  // Fisher-Yates shuffle using the seeded PRNG
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(prng() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  return pool.slice(0, safeCount);
}

/**
 * Install hidden honeypot fields into the DOM. Each field fires `onTrigger(name)` exactly
 * once when it gets a non-empty value — subsequent changes on the same field are ignored,
 * so a bot mashing keys doesn't spam the reporting API.
 *
 * Returns a cleanup function that removes the injected DOM and event listeners. Callers
 * usually don't need to call this in production (page unload cleans everything), but tests
 * and SPAs may.
 *
 * @throws never — DOM operations are wrapped so a hostile page environment can't crash init
 */
export function installHoneypots(
  config: Pick<ResolvedConfig, "seed" | "honeypotCount">,
  onTrigger: (fieldName: string) => void,
): () => void {
  if (typeof document === "undefined" || !document.body) {
    return () => undefined;
  }

  const names = deriveHoneypotNames(config.seed, config.honeypotCount);
  const cleanups: Array<() => void> = [];

  for (const name of names) {
    try {
      const wrapper = document.createElement("div");
      wrapper.setAttribute("aria-hidden", "true");
      wrapper.setAttribute("data-rs-decoy", "1");
      // Off-screen positioning — visible to naive scrapers that read all inputs,
      // invisible to humans and to assistive tech (aria-hidden).
      wrapper.style.cssText =
        "position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;opacity:0;pointer-events:none;";

      const label = document.createElement("label");
      label.textContent = name.replace(/_/g, " ");
      label.setAttribute("for", `rs_hp_${name}`);

      const input = document.createElement("input");
      input.type = "text";
      input.name = name;
      input.id = `rs_hp_${name}`;
      input.tabIndex = -1;
      input.autocomplete = "off";
      input.setAttribute("aria-hidden", "true");

      let triggered = false;
      const handler = (): void => {
        if (triggered) return;
        if (input.value.length > 0) {
          triggered = true;
          try {
            onTrigger(name);
          } catch {
            // Never let a caller's handler crash the page
          }
        }
      };
      input.addEventListener("input", handler);
      input.addEventListener("change", handler);

      wrapper.appendChild(label);
      wrapper.appendChild(input);
      document.body.appendChild(wrapper);

      cleanups.push(() => {
        input.removeEventListener("input", handler);
        input.removeEventListener("change", handler);
        wrapper.remove();
      });
    } catch {
      // Swallow — a broken DOM shouldn't kill the whole agent
    }
  }

  return () => {
    for (const fn of cleanups) {
      try {
        fn();
      } catch {
        // ignore
      }
    }
  };
}
