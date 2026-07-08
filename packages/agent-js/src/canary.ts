/**
 * Canary token generation and DOM embedding.
 *
 * Format (SPEC §3.2):
 *   rs_<site_id_first8>_<random_base62_12>
 *
 * The prefix `rs_<site_id_first8>` lets us attribute a leaked token back to a site
 * without having to look it up. The random 12-char suffix gives ~71 bits of entropy,
 * more than enough for uniqueness within a single site's traffic. Base62 is chosen
 * because tokens will end up in URLs, HTML, and log lines — no escaping headaches.
 *
 * v1: tokens are embedded per page load and reported to the ingestion API.
 * v3: an external subsystem will search public corpora for leaked tokens.
 */

const BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/**
 * Generate a base62 string of the requested length using CSPRNG if available.
 * Falls back to Math.random only when `crypto.getRandomValues` is entirely absent —
 * this only matters for legacy WebViews.
 *
 * Note on bias: `bytes[i] % 62` introduces a tiny non-uniformity because 256 is not
 * divisible by 62. For token uniqueness this is irrelevant (12 chars still give
 * ~71 bits of entropy). It would matter for cryptographic use, which this isn't.
 */
function randomBase62(length: number): string {
  const bytes = new Uint8Array(length);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < length; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  let out = "";
  for (let i = 0; i < length; i++) {
    out += BASE62[bytes[i] % BASE62.length];
  }
  return out;
}

/**
 * Generate a canary token per SPEC §3.2.
 * Strips dashes from siteId before taking the first 8 chars, so UUIDs and other
 * dash-containing identifiers produce a clean prefix.
 */
export function generateCanaryToken(siteId: string): string {
  if (!siteId || typeof siteId !== "string") {
    throw new Error("ReverseShield: siteId is required to generate a canary token");
  }
  const prefix = siteId.replace(/-/g, "").slice(0, 8);
  return `rs_${prefix}_${randomBase62(12)}`;
}

/** Regex used both here and in tests to validate canary token format. Exported for reuse. */
export const CANARY_TOKEN_REGEX = /^rs_[A-Za-z0-9]{1,8}_[A-Za-z0-9]{12}$/;

/**
 * Embed a canary token into the DOM as an invisible element carrying `data-rs-token`.
 * Returns the element so the caller can remove it if needed (SPAs, tests).
 *
 * @throws never — returns null if document is unavailable
 */
export function embedCanaryToken(token: string): HTMLElement | null {
  if (typeof document === "undefined" || !document.body) return null;
  try {
    const el = document.createElement("span");
    el.setAttribute("data-rs-token", token);
    el.setAttribute("aria-hidden", "true");
    el.style.cssText = "display:none;";
    document.body.appendChild(el);
    return el;
  } catch {
    return null;
  }
}
