/**
 * Runtime validation for API inputs. Every payload arriving at a route is parsed through
 * these schemas before it can touch the database. Unknown fields are rejected outright
 * (`.strict()`) — a well-formed SPEC §3.1 event has a known shape, and anything extra is
 * more likely an injection attempt than a legitimate new field.
 *
 * When SPEC §3.1 evolves, edit this file first. Everything downstream (DB inserts, route
 * handlers, tests) will surface the mismatch at compile time via the exported types.
 */

import { z } from "zod";

/** ISO-8601 timestamp validator. */
const isoTimestamp = z
  .string()
  .refine(
    (v) => !Number.isNaN(new Date(v).getTime()) && v.includes("T"),
    { message: "must be an ISO-8601 timestamp" },
  );

/**
 * SPEC §3.1 event schema. Kept in one place so the rest of the codebase infers its types
 * from here rather than restating them.
 */
export const eventSchema = z
  .object({
    event_id: z.string().uuid(),
    site_id: z.string().uuid(),
    timestamp: isoTimestamp,
    source: z.enum(["browser", "server"]),
    session_id: z.string().uuid(),
    type: z.enum([
      "honeypot_triggered",
      "canary_embedded",
      "rate_limit_exceeded",
      "behavioral_score",
      "attestation_failed",
      "request_fingerprint",
    ]),
    score_delta: z.number().int(),
    details: z.record(z.unknown()),
    ip_hash: z.string().nullable(),
    user_agent: z.string(),
    asn: z.string().nullable(),
  })
  .strict();

export type ValidatedEvent = z.infer<typeof eventSchema>;

/** POST /api/v1/sites request body. Minimal — just a display name for now. */
export const registerSiteSchema = z
  .object({
    name: z.string().min(1).max(200),
  })
  .strict();

export type RegisterSiteInput = z.infer<typeof registerSiteSchema>;

/**
 * Single detection rule loaded from `rules/core-rules.yaml`. Shape mirrors the Rust
 * `Rule` struct in packages/core/src/rules.rs one-for-one — same field names, same
 * types, same defaults — so what this service emits over the wire deserializes
 * cleanly on the WASM side without any adapter layer.
 *
 * Unknown fields are silently dropped (not `.strict()`). Rationale: the Rust engine
 * uses `deny_unknown_fields` at its own YAML parse boundary, so structural mistakes
 * are already caught by whichever engine is closer to the maintainer. This service
 * is a wire-format transformer between the two, not a duplicate gatekeeper.
 */
export const ruleSchema = z.object({
  id: z.string().min(1),
  description: z.string(),
  signal: z.string().min(1),
  weight: z.number().int().nonnegative(),
  action: z.enum(["flag", "throttle", "block"]).default("flag"),
});

export type ValidatedRule = z.infer<typeof ruleSchema>;

/** The rules file is a top-level array of rules. */
export const ruleSetSchema = z.array(ruleSchema);
