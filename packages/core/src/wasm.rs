//! WebAssembly bindings for browser-side scoring.
//!
//! This module is the boundary between the shared scoring engine and the JS agent.
//! Everything here is a thin adapter — no scoring math, no rule parsing, no policy
//! decisions. Those all live in [`crate::rules`] and [`crate::scoring`] and are shared
//! verbatim between native and WASM builds.
//!
//! The module is only compiled for `target_arch = "wasm32"`. Native `cargo build` /
//! `cargo test` skip it entirely, which is the point of the `native` feature gate on
//! `serde_yaml` — native builds never pull in `wasm-bindgen`, WASM builds never pull
//! in `serde_yaml`. Each transport format lives in exactly one wire boundary.
//!
//! ## Exports
//!
//!   * `scoreFromWeights(weights: Uint32Array): number` — total function. Any u32 array
//!     (including empty) produces a u8 in `[0, 100]`. Overflow is impossible; internal
//!     accumulation uses `u64`. Never throws.
//!
//!   * `scoreSignalsJson(rulesJson: string, signalsJson: string): string` — parses a
//!     JSON-encoded rule set and a JSON-encoded array of signal strings, returns a
//!     JSON-encoded [`crate::scoring::ScoreResult`]. Throws a JS `Error` on any parse
//!     failure so the JS agent's silent-fail wrapper can catch it and disable local
//!     scoring for that session without crashing.
//!
//! ## Why JSON and not typed bindings?
//!
//! `wasm-bindgen` can generate typed struct bindings via `serde-wasm-bindgen`, but that
//! adds ~15 KB to the output for a scoring engine whose entire state fits in a JSON
//! blob smaller than a single HTTP header. String-in / string-out is the smallest
//! possible boundary and it keeps the JS side free to log, cache, or replay payloads
//! without any binding-specific accessors.

use wasm_bindgen::prelude::*;

use crate::rules::RuleSet;
use crate::scoring::{score_from_weights, score_signals};

/// See module docs. Total function; cannot throw.
#[wasm_bindgen(js_name = scoreFromWeights)]
pub fn wasm_score_from_weights(weights: Vec<u32>) -> u8 {
    score_from_weights(&weights)
}

/// See module docs. Throws a JS `Error` on parse failure.
#[wasm_bindgen(js_name = scoreSignalsJson)]
pub fn wasm_score_signals_json(rules_json: &str, signals_json: &str) -> Result<String, JsError> {
    let rule_set = RuleSet::from_json_str(rules_json)
        .map_err(|e| JsError::new(&format!("failed to parse rules JSON: {e}")))?;

    let signals: Vec<String> = serde_json::from_str(signals_json)
        .map_err(|e| JsError::new(&format!("failed to parse signals JSON: {e}")))?;
    let signal_refs: Vec<&str> = signals.iter().map(String::as_str).collect();

    let result = score_signals(&rule_set, &signal_refs);
    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("failed to serialize score result: {e}")))
}
