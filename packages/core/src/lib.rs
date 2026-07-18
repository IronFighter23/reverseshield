//! reverseshield-core — detection engine used by every ReverseShield component.
//!
//! Public surface, in the order operators are likely to reach for it:
//!
//!   * [`rules::RuleSet`]      — loads and hot-reloads `rules/core-rules.yaml`.
//!   * [`scoring::score_signals`] — evaluates a slice of incoming event signals
//!     against a rule set and returns a trust score plus its band.
//!   * [`scoring::ScoreBand`]  — the three-band classification (SPEC §3.4).
//!
//! Scope of Phase 2 step 1: native rule loading + scoring only. The WASM export
//! layer (Phase 2 step 3) and the PHP FFI shim (Phase 2 step 4) both consume this
//! same module tree — they add adapter code, they do not reimplement scoring.
//!
//! Modules for `canary` and `event` remain as Phase 1 scaffolds. They will be
//! filled in against SPEC §3.1 / §3.2 in later Phase 2 tasks and are intentionally
//! left untouched here to keep the diff on this milestone focused.

pub mod canary;
pub mod event;
pub mod rules;
pub mod scoring;

// wasm-bindgen exports for the browser agent. Only compiled for wasm32 targets, using
// the same target-arch gate as the wasm-bindgen dep in packages/core/Cargo.toml. Native
// builds and the PHP FFI binding (Phase 2 step 4) skip this module entirely.
#[cfg(target_arch = "wasm32")]
pub mod wasm;

// Re-exports so downstream callers can `use reverseshield_core::RuleSet` without
// caring which internal module owns which type. Keep this list tight — the point
// of re-exporting is convenience for the two or three types every consumer needs,
// not to flatten the module tree.
pub use rules::{Action, Rule, RuleError, RuleSet};
pub use scoring::{
    score_from_triggered_rules, score_from_weights, score_signals, ScoreBand, ScoreResult,
    BASELINE_SCORE,
};
