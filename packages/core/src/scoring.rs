//! Trust-score computation.
//!
//! Implements SPEC §3.4 verbatim:
//!
//! ```text
//! score = clamp(100 - sum(weight_i for each triggered rule_i), 0, 100)
//!
//! bands:
//!   70..=100 = likely human
//!   40..=69  = suspicious
//!    0..=39  = likely bot
//! ```
//!
//! The scoring function has one job — turn a set of triggered weights into a `u8` in
//! `[0, 100]` — and that job is small enough to keep pure and side-effect-free. The
//! only interesting engineering here is the clamp: with adversarial input we must
//! never overflow, never wrap, and never produce a value outside the two boundary
//! constants. Everything else is bookkeeping.
//!
//! Callers who have a full [`RuleSet`](crate::rules::RuleSet) and a list of incoming
//! signals should reach for [`score_signals`], which handles the rule lookup for them.
//! Callers who already have weights in hand (e.g. from a cache or a different rule
//! source) should reach for [`score_from_weights`].

use serde::{Deserialize, Serialize};

use crate::rules::{Rule, RuleSet};

/// Trust-score band per SPEC §3.4.
///
/// Serialized as a lowercase string so it round-trips cleanly to the reporting API,
/// dashboard, and any Slack/webhook alerts that key off it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreBand {
    /// 70..=100 — trust the session by default.
    LikelyHuman,
    /// 40..=69 — surface in the dashboard; do not block.
    Suspicious,
    /// 0..=39 — block-eligible once v2 turns on active response.
    LikelyBot,
}

impl ScoreBand {
    /// Classify a score into its band. Guaranteed total function over `u8`, though
    /// scores above 100 are clamped to `LikelyHuman` for defense-in-depth — if this
    /// somehow gets a raw-input value, the caller shouldn't get a wrong band.
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=39 => ScoreBand::LikelyBot,
            40..=69 => ScoreBand::Suspicious,
            _ => ScoreBand::LikelyHuman, // 70..=255; anything ≥70 is the same band.
        }
    }
}

/// The full evaluation result. Consumers usually want the score, but the band and
/// triggered-rule ids are what the dashboard and webhook payloads need. Bundling
/// them together means the engine returns everything downstream code will ask for
/// in one pass — no second walk over the rule set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreResult {
    pub score: u8,
    pub band: ScoreBand,
    /// IDs of every rule that fired, in the order they were evaluated. Order matches
    /// the rules-file order so dashboard output is stable.
    pub triggered_rule_ids: Vec<String>,
    /// Sum of weights before clamping. Preserved for observability — helpful when
    /// operators are tuning weights and want to see "how far over 100 did we go?"
    pub total_weight: u32,
}

/// The score assigned to a session before any rules have triggered. Exposed as a
/// constant so the JS agent, PHP middleware, and dashboard can all agree on the same
/// baseline through the FFI/WASM boundary once Phase 2 step 3 lands.
pub const BASELINE_SCORE: u8 = 100;

/// Compute a trust score from a raw list of weights.
///
/// This is the mathematical core. It exists as a separate function so scoring can be
/// unit-tested against arbitrary inputs — including inputs no real rule set could
/// produce — without having to construct a `RuleSet`. It is the *only* place the
/// `100 - sum` arithmetic happens in the engine; callers must not reimplement it.
///
/// Overflow protection: the sum is computed as `u64` before subtraction, so even a
/// pathological rules file with millions of rules of weight `u32::MAX` cannot wrap.
/// The clamp then floors the result at 0.
pub fn score_from_weights(weights: &[u32]) -> u8 {
    let total: u64 = weights.iter().map(|&w| u64::from(w)).sum();
    let baseline = u64::from(BASELINE_SCORE);
    // `saturating_sub` on `u64` gives us the lower clamp for free — if the total
    // exceeds the baseline, we land at 0 instead of wrapping to a huge number.
    let clamped = baseline.saturating_sub(total);
    // `clamped` is now in [0, 100] by construction (baseline is 100 and saturating_sub
    // cannot produce a value greater than its minuend). Cast is lossless.
    debug_assert!(clamped <= u64::from(BASELINE_SCORE));
    clamped as u8
}

/// Evaluate a set of incoming signals against a rule set and produce a full score
/// result. This is the entry point Phase 2 wires the JS agent and PHP middleware into
/// once the FFI/WASM bindings land.
///
/// Semantics:
///   * Each signal in `signals` fires every rule whose `signal` field matches it.
///     A signal that appears twice in the input fires its rules twice (compounding
///     the penalty). This matches how the reporting API counts events.
///   * Rules that appear in the set but whose signal is not in `signals` do not fire.
///   * An empty `signals` slice yields `BASELINE_SCORE` and an empty triggered list.
pub fn score_signals(rule_set: &RuleSet, signals: &[&str]) -> ScoreResult {
    let mut weights: Vec<u32> = Vec::new();
    let mut triggered_ids: Vec<String> = Vec::new();

    for signal in signals {
        for rule in rule_set.rules_for_signal(signal) {
            weights.push(rule.weight);
            triggered_ids.push(rule.id.clone());
        }
    }

    let total_weight: u64 = weights.iter().map(|&w| u64::from(w)).sum();
    let score = score_from_weights(&weights);

    ScoreResult {
        score,
        band: ScoreBand::from_score(score),
        triggered_rule_ids: triggered_ids,
        // Cap the reported total at u32::MAX; callers just want it for observability
        // and a u32 sum is enough for any realistic rules file.
        total_weight: total_weight.min(u64::from(u32::MAX)) as u32,
    }
}

/// Convenience: given a slice of rules already known to have triggered (regardless of
/// how they were selected), score them. Used by middlewares that do their own rule
/// selection but want the shared clamp/band logic.
pub fn score_from_triggered_rules(triggered: &[&Rule]) -> ScoreResult {
    let weights: Vec<u32> = triggered.iter().map(|r| r.weight).collect();
    let triggered_ids: Vec<String> = triggered.iter().map(|r| r.id.clone()).collect();
    let total_weight: u64 = weights.iter().map(|&w| u64::from(w)).sum();
    let score = score_from_weights(&weights);
    ScoreResult {
        score,
        band: ScoreBand::from_score(score),
        triggered_rule_ids: triggered_ids,
        total_weight: total_weight.min(u64::from(u32::MAX)) as u32,
    }
}

// =====================================================================================
// Tests
// =====================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;

    // --- score_from_weights: the clamp is the whole ballgame -------------------------

    #[test]
    fn no_weights_yields_baseline() {
        assert_eq!(score_from_weights(&[]), BASELINE_SCORE);
        assert_eq!(score_from_weights(&[]), 100);
    }

    #[test]
    fn single_weight_subtracts_from_baseline() {
        assert_eq!(score_from_weights(&[30]), 70);
        assert_eq!(score_from_weights(&[40]), 60);
        assert_eq!(score_from_weights(&[1]), 99);
    }

    #[test]
    fn multiple_weights_sum_and_subtract() {
        // Canonical SPEC example: honeypot (80) + rate limit (40) = 120 → clamped to 0.
        assert_eq!(score_from_weights(&[80, 40]), 0);
        // Order-independence — sums commute.
        assert_eq!(score_from_weights(&[40, 80]), 0);
    }

    #[test]
    fn weight_equal_to_baseline_lands_at_zero() {
        assert_eq!(score_from_weights(&[100]), 0);
    }

    #[test]
    fn weights_summing_to_baseline_land_at_zero() {
        assert_eq!(score_from_weights(&[50, 50]), 0);
        assert_eq!(score_from_weights(&[25, 25, 25, 25]), 0);
    }

    #[test]
    fn overshoot_clamps_to_zero_not_negative_and_not_wrapped() {
        // If clamping were done with a plain `i32` subtraction and cast, an overshoot
        // could produce a negative that either panics or wraps. This test would catch
        // both.
        assert_eq!(score_from_weights(&[999]), 0);
        assert_eq!(score_from_weights(&[500, 500, 500]), 0);
    }

    #[test]
    fn u32_max_single_weight_does_not_wrap() {
        // Adversarial rule file with a maxed-out weight. Must land at 0, not overflow.
        assert_eq!(score_from_weights(&[u32::MAX]), 0);
    }

    #[test]
    fn many_maxed_weights_still_clamp_to_zero_without_overflow() {
        // Sum here (10 * u32::MAX) exceeds u32::MAX by an order of magnitude. The
        // internal u64 accumulator is what keeps this correct.
        let hostile = vec![u32::MAX; 10];
        assert_eq!(score_from_weights(&hostile), 0);
    }

    #[test]
    fn zero_weights_are_a_noop() {
        // The `canary-embedded` rule has weight 0 by design — it's an observation
        // signal, not a penalty. Firing 100 of them must still leave score at 100.
        assert_eq!(score_from_weights(&[0]), 100);
        assert_eq!(score_from_weights(&vec![0u32; 100]), 100);
    }

    #[test]
    fn zero_weights_do_not_shift_the_result() {
        // Interleaved zeros should not change the outcome vs. the same non-zero list.
        assert_eq!(
            score_from_weights(&[0, 30, 0, 10, 0]),
            score_from_weights(&[30, 10])
        );
    }

    // Exhaustive property-style check: every weight from 0..=200 must produce a score
    // in [0, 100]. Cheap enough at 201 iterations to run on every `cargo test`.
    #[test]
    fn exhaustive_single_weight_stays_in_bounds() {
        for w in 0u32..=200 {
            let s = score_from_weights(&[w]);
            assert!(s <= 100, "weight {} produced out-of-band score {}", w, s);
        }
    }

    #[test]
    fn exhaustive_two_weights_up_to_150_each_stays_in_bounds() {
        // Covers every crossing of the baseline. 150 * 150 = 22_500 iterations.
        for a in 0u32..=150 {
            for b in 0u32..=150 {
                let s = score_from_weights(&[a, b]);
                assert!(s <= 100, "weights {}+{} produced {}", a, b, s);
            }
        }
    }

    #[test]
    fn score_is_monotonically_non_increasing_in_weight() {
        // Adding a weight can never *raise* the score. Property check across the range.
        for base in 0u32..=100 {
            for extra in 0u32..=100 {
                let with_extra = score_from_weights(&[base, extra]);
                let without = score_from_weights(&[base]);
                assert!(
                    with_extra <= without,
                    "adding weight {} to base {} raised score from {} to {}",
                    extra,
                    base,
                    without,
                    with_extra
                );
            }
        }
    }

    // --- Band boundaries: verify SPEC §3.4 exactly at every edge --------------------

    #[test]
    fn band_boundaries_match_spec_exactly() {
        // Bot band: 0..=39
        assert_eq!(ScoreBand::from_score(0), ScoreBand::LikelyBot);
        assert_eq!(ScoreBand::from_score(39), ScoreBand::LikelyBot);
        // Suspicious band: 40..=69
        assert_eq!(ScoreBand::from_score(40), ScoreBand::Suspicious);
        assert_eq!(ScoreBand::from_score(69), ScoreBand::Suspicious);
        // Human band: 70..=100
        assert_eq!(ScoreBand::from_score(70), ScoreBand::LikelyHuman);
        assert_eq!(ScoreBand::from_score(100), ScoreBand::LikelyHuman);
    }

    #[test]
    fn every_score_from_0_to_100_maps_to_exactly_one_band() {
        for s in 0u8..=100 {
            let band = ScoreBand::from_score(s);
            match band {
                ScoreBand::LikelyBot => assert!(s <= 39),
                ScoreBand::Suspicious => assert!((40..=69).contains(&s)),
                ScoreBand::LikelyHuman => assert!(s >= 70),
            }
        }
    }

    #[test]
    fn bands_are_defense_in_depth_above_100() {
        // Should never be reachable via public API, but if a caller feeds a raw u8
        // above 100 the classifier must still return a sensible band, not panic.
        assert_eq!(ScoreBand::from_score(200), ScoreBand::LikelyHuman);
        assert_eq!(ScoreBand::from_score(u8::MAX), ScoreBand::LikelyHuman);
    }

    // --- score_signals: integration with the rule set --------------------------------

    const CANONICAL_RULES: &str = r#"
- {id: honeypot-field-fill,   description: h, signal: honeypot_triggered,   weight: 80, action: flag}
- {id: rate-limit-exceeded,   description: r, signal: rate_limit_exceeded,  weight: 40, action: flag}
- {id: canary-embedded,       description: c, signal: canary_embedded,      weight: 0,  action: flag}
- {id: behavioral-score-low,  description: b, signal: behavioral_score,     weight: 30, action: flag}
- {id: attestation-failed,    description: a, signal: attestation_failed,   weight: 60, action: flag}
- {id: request-fingerprint,   description: f, signal: request_fingerprint,  weight: 50, action: flag}
"#;

    fn canonical() -> RuleSet {
        RuleSet::from_yaml_str(CANONICAL_RULES).unwrap()
    }

    #[test]
    fn empty_signals_yields_baseline_and_no_triggers() {
        let r = score_signals(&canonical(), &[]);
        assert_eq!(r.score, 100);
        assert_eq!(r.band, ScoreBand::LikelyHuman);
        assert!(r.triggered_rule_ids.is_empty());
        assert_eq!(r.total_weight, 0);
    }

    #[test]
    fn honeypot_alone_lands_in_suspicious_band() {
        // 100 - 80 = 20 → LikelyBot. This is the "bot filled the hidden field" case
        // and the spec wants it clearly in the block-eligible band.
        let r = score_signals(&canonical(), &["honeypot_triggered"]);
        assert_eq!(r.score, 20);
        assert_eq!(r.band, ScoreBand::LikelyBot);
        assert_eq!(r.triggered_rule_ids, vec!["honeypot-field-fill"]);
        assert_eq!(r.total_weight, 80);
    }

    #[test]
    fn rate_limit_alone_lands_in_suspicious_band() {
        // 100 - 40 = 60 → Suspicious.
        let r = score_signals(&canonical(), &["rate_limit_exceeded"]);
        assert_eq!(r.score, 60);
        assert_eq!(r.band, ScoreBand::Suspicious);
    }

    #[test]
    fn spec_canonical_two_signal_case() {
        // Both spec-example rules firing: 100 - (80 + 40) = -20 → clamped to 0.
        let r = score_signals(&canonical(), &["honeypot_triggered", "rate_limit_exceeded"]);
        assert_eq!(r.score, 0);
        assert_eq!(r.band, ScoreBand::LikelyBot);
        assert_eq!(r.total_weight, 120);
        assert_eq!(r.triggered_rule_ids.len(), 2);
    }

    #[test]
    fn unmatched_signal_is_ignored() {
        let r = score_signals(&canonical(), &["signal_that_no_rule_reacts_to"]);
        assert_eq!(r.score, 100);
        assert!(r.triggered_rule_ids.is_empty());
    }

    #[test]
    fn repeated_signal_compounds_penalty() {
        // Two honeypot events in one session = 2 * 80 = 160 → clamped to 0.
        let r = score_signals(&canonical(), &["honeypot_triggered", "honeypot_triggered"]);
        assert_eq!(r.score, 0);
        assert_eq!(r.triggered_rule_ids.len(), 2);
        assert_eq!(r.total_weight, 160);
    }

    #[test]
    fn canary_signal_never_penalizes() {
        // The `canary_embedded` rule has weight 0. Firing it any number of times must
        // leave the score at baseline — this is what makes canaries observational.
        let r = score_signals(&canonical(), &["canary_embedded"; 50]);
        assert_eq!(r.score, 100);
        assert_eq!(r.band, ScoreBand::LikelyHuman);
        assert_eq!(r.triggered_rule_ids.len(), 50);
        assert_eq!(r.total_weight, 0);
    }

    #[test]
    fn all_six_spec_signals_together_land_at_zero() {
        let r = score_signals(
            &canonical(),
            &[
                "honeypot_triggered",
                "rate_limit_exceeded",
                "canary_embedded",
                "behavioral_score",
                "attestation_failed",
                "request_fingerprint",
            ],
        );
        assert_eq!(r.score, 0);
        assert_eq!(r.band, ScoreBand::LikelyBot);
        assert_eq!(r.triggered_rule_ids.len(), 6);
        // 80 + 40 + 0 + 30 + 60 + 50 = 260
        assert_eq!(r.total_weight, 260);
    }

    #[test]
    fn empty_rule_set_never_penalizes() {
        let empty = RuleSet::empty();
        let r = score_signals(&empty, &["honeypot_triggered", "attestation_failed"]);
        assert_eq!(r.score, 100);
        assert!(r.triggered_rule_ids.is_empty());
    }

    #[test]
    fn triggered_ids_preserve_rule_file_order() {
        // Determinism matters for the dashboard: reordering the input signals must not
        // reorder the output list — it's driven by the *rules* file order, not the
        // event stream order for the same signal.
        let yaml = r#"
- {id: first,  description: x, signal: same, weight: 10}
- {id: second, description: x, signal: same, weight: 10}
- {id: third,  description: x, signal: same, weight: 10}
"#;
        let set = RuleSet::from_yaml_str(yaml).unwrap();
        let r = score_signals(&set, &["same"]);
        assert_eq!(r.triggered_rule_ids, vec!["first", "second", "third"]);
    }

    #[test]
    fn score_from_triggered_rules_matches_score_signals() {
        let set = canonical();
        let r_signals = score_signals(&set, &["honeypot_triggered", "behavioral_score"]);

        let triggered: Vec<&Rule> = set
            .rules()
            .iter()
            .filter(|r| r.signal == "honeypot_triggered" || r.signal == "behavioral_score")
            .collect();
        let r_direct = score_from_triggered_rules(&triggered);

        assert_eq!(r_signals.score, r_direct.score);
        assert_eq!(r_signals.band, r_direct.band);
        assert_eq!(r_signals.total_weight, r_direct.total_weight);
    }
}
