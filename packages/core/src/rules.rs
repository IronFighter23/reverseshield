//! Rule loading, deserialization, and hot-reloading.
//!
//! This module owns the *shape* of a detection rule and how rules get from disk (native)
//! or off the wire (WASM) into memory. Everything about *what a rule means numerically*
//! — how a triggered rule maps to a score change — lives in [`crate::scoring`]. Splitting
//! it this way lets the reporting service load a `RuleSet` once at startup, watch the
//! file for edits, and ask the scoring module to evaluate signals without either side
//! leaking into the other.
//!
//! Design decisions worth flagging:
//!
//!   * `Rule::signal` is a `String`, not an enum. SPEC §3.1 lists six signal types
//!     today, but the whole point of keeping rules in YAML is that Phase 3 can add
//!     new signals without a Rust release. Matching is exact string equality.
//!
//!   * `Action` *is* an enum. Actions drive real code paths (flag / throttle / block)
//!     and unknown values must be surfaced at parse time, not silently ignored.
//!
//!   * Hot reload is `mtime`-based rather than filesystem-notify-based. The reporting
//!     service is single-node in v1 (SPEC §4.D) and a stat call per request is cheap.
//!     A notify-crate watcher can drop in later without changing the public API.
//!
//!   * We never panic on a malformed rules file at runtime. Callers get a `RuleError`
//!     and decide whether to keep serving with the last-known-good rule set or fail
//!     closed. The engine has no opinion on that policy.
//!
//!   * **YAML is developer-facing; JSON is wire-format.** The `rules/core-rules.yaml`
//!     file is the single source of truth operators edit. The reporting service loads
//!     it via [`RuleSet::load_from_path`] and serializes the resulting `Vec<Rule>` to
//!     JSON for delivery to browser agents (via a future `/api/v1/sites/:site_id/rules`
//!     endpoint). Browsers call [`RuleSet::from_json_str`] — no YAML parser in the
//!     WASM bundle, which saves ~50 KB of gzipped code before we even start optimizing.
//!
//! Everything that touches YAML, the filesystem, or `SystemTime` is gated behind the
//! `native` cargo feature. WASM builds (`--no-default-features`) drop those symbols
//! entirely — the browser cannot accidentally reach for a filesystem it doesn't have.

#[cfg(feature = "native")]
use std::fs;
#[cfg(feature = "native")]
use std::path::{Path, PathBuf};
#[cfg(feature = "native")]
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What the engine should do when a rule triggers.
///
/// v1 only reports; `Throttle` and `Block` are parsed and preserved so that Phase 2
/// middlewares can enforce them without a rules-file migration. See SPEC §3.4 —
/// "Automatic blocking based on score is a v2 feature gated behind explicit config
/// (`action: block`) — never on by default."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Flag,
    Throttle,
    Block,
}

/// One row in `rules/core-rules.yaml`. Shape locked to SPEC §3.3.
///
/// `#[serde(deny_unknown_fields)]` is deliberate: an unknown key almost always means a
/// typo (e.g. `weights: 80` instead of `weight: 80`), and silently dropping it would
/// give the operator a scoring behavior they didn't ask for. Parse errors are loud;
/// scoring drift is silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique kebab-case identifier. Duplicates are rejected at load time.
    pub id: String,
    /// Human-readable description, used by the dashboard.
    pub description: String,
    /// The SPEC §3.1 event `type` this rule reacts to.
    pub signal: String,
    /// Non-negative penalty applied to the base score of 100 when this rule triggers.
    /// Modeled as `u32` so YAML `-10` fails to parse rather than silently boosting
    /// scores — negative weights would break the invariant tested in scoring.rs.
    pub weight: u32,
    /// What to do when the rule triggers. Defaults to `flag` if the field is omitted,
    /// preserving forward-compat with older rule files.
    #[serde(default)]
    pub action: Action,
}

/// An in-memory rule set plus the metadata needed to hot-reload it (native builds only).
///
/// A `RuleSet` can be built four ways:
///   * [`RuleSet::empty`]         — construct scoring-only pipelines in tests.
///   * [`RuleSet::from_json_str`] — for browsers and any host that receives rules
///     over the wire (available in both native and WASM).
///   * [`RuleSet::from_yaml_str`] — for hosts that ship YAML inline (native only).
///   * [`RuleSet::load_from_path`] — for the reporting service and middlewares
///     (native only).
///
/// Only rule sets built from a path can be reloaded; the others return `Ok(false)`
/// from [`RuleSet::reload_if_changed`] because there's nothing to poll.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<Rule>,
    // The `source` and `last_loaded_mtime` fields only exist on native builds. On WASM
    // there's nothing to reload from — rules arrive as JSON over the wire and the host
    // is expected to fetch a fresh copy when it wants to update them. Gating the fields
    // themselves (rather than just the methods) keeps the WASM binary a few bytes smaller
    // per instance and makes the "no filesystem in browser" invariant a compile-time
    // property rather than a runtime one.
    #[cfg(feature = "native")]
    source: Option<PathBuf>,
    /// mtime observed the last time we successfully loaded `source`. `None` means the
    /// source has never been read (or the FS didn't report an mtime, which we treat as
    /// "always reload" — better a redundant parse than a stale rule set).
    #[cfg(feature = "native")]
    last_loaded_mtime: Option<SystemTime>,
}

impl RuleSet {
    /// Build an empty rule set. Useful for tests and for the "no rules configured yet"
    /// startup state — scoring an empty rule set is well-defined and returns 100.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            #[cfg(feature = "native")]
            source: None,
            #[cfg(feature = "native")]
            last_loaded_mtime: None,
        }
    }

    /// Parse a rule set from an in-memory JSON string. Available on both native and
    /// WASM builds — this is the transport format between the reporting service and
    /// browser agents. The wire shape is a JSON array of [`Rule`] objects.
    ///
    /// An empty or whitespace-only input yields an empty rule set (the "no rules
    /// configured" state), matching the YAML loader's behavior.
    pub fn from_json_str(json: &str) -> Result<Self, RuleError> {
        let rules = parse_and_validate_json(json)?;
        Ok(Self {
            rules,
            #[cfg(feature = "native")]
            source: None,
            #[cfg(feature = "native")]
            last_loaded_mtime: None,
        })
    }

    /// Serialize this rule set to JSON for wire delivery to browser agents.
    /// Round-trips cleanly through [`RuleSet::from_json_str`].
    pub fn to_json_string(&self) -> Result<String, RuleError> {
        serde_json::to_string(&self.rules).map_err(RuleError::from)
    }

    /// Parse a rule set from an in-memory YAML string. Native builds only — the WASM
    /// bundle does not carry a YAML parser.
    #[cfg(feature = "native")]
    pub fn from_yaml_str(yaml: &str) -> Result<Self, RuleError> {
        let rules = parse_and_validate_yaml(yaml)?;
        Ok(Self {
            rules,
            source: None,
            last_loaded_mtime: None,
        })
    }

    /// Load a rule set from a YAML file. Native builds only.
    ///
    /// The path is remembered so that [`RuleSet::reload_if_changed`] can poll it.
    #[cfg(feature = "native")]
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, RuleError> {
        let path = path.as_ref().to_path_buf();
        let (rules, mtime) = read_and_parse(&path)?;
        Ok(Self {
            rules,
            source: Some(path),
            last_loaded_mtime: mtime,
        })
    }

    /// Reload the rule set from disk if the source file's mtime has advanced since the
    /// last successful load. Returns `Ok(true)` if rules were replaced, `Ok(false)` if
    /// nothing changed (or if this rule set has no on-disk source).
    ///
    /// On parse failure the *existing* rule set is preserved and the error is returned
    /// — a hot-reload attempt should never leave the engine in a worse state than it
    /// was in a moment ago.
    #[cfg(feature = "native")]
    pub fn reload_if_changed(&mut self) -> Result<bool, RuleError> {
        let Some(path) = self.source.clone() else {
            return Ok(false);
        };

        let current_mtime = fs::metadata(&path)
            .and_then(|m| m.modified())
            .map_err(|e| RuleError::Io {
                path: path.clone(),
                source: e,
            })?;

        // Only skip when we have a previously-recorded mtime *and* it exactly matches.
        // First reload after `load_from_path` always proceeds if mtime is unavailable.
        if let Some(prev) = self.last_loaded_mtime {
            if prev == current_mtime {
                return Ok(false);
            }
        }

        let (rules, mtime) = read_and_parse(&path)?;
        self.rules = rules;
        self.last_loaded_mtime = mtime;
        Ok(true)
    }

    /// All rules currently loaded. Order matches the YAML/JSON source to keep
    /// dashboard output stable for operators who read rules top-to-bottom.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Rules that react to the given event signal name (SPEC §3.1 event `type`).
    ///
    /// Linear scan is deliberate: a realistic rule set is O(dozens), and building a
    /// hash index would need to be invalidated on every hot reload. Revisit if a
    /// deployment ever exceeds a few hundred rules.
    pub fn rules_for_signal<'a>(&'a self, signal: &'a str) -> impl Iterator<Item = &'a Rule> {
        self.rules.iter().filter(move |r| r.signal == signal)
    }

    /// Path this rule set was loaded from, if any. Exposed for diagnostic logging.
    /// Native builds only.
    #[cfg(feature = "native")]
    pub fn source_path(&self) -> Option<&Path> {
        self.source.as_deref()
    }
}

/// Errors that can arise during rule loading or hot-reloading.
///
/// The YAML- and filesystem-specific variants only exist in native builds. WASM builds
/// see a smaller enum with just the JSON and validation cases, which is exactly what's
/// reachable from that build's public API.
#[derive(Debug, Error)]
pub enum RuleError {
    #[cfg(feature = "native")]
    #[error("failed to read rules file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[cfg(feature = "native")]
    #[error("failed to parse rules YAML: {0}")]
    ParseYaml(#[from] serde_yaml::Error),

    #[error("failed to parse rules JSON: {0}")]
    ParseJson(#[from] serde_json::Error),

    #[error("duplicate rule id `{0}` in rules file")]
    DuplicateId(String),

    #[error("rule `{0}` has an empty signal — every rule must react to something")]
    EmptySignal(String),

    #[error("rule `{0}` has an empty id")]
    EmptyId(String),
}

// --- Internal parsing helpers -----------------------------------------------------------

#[cfg(feature = "native")]
fn read_and_parse(path: &Path) -> Result<(Vec<Rule>, Option<SystemTime>), RuleError> {
    let contents = fs::read_to_string(path).map_err(|e| RuleError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // mtime is captured *after* the read so we can never remember a newer mtime than
    // the content we actually parsed (which would suppress a legitimate reload).
    let mtime = fs::metadata(path).ok().and_then(|m| m.modified().ok());
    let rules = parse_and_validate_yaml(&contents)?;
    Ok((rules, mtime))
}

#[cfg(feature = "native")]
fn parse_and_validate_yaml(yaml: &str) -> Result<Vec<Rule>, RuleError> {
    // Empty file → empty rule set. `serde_yaml` on an empty input yields a Null, which
    // deserializes into `Vec<Rule>` as an error; short-circuit here to give operators
    // "no rules yet" as a valid state instead of a cryptic parse error.
    if yaml.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rules: Vec<Rule> = serde_yaml::from_str(yaml)?;
    validate_rules(&rules)?;
    Ok(rules)
}

fn parse_and_validate_json(json: &str) -> Result<Vec<Rule>, RuleError> {
    // Match the YAML loader's empty-input semantics — a blank string is a valid empty
    // rule set. `serde_json` would error on `""`, so short-circuit before it gets a
    // chance to.
    if json.trim().is_empty() {
        return Ok(Vec::new());
    }
    let rules: Vec<Rule> = serde_json::from_str(json)?;
    validate_rules(&rules)?;
    Ok(rules)
}

/// Semantic validation shared by both YAML and JSON parse paths. Anything a parser
/// can't catch on its own (duplicate IDs, empty required strings) lives here so both
/// wire formats produce identical error surface.
fn validate_rules(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen_ids = std::collections::HashSet::with_capacity(rules.len());
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err(RuleError::EmptyId(rule.description.clone()));
        }
        if rule.signal.trim().is_empty() {
            return Err(RuleError::EmptySignal(rule.id.clone()));
        }
        if !seen_ids.insert(rule.id.clone()) {
            return Err(RuleError::DuplicateId(rule.id.clone()));
        }
    }
    Ok(())
}

// =====================================================================================
// Tests
// =====================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Native/YAML tests -----------------------------------------------------------
    //
    // These stay gated behind the `native` feature so `cargo test --no-default-features`
    // (used to sanity-check the WASM code path on native hardware) still compiles.

    #[cfg(feature = "native")]
    const CANONICAL_YAML: &str = r#"
- id: honeypot-field-fill
  description: "Bot filled a hidden form field"
  signal: honeypot_triggered
  weight: 80
  action: flag
- id: rate-limit-exceeded
  description: "Session exceeded request rate threshold"
  signal: rate_limit_exceeded
  weight: 40
  action: flag
"#;

    #[cfg(feature = "native")]
    #[test]
    fn parses_canonical_spec_example() {
        let set = RuleSet::from_yaml_str(CANONICAL_YAML).unwrap();
        assert_eq!(set.rules().len(), 2);
        assert_eq!(set.rules()[0].id, "honeypot-field-fill");
        assert_eq!(set.rules()[0].weight, 80);
        assert_eq!(set.rules()[0].action, Action::Flag);
    }

    #[cfg(feature = "native")]
    #[test]
    fn empty_yaml_is_a_valid_empty_ruleset() {
        // Operators may deploy the file before they've written any rules. That should
        // load cleanly, not error — scoring an empty set is well-defined.
        let set = RuleSet::from_yaml_str("").unwrap();
        assert!(set.rules().is_empty());
        let set2 = RuleSet::from_yaml_str("   \n\n  ").unwrap();
        assert!(set2.rules().is_empty());
    }

    #[cfg(feature = "native")]
    #[test]
    fn missing_action_defaults_to_flag() {
        let yaml = r#"
- id: no-action-specified
  description: "action omitted"
  signal: honeypot_triggered
  weight: 10
"#;
        let set = RuleSet::from_yaml_str(yaml).unwrap();
        assert_eq!(set.rules()[0].action, Action::Flag);
    }

    #[cfg(feature = "native")]
    #[test]
    fn all_three_actions_deserialize() {
        let yaml = r#"
- {id: a, description: x, signal: s, weight: 1, action: flag}
- {id: b, description: x, signal: s, weight: 1, action: throttle}
- {id: c, description: x, signal: s, weight: 1, action: block}
"#;
        let set = RuleSet::from_yaml_str(yaml).unwrap();
        assert_eq!(set.rules()[0].action, Action::Flag);
        assert_eq!(set.rules()[1].action, Action::Throttle);
        assert_eq!(set.rules()[2].action, Action::Block);
    }

    #[cfg(feature = "native")]
    #[test]
    fn unknown_action_is_rejected() {
        let yaml = r#"
- id: a
  description: x
  signal: s
  weight: 1
  action: nuke
"#;
        assert!(matches!(
            RuleSet::from_yaml_str(yaml),
            Err(RuleError::ParseYaml(_))
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn unknown_fields_are_rejected() {
        // Typos like `weights:` must not silently zero the rule.
        let yaml = r#"
- id: typo
  description: x
  signal: s
  weights: 80
  action: flag
"#;
        assert!(matches!(
            RuleSet::from_yaml_str(yaml),
            Err(RuleError::ParseYaml(_))
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn negative_weight_is_rejected() {
        let yaml = r#"
- id: bad
  description: x
  signal: s
  weight: -1
  action: flag
"#;
        assert!(matches!(
            RuleSet::from_yaml_str(yaml),
            Err(RuleError::ParseYaml(_))
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn duplicate_ids_are_rejected() {
        let yaml = r#"
- {id: dup, description: a, signal: s, weight: 1}
- {id: dup, description: b, signal: s, weight: 2}
"#;
        match RuleSet::from_yaml_str(yaml) {
            Err(RuleError::DuplicateId(id)) => assert_eq!(id, "dup"),
            other => panic!("expected DuplicateId, got {:?}", other),
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn empty_signal_is_rejected() {
        let yaml = r#"
- {id: r, description: a, signal: "", weight: 1}
"#;
        assert!(matches!(
            RuleSet::from_yaml_str(yaml),
            Err(RuleError::EmptySignal(_))
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn empty_id_is_rejected() {
        let yaml = r#"
- {id: "", description: a, signal: s, weight: 1}
"#;
        assert!(matches!(
            RuleSet::from_yaml_str(yaml),
            Err(RuleError::EmptyId(_))
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn rules_for_signal_filters_correctly() {
        let set = RuleSet::from_yaml_str(CANONICAL_YAML).unwrap();
        let matches: Vec<_> = set.rules_for_signal("honeypot_triggered").collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "honeypot-field-fill");

        let none: Vec<_> = set.rules_for_signal("nope").collect();
        assert!(none.is_empty());
    }

    #[cfg(feature = "native")]
    #[test]
    fn rules_for_signal_returns_all_matches_when_multiple_share_a_signal() {
        // Nothing in the schema forbids two rules reacting to the same signal, so both
        // should fire (their weights compound). This is what makes "add another
        // penalty for repeated abuse" a rules-file-only change in v2.
        let yaml = r#"
- {id: a, description: x, signal: honeypot_triggered, weight: 30}
- {id: b, description: y, signal: honeypot_triggered, weight: 25}
- {id: c, description: z, signal: other, weight: 10}
"#;
        let set = RuleSet::from_yaml_str(yaml).unwrap();
        let matches: Vec<_> = set.rules_for_signal("honeypot_triggered").collect();
        assert_eq!(matches.len(), 2);
    }

    #[cfg(feature = "native")]
    #[test]
    fn load_from_path_reads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, CANONICAL_YAML).unwrap();

        let set = RuleSet::load_from_path(&path).unwrap();
        assert_eq!(set.rules().len(), 2);
        assert_eq!(set.source_path(), Some(path.as_path()));
    }

    #[cfg(feature = "native")]
    #[test]
    fn load_from_missing_path_yields_io_error() {
        let err = RuleSet::load_from_path("/definitely/not/here.yaml").unwrap_err();
        assert!(matches!(err, RuleError::Io { .. }));
    }

    #[cfg(feature = "native")]
    #[test]
    fn reload_on_empty_ruleset_is_a_noop() {
        let mut set = RuleSet::empty();
        assert!(!set.reload_if_changed().unwrap());
    }

    #[cfg(feature = "native")]
    #[test]
    fn reload_detects_mtime_change_and_swaps_rules() {
        use std::io::Write;
        use std::thread;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(CANONICAL_YAML.as_bytes()).unwrap();
        f.sync_all().unwrap();
        drop(f);

        let mut set = RuleSet::load_from_path(&path).unwrap();
        assert_eq!(set.rules().len(), 2);

        // Filesystems (notably macOS HFS) can round mtime to whole seconds. Sleep past
        // that granularity so the reload detector doesn't false-negative.
        thread::sleep(Duration::from_millis(1100));

        let replacement = r#"
- {id: only-one, description: x, signal: s, weight: 5}
"#;
        std::fs::write(&path, replacement).unwrap();

        assert!(set.reload_if_changed().unwrap());
        assert_eq!(set.rules().len(), 1);
        assert_eq!(set.rules()[0].id, "only-one");
    }

    #[cfg(feature = "native")]
    #[test]
    fn reload_returns_false_when_file_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, CANONICAL_YAML).unwrap();

        let mut set = RuleSet::load_from_path(&path).unwrap();
        assert!(!set.reload_if_changed().unwrap());
        assert!(!set.reload_if_changed().unwrap());
    }

    #[cfg(feature = "native")]
    #[test]
    fn reload_parse_failure_preserves_previous_rules() {
        use std::thread;
        use std::time::Duration;

        // Guarantee: a bad edit never leaves the engine worse off than before.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, CANONICAL_YAML).unwrap();
        let mut set = RuleSet::load_from_path(&path).unwrap();
        let original = set.rules().to_vec();

        thread::sleep(Duration::from_millis(1100));
        std::fs::write(&path, "not: valid: yaml: [unbalanced").unwrap();

        let err = set.reload_if_changed().unwrap_err();
        assert!(matches!(err, RuleError::ParseYaml(_)));
        assert_eq!(set.rules(), original.as_slice());
    }

    #[cfg(feature = "native")]
    #[test]
    fn shipped_rules_file_parses() {
        // Guard against typos in rules/core-rules.yaml. The path is relative to the
        // crate root, which is where `cargo test` runs.
        let path = std::path::Path::new("../../rules/core-rules.yaml");
        if path.exists() {
            let set = RuleSet::load_from_path(path)
                .expect("shipped rules/core-rules.yaml must parse cleanly");
            assert!(
                !set.rules().is_empty(),
                "shipped rules file should not be empty"
            );
            // Every shipped rule must react to one of the six SPEC §3.1 signals.
            let valid_signals = [
                "honeypot_triggered",
                "canary_embedded",
                "rate_limit_exceeded",
                "behavioral_score",
                "attestation_failed",
                "request_fingerprint",
            ];
            for rule in set.rules() {
                assert!(
                    valid_signals.contains(&rule.signal.as_str()),
                    "shipped rule `{}` uses signal `{}` which is not in SPEC §3.1",
                    rule.id,
                    rule.signal
                );
            }
        }
    }

    // --- JSON tests (available in both native and WASM builds) -----------------------
    //
    // These exercise the wire format the browser agent will use in sub-step 2c.
    // They compile and pass with either `--features native` (default) or
    // `--no-default-features`.

    const CANONICAL_JSON: &str = r#"[
        {"id": "honeypot-field-fill", "description": "Bot filled a hidden form field", "signal": "honeypot_triggered", "weight": 80, "action": "flag"},
        {"id": "rate-limit-exceeded", "description": "Rate", "signal": "rate_limit_exceeded", "weight": 40, "action": "flag"}
    ]"#;

    #[test]
    fn parses_canonical_json() {
        let set = RuleSet::from_json_str(CANONICAL_JSON).unwrap();
        assert_eq!(set.rules().len(), 2);
        assert_eq!(set.rules()[0].id, "honeypot-field-fill");
        assert_eq!(set.rules()[0].weight, 80);
        assert_eq!(set.rules()[0].action, Action::Flag);
    }

    #[test]
    fn empty_json_is_a_valid_empty_ruleset() {
        // Match YAML loader semantics — an empty/whitespace input is not an error.
        assert!(RuleSet::from_json_str("").unwrap().rules().is_empty());
        assert!(RuleSet::from_json_str("  \n\t ")
            .unwrap()
            .rules()
            .is_empty());
        // An explicit empty array is also fine.
        assert!(RuleSet::from_json_str("[]").unwrap().rules().is_empty());
    }

    #[test]
    fn malformed_json_yields_parse_error() {
        let set = RuleSet::from_json_str("[{not-json");
        assert!(matches!(set, Err(RuleError::ParseJson(_))));
    }

    #[test]
    fn json_missing_required_field_yields_parse_error() {
        // Missing `weight` — serde rejects. Guarantees the browser can never load a
        // rule set with holes in it.
        let json = r#"[{"id": "a", "description": "x", "signal": "s", "action": "flag"}]"#;
        assert!(matches!(
            RuleSet::from_json_str(json),
            Err(RuleError::ParseJson(_))
        ));
    }

    #[test]
    fn json_unknown_field_is_rejected() {
        // Same deny_unknown_fields protection as YAML — typos never pass silently.
        let json = r#"[{"id": "a", "description": "x", "signal": "s", "weights": 10}]"#;
        assert!(matches!(
            RuleSet::from_json_str(json),
            Err(RuleError::ParseJson(_))
        ));
    }

    #[test]
    fn json_duplicate_ids_are_rejected() {
        let json = r#"[
            {"id": "dup", "description": "x", "signal": "s", "weight": 1},
            {"id": "dup", "description": "y", "signal": "s", "weight": 2}
        ]"#;
        match RuleSet::from_json_str(json) {
            Err(RuleError::DuplicateId(id)) => assert_eq!(id, "dup"),
            other => panic!("expected DuplicateId, got {:?}", other),
        }
    }

    #[test]
    fn json_empty_signal_is_rejected() {
        let json = r#"[{"id": "r", "description": "a", "signal": "", "weight": 1}]"#;
        assert!(matches!(
            RuleSet::from_json_str(json),
            Err(RuleError::EmptySignal(_))
        ));
    }

    #[test]
    fn json_missing_action_defaults_to_flag() {
        // #[serde(default)] on the `action` field means JSON callers can omit it too.
        let json = r#"[{"id": "a", "description": "x", "signal": "s", "weight": 10}]"#;
        let set = RuleSet::from_json_str(json).unwrap();
        assert_eq!(set.rules()[0].action, Action::Flag);
    }

    #[test]
    fn json_round_trip_through_to_json_string() {
        // Serialize → parse → compare. Guards against any serde attribute drift that
        // would break the reporting-service → browser handoff.
        let original = RuleSet::from_json_str(CANONICAL_JSON).unwrap();
        let serialized = original.to_json_string().unwrap();
        let reparsed = RuleSet::from_json_str(&serialized).unwrap();
        assert_eq!(original.rules(), reparsed.rules());
    }

    // Bridge test: prove YAML and JSON produce identical `Rule` structs from equivalent
    // inputs. This is what makes "operators edit YAML, browsers receive JSON" a safe
    // hand-off — the two wire formats deserialize into the exact same in-memory shape.
    #[cfg(feature = "native")]
    #[test]
    fn yaml_and_json_produce_equal_rules() {
        let from_yaml = RuleSet::from_yaml_str(CANONICAL_YAML).unwrap();
        let from_json = RuleSet::from_json_str(CANONICAL_JSON).unwrap();
        // Descriptions differ intentionally in the JSON canonical to keep the strings
        // short — normalize by comparing every field except description.
        assert_eq!(from_yaml.rules().len(), from_json.rules().len());
        for (y, j) in from_yaml.rules().iter().zip(from_json.rules()) {
            assert_eq!(y.id, j.id);
            assert_eq!(y.signal, j.signal);
            assert_eq!(y.weight, j.weight);
            assert_eq!(y.action, j.action);
        }
    }

    #[test]
    fn empty_ruleset_serializes_to_empty_array() {
        let set = RuleSet::empty();
        assert_eq!(set.to_json_string().unwrap(), "[]");
    }
}
