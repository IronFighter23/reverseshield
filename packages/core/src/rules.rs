//! Rule loading, deserialization, and hot-reloading.
//!
//! This module owns the *shape* of a detection rule and how rules get from disk into
//! memory. Everything about *what a rule means numerically* — how a triggered rule maps
//! to a score change — lives in [`crate::scoring`]. Splitting it this way lets the
//! reporting service load a `RuleSet` once at startup, watch the file for edits, and
//! ask the scoring module to evaluate signals without either side leaking into the
//! other.
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

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What the engine should do when a rule triggers.
///
/// v1 only reports; `Throttle` and `Block` are parsed and preserved so that Phase 2
/// middlewares can enforce them without a rules-file migration. See SPEC §3.4 —
/// "Automatic blocking based on score is a v2 feature gated behind explicit config
/// (`action: block`) — never on by default."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Flag,
    Throttle,
    Block,
}

impl Default for Action {
    fn default() -> Self {
        Action::Flag
    }
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

/// An in-memory rule set plus the metadata needed to hot-reload it.
///
/// A `RuleSet` can be built three ways:
///   * [`RuleSet::from_yaml_str`] — for tests and for hosts that ship rules inline.
///   * [`RuleSet::load_from_path`] — for the reporting service and middlewares.
///   * [`RuleSet::empty`] — for constructing scoring-only pipelines in tests.
///
/// Only rule sets built from a path can be reloaded; the others return
/// `Ok(false)` from [`RuleSet::reload_if_changed`] because there's nothing to poll.
#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<Rule>,
    source: Option<PathBuf>,
    /// mtime observed the last time we successfully loaded `source`. `None` means the
    /// source has never been read (or the FS didn't report an mtime, which we treat as
    /// "always reload" — better a redundant parse than a stale rule set).
    last_loaded_mtime: Option<SystemTime>,
}

impl RuleSet {
    /// Build an empty rule set. Useful for tests and for the "no rules configured yet"
    /// startup state — scoring an empty rule set is well-defined and returns 100.
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            source: None,
            last_loaded_mtime: None,
        }
    }

    /// Parse a rule set from an in-memory YAML string.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, RuleError> {
        let rules = parse_and_validate(yaml)?;
        Ok(Self {
            rules,
            source: None,
            last_loaded_mtime: None,
        })
    }

    /// Load a rule set from a YAML file. The path is remembered so that
    /// [`RuleSet::reload_if_changed`] can poll it.
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

    /// All rules currently loaded. Order matches the YAML file to keep dashboard output
    /// stable for operators who read the file top-to-bottom.
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
    pub fn source_path(&self) -> Option<&Path> {
        self.source.as_deref()
    }
}

/// Errors that can arise during rule loading or hot-reloading.
#[derive(Debug, Error)]
pub enum RuleError {
    #[error("failed to read rules file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse rules YAML: {0}")]
    Parse(#[from] serde_yaml::Error),

    #[error("duplicate rule id `{0}` in rules file")]
    DuplicateId(String),

    #[error("rule `{0}` has an empty signal — every rule must react to something")]
    EmptySignal(String),

    #[error("rule `{0}` has an empty id")]
    EmptyId(String),
}

fn read_and_parse(path: &Path) -> Result<(Vec<Rule>, Option<SystemTime>), RuleError> {
    let contents = fs::read_to_string(path).map_err(|e| RuleError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // mtime is captured *after* the read so we can never remember a newer mtime than
    // the content we actually parsed (which would suppress a legitimate reload).
    let mtime = fs::metadata(path).ok().and_then(|m| m.modified().ok());
    let rules = parse_and_validate(&contents)?;
    Ok((rules, mtime))
}

fn parse_and_validate(yaml: &str) -> Result<Vec<Rule>, RuleError> {
    // Empty file → empty rule set. `serde_yaml` on an empty input yields a Null, which
    // deserializes into `Vec<Rule>` as an error; short-circuit here to give operators
    // "no rules yet" as a valid state instead of a cryptic parse error.
    if yaml.trim().is_empty() {
        return Ok(Vec::new());
    }

    let rules: Vec<Rule> = serde_yaml::from_str(yaml)?;

    let mut seen_ids = std::collections::HashSet::with_capacity(rules.len());
    for rule in &rules {
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

    Ok(rules)
}

// =====================================================================================
// Tests
// =====================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;

    const CANONICAL: &str = r#"
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

    #[test]
    fn parses_canonical_spec_example() {
        let set = RuleSet::from_yaml_str(CANONICAL).unwrap();
        assert_eq!(set.rules().len(), 2);
        assert_eq!(set.rules()[0].id, "honeypot-field-fill");
        assert_eq!(set.rules()[0].weight, 80);
        assert_eq!(set.rules()[0].action, Action::Flag);
    }

    #[test]
    fn empty_yaml_is_a_valid_empty_ruleset() {
        // Operators may deploy the file before they've written any rules. That should
        // load cleanly, not error — scoring an empty set is well-defined.
        let set = RuleSet::from_yaml_str("").unwrap();
        assert!(set.rules().is_empty());
        let set2 = RuleSet::from_yaml_str("   \n\n  ").unwrap();
        assert!(set2.rules().is_empty());
    }

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
            Err(RuleError::Parse(_))
        ));
    }

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
            Err(RuleError::Parse(_))
        ));
    }

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
            Err(RuleError::Parse(_))
        ));
    }

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

    #[test]
    fn rules_for_signal_filters_correctly() {
        let set = RuleSet::from_yaml_str(CANONICAL).unwrap();
        let matches: Vec<_> = set.rules_for_signal("honeypot_triggered").collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "honeypot-field-fill");

        let none: Vec<_> = set.rules_for_signal("nope").collect();
        assert!(none.is_empty());
    }

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

    #[test]
    fn load_from_path_reads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        fs::write(&path, CANONICAL).unwrap();

        let set = RuleSet::load_from_path(&path).unwrap();
        assert_eq!(set.rules().len(), 2);
        assert_eq!(set.source_path(), Some(path.as_path()));
    }

    #[test]
    fn load_from_missing_path_yields_io_error() {
        let err = RuleSet::load_from_path("/definitely/not/here.yaml").unwrap_err();
        assert!(matches!(err, RuleError::Io { .. }));
    }

    #[test]
    fn reload_on_empty_ruleset_is_a_noop() {
        let mut set = RuleSet::empty();
        assert!(!set.reload_if_changed().unwrap());
    }

    #[test]
    fn reload_detects_mtime_change_and_swaps_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(CANONICAL.as_bytes()).unwrap();
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
        fs::write(&path, replacement).unwrap();

        assert!(set.reload_if_changed().unwrap());
        assert_eq!(set.rules().len(), 1);
        assert_eq!(set.rules()[0].id, "only-one");
    }

    #[test]
    fn reload_returns_false_when_file_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        fs::write(&path, CANONICAL).unwrap();

        let mut set = RuleSet::load_from_path(&path).unwrap();
        assert!(!set.reload_if_changed().unwrap());
        assert!(!set.reload_if_changed().unwrap());
    }

    #[test]
    fn reload_parse_failure_preserves_previous_rules() {
        // Guarantee: a bad edit never leaves the engine worse off than before.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.yaml");
        fs::write(&path, CANONICAL).unwrap();
        let mut set = RuleSet::load_from_path(&path).unwrap();
        let original = set.rules().to_vec();

        thread::sleep(Duration::from_millis(1100));
        fs::write(&path, "not: valid: yaml: [unbalanced").unwrap();

        let err = set.reload_if_changed().unwrap_err();
        assert!(matches!(err, RuleError::Parse(_)));
        assert_eq!(set.rules(), original.as_slice());
    }

    #[test]
    fn shipped_rules_file_parses() {
        // Guard against typos in rules/core-rules.yaml. The path is relative to the
        // crate root, which is where `cargo test` runs.
        let path = std::path::Path::new("../../rules/core-rules.yaml");
        if path.exists() {
            let set = RuleSet::load_from_path(path)
                .expect("shipped rules/core-rules.yaml must parse cleanly");
            assert!(!set.rules().is_empty(), "shipped rules file should not be empty");
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
}
