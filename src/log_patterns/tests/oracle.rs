// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//! The extractor against the captured answers of the reference binary.

use o2_log_patterns::{Config, Extraction, extract};
use serde_json::Value;

const ORACLE: &str = include_str!("../../../tests/parity/enterprise-v1.1.2-pattern-shapes.json");

/// Captured cases this crate answers differently: runs of adjacent variable tokens, and the
/// kinds other than IPv4 (`<:UUID>`, `<:TIMESTAMP>`, `<:IDENTIFIERS>`).
const OPEN: [&str; 5] = [
    "adjacent_mixed",
    "adjacent_numbers",
    "ipv4_next_to_number",
    "other_kinds",
    "word_then_number",
];

fn oracle() -> Value {
    serde_json::from_str(ORACLE).unwrap()
}

fn messages(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect()
}

fn run(messages: &[&str], config: &Config) -> Extraction {
    extract(messages.iter().copied(), config)
}

fn pairs(e: &Extraction) -> Vec<(String, u64)> {
    e.patterns
        .iter()
        .map(|p| (p.template.clone(), p.frequency as u64))
        .collect()
}

fn captured_pairs(v: &Value) -> Vec<(String, u64)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|p| (p[0].as_str().unwrap().to_string(), p[1].as_u64().unwrap()))
        .collect()
}

/// Templates, frequencies, shares, row count and coverage of one full captured answer.
fn assert_answer(got: &Extraction, want: &Value, what: &str) {
    let stats = &want["statistics"];
    assert_eq!(
        got.analyzed as u64,
        stats["total_logs_analyzed"].as_u64().unwrap(),
        "{what}"
    );
    let coverage = stats["coverage_percentage"].as_f64().unwrap();
    assert!((got.coverage_percentage - coverage).abs() < 1e-6, "{what}");
    let patterns = want["patterns"].as_array().unwrap();
    assert_eq!(got.patterns.len(), patterns.len(), "{what}");
    for (g, w) in got.patterns.iter().zip(patterns) {
        assert_eq!(g.template, w["template"].as_str().unwrap(), "{what}");
        assert_eq!(
            g.frequency as u64,
            w["frequency"].as_u64().unwrap(),
            "{what}"
        );
        let share = w["percentage"].as_f64().unwrap();
        assert!((g.percentage - share).abs() < 1e-6, "{what}");
    }
}

#[test]
fn five_shapes_give_the_four_captured_patterns() {
    let o = oracle();
    let got = run(&messages(&o["messages"]), &Config::default());
    assert_eq!(got.patterns.len(), 4);
    assert_answer(&got, &o["all"], "all");
}

/// One shape alone keeps its template; the shape with 6 rows is analysed and reported as nothing.
#[test]
fn the_two_control_windows_match() {
    let o = oracle();
    let all = messages(&o["messages"]);
    for (name, want) in o["controls"].as_object().unwrap() {
        let prefix = want["like"].as_str().unwrap().trim_end_matches('%');
        let window: Vec<&str> = all
            .iter()
            .copied()
            .filter(|m| m.starts_with(prefix))
            .collect();
        assert!(!window.is_empty() && window.len() < all.len(), "{name}");
        assert_answer(&run(&window, &Config::default()), want, name);
    }
    assert!(
        o["controls"]["below_minimum"]["patterns"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// Every rule probe outside `OPEN` matches; every probe in `OPEN` still differs.
#[test]
fn the_rule_probes_match_except_the_open_ones() {
    let o = oracle();
    let rules = o["rules"].as_object().unwrap();
    assert_eq!(rules.len(), 14);
    for name in OPEN {
        assert!(rules.contains_key(name), "{name} is not a captured probe");
    }
    for (name, want) in rules {
        let got = run(&messages(&want["messages"]), &Config::default());
        let same = got.analyzed as u64 == want["analyzed"].as_u64().unwrap()
            && pairs(&got) == captured_pairs(&want["patterns"]);
        assert_eq!(same, !OPEN.contains(&name.as_str()), "{name}: {got:?}");
    }
}

/// Each knob changes an answer: none of them is decoration.
#[test]
fn each_knob_changes_an_answer() {
    let o = oracle();
    let rules = &o["rules"];
    let base = Config::default();

    let short = messages(&rules["short_rows"]["messages"]);
    assert_eq!(run(&short, &base).analyzed, 36);
    let no_floor = Config {
        min_length: 0,
        ..base
    };
    assert_eq!(run(&short, &no_floor).analyzed, 40);

    let sixth = messages(&rules["sixth_word"]["messages"]);
    assert_eq!(run(&sixth, &base).patterns.len(), 1);
    let strict = Config {
        similarity: 0.99,
        ..base
    };
    assert_eq!(run(&sixth, &strict).patterns.len(), 2);
    let long_prefix = Config {
        prefix_tokens: 6,
        ..base
    };
    assert_eq!(run(&sixth, &long_prefix).patterns.len(), 2);

    let all = messages(&o["messages"]);
    let small = Config {
        min_cluster_size: 2,
        ..base
    };
    assert_eq!(run(&all, &small).patterns.len(), 7);
}

#[test]
fn no_message_gives_no_pattern() {
    let got = run(&[], &Config::default());
    assert_eq!(got.analyzed, 0);
    assert!(got.patterns.is_empty());
    assert_eq!(got.coverage_percentage, 0.0);
}
