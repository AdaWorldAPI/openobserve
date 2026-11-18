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
//! Log pattern extraction: rows that share a shape become one template with a frequency.
//!
//! Every rule here is pinned by a capture in `tests/parity/enterprise-v1.1.2-pattern-shapes.json`.
//! `tests/oracle.rs` names the captured cases this crate does not answer the same way yet.

#![forbid(unsafe_code)]

use std::{collections::HashMap, net::Ipv4Addr};

const WILDCARD: &str = "<*>";
const IPV4: &str = "<:IPV4>";

/// The knobs of one extraction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Config {
    /// A message with fewer characters is not analysed.
    pub min_length: usize,
    /// Leading tokens that must agree for two rows to share a pattern.
    pub prefix_tokens: usize,
    /// The share of equal tokens a row needs to join an existing pattern.
    pub similarity: f64,
    /// A pattern with fewer rows is not reported.
    pub min_cluster_size: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            min_length: 20,
            prefix_tokens: 5,
            similarity: 0.3,
            min_cluster_size: 10,
        }
    }
}

/// One reported pattern.
#[derive(Clone, Debug, PartialEq)]
pub struct Pattern {
    pub template: String,
    pub frequency: usize,
    /// `frequency` as a share of the analysed rows, in percent.
    pub percentage: f64,
}

/// The answer for one set of messages.
#[derive(Clone, Debug, PartialEq)]
pub struct Extraction {
    pub analyzed: usize,
    /// Most frequent first; equal frequencies by template.
    pub patterns: Vec<Pattern>,
    /// The share of analysed rows that fall in a reported pattern, in percent.
    pub coverage_percentage: f64,
}

struct Cluster {
    template: Vec<String>,
    frequency: usize,
}

impl Cluster {
    /// Equal tokens over all tokens; a wildcard in the template equals nothing.
    fn similarity(&self, tokens: &[String]) -> f64 {
        let equal = self
            .template
            .iter()
            .zip(tokens)
            .filter(|(a, b)| a == b)
            .count();
        equal as f64 / tokens.len() as f64
    }

    fn absorb(&mut self, tokens: &[String]) {
        for (have, new) in self.template.iter_mut().zip(tokens) {
            if have != new {
                *have = WILDCARD.to_string();
            }
        }
        self.frequency += 1;
    }
}

/// The patterns of `messages` under `config`.
pub fn extract<'a>(messages: impl IntoIterator<Item = &'a str>, config: &Config) -> Extraction {
    let mut clusters: Vec<Cluster> = Vec::new();
    let mut leaves: HashMap<(usize, Vec<String>), Vec<usize>> = HashMap::new();
    let mut analyzed = 0;
    for message in messages {
        if message.chars().count() < config.min_length {
            continue;
        }
        let tokens = tokenize(message);
        if tokens.is_empty() {
            continue;
        }
        analyzed += 1;
        let leaf = leaves
            .entry(route(&tokens, config.prefix_tokens))
            .or_default();
        let best = leaf
            .iter()
            .map(|&c| (c, clusters[c].similarity(&tokens)))
            .filter(|(_, s)| *s >= config.similarity)
            .max_by(|a, b| a.1.total_cmp(&b.1));
        match best {
            Some((c, _)) => clusters[c].absorb(&tokens),
            None => {
                leaf.push(clusters.len());
                clusters.push(Cluster {
                    template: tokens,
                    frequency: 1,
                });
            }
        }
    }
    report(clusters, analyzed, config.min_cluster_size)
}

/// Splits on whitespace and names an IPv4 address by its kind.
fn tokenize(message: &str) -> Vec<String> {
    message
        .split_whitespace()
        .map(|t| {
            if t.parse::<Ipv4Addr>().is_ok() {
                IPV4.to_string()
            } else {
                t.to_string()
            }
        })
        .collect()
}

/// The leaf a row belongs to: its token count and leading tokens, any token with a digit as one.
fn route(tokens: &[String], prefix: usize) -> (usize, Vec<String>) {
    let lead = tokens
        .iter()
        .take(prefix)
        .map(|t| {
            if t.bytes().any(|b| b.is_ascii_digit()) {
                WILDCARD.to_string()
            } else {
                t.clone()
            }
        })
        .collect();
    (tokens.len(), lead)
}

fn report(clusters: Vec<Cluster>, analyzed: usize, min_cluster_size: usize) -> Extraction {
    let percent = |rows: usize| {
        if analyzed == 0 {
            0.0
        } else {
            rows as f64 / analyzed as f64 * 100.0
        }
    };
    let mut patterns: Vec<Pattern> = clusters
        .into_iter()
        .filter(|c| c.frequency >= min_cluster_size)
        .map(|c| Pattern {
            template: c.template.join(" "),
            frequency: c.frequency,
            percentage: percent(c.frequency),
        })
        .collect();
    patterns.sort_by(|a, b| {
        b.frequency
            .cmp(&a.frequency)
            .then_with(|| a.template.cmp(&b.template))
    });
    let covered = patterns.iter().map(|p| p.frequency).sum();
    Extraction {
        analyzed,
        patterns,
        coverage_percentage: percent(covered),
    }
}
