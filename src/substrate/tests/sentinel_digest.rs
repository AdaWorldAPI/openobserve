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
//! Sentinel's two digest queries, answered by folds over lanes and compared with the replies
//! sentinel-rs captured from a real OpenObserve (`tests/data/sentinel-digests.json`).
//!
//! The digest keys (`subject_ref`, `target_ref`) are SQL `COALESCE`s there; here they are
//! columns of the batch, as an ingest function would write them. `event_refs` is not compared.

use std::sync::Arc;

use arrow::{
    array::{ArrayRef, Int64Array, RecordBatch, StringArray},
    datatypes::{Field, Schema},
};
use o2_substrate::{Filter, PairGroup, Scope, StreamSource, TIMESTAMP};
use serde_json::{Map, Value};

const CAPTURE: &str = include_str!("data/sentinel-digests.json");
const CLASS: u32 = 0x0C1D_0002;
const READER: Scope = Scope { id: 1 };
const MINUTE_US: i64 = 60_000_000;

fn capture() -> Value {
    serde_json::from_str(CAPTURE).unwrap()
}

/// The six rows sentinel's `poc/openobserve-live/events.py` ingests: the four fixture events
/// a minute apart, a second failure in the first event's group, and one of a foreign tenant.
fn events(c: &Value, mutate: bool) -> Vec<Map<String, Value>> {
    let base = c["signal_summary"]["start_time"].as_i64().unwrap();
    let mut rows: Vec<Map<String, Value>> = c["events"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let mut e = e.as_object().unwrap().clone();
            e.insert(TIMESTAMP.into(), (base + (i as i64 + 1) * MINUTE_US).into());
            e
        })
        .collect();
    let mut second = rows[0].clone();
    second.insert("event_id".into(), "entra-signin-fail-05".into());
    second.insert(TIMESTAMP.into(), (base + 270_000_000).into());
    let mut foreign = rows[0].clone();
    foreign.insert("event_id".into(), "foreign-k02-01".into());
    foreign.insert("customer_code".into(), "K02".into());
    foreign.insert("tenant_alias".into(), "k02-1".into());
    foreign.insert(TIMESTAMP.into(), (base + 30_000_000).into());
    rows.extend([second, foreign]);
    if mutate {
        rows[1].insert("signal".into(), "signin_failure_burst".into());
    }
    rows
}

fn first_of<'a>(row: &'a Map<String, Value>, fields: &[&str]) -> Option<&'a str> {
    fields.iter().find_map(|f| row.get(*f)?.as_str())
}

fn batch(rows: &[Map<String, Value>]) -> RecordBatch {
    let text = |pick: &dyn Fn(&Map<String, Value>) -> Option<String>| -> ArrayRef {
        Arc::new(StringArray::from(
            rows.iter().map(pick).collect::<Vec<Option<String>>>(),
        ))
    };
    let field =
        |name: &'static str| move |r: &Map<String, Value>| first_of(r, &[name]).map(str::to_string);
    let time: Vec<i64> = rows
        .iter()
        .map(|r| r[TIMESTAMP].as_i64().unwrap())
        .collect();
    let columns: Vec<(&str, ArrayRef)> = vec![
        (TIMESTAMP, Arc::new(Int64Array::from(time))),
        ("customer_code", text(&field("customer_code"))),
        ("tenant_alias", text(&field("tenant_alias"))),
        ("signal", text(&field("signal"))),
        ("actor_ref", text(&field("actor_ref"))),
        (
            "subject_ref",
            text(&|r| {
                first_of(r, &["account_ref", "resource_ref", "policy_ref"]).map(str::to_string)
            }),
        ),
        (
            "target_ref",
            text(&|r| first_of(r, &["resource_ref", "policy_ref"]).map(str::to_string)),
        ),
    ];
    let fields: Vec<Field> = columns
        .iter()
        .map(|(n, a)| Field::new(*n, a.data_type().clone(), true))
        .collect();
    RecordBatch::try_new(
        Arc::new(Schema::new(fields)),
        columns.into_iter().map(|(_, a)| a).collect(),
    )
    .unwrap()
}

/// `(hi, lo, rows, first, last)` per group, sorted; `tenant` narrows to sentinel's `WHERE`.
fn fold(rows: &[Map<String, Value>], hi: &str, lo: &str, tenant: bool) -> Vec<PairGroup> {
    let mut source = StreamSource::new(CLASS, READER);
    source.append(&batch(rows)).unwrap();
    let r = source.reader().unwrap();
    let filter = if tenant {
        Filter::and([
            r.eq_text("customer_code", "LAB").unwrap(),
            r.eq_text("tenant_alias", "lab-1").unwrap(),
        ])
    } else {
        r.all()
    };
    let mut groups = r.group_by_pair(filter, hi, lo).unwrap();
    groups.sort();
    groups
}

fn captured(c: &Value, query: &str, hi: &str, lo: &str) -> Vec<PairGroup> {
    assert_eq!(c[query]["is_partial"], false);
    let mut groups: Vec<PairGroup> = c[query]["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| PairGroup {
            hi: h[hi].as_str().unwrap().to_string(),
            lo: h[lo].as_str().unwrap().to_string(),
            rows: h["events"].as_u64().unwrap() as usize,
            first_us: h["first_us"].as_i64().unwrap(),
            last_us: h["last_us"].as_i64().unwrap(),
        })
        .collect();
    groups.sort();
    groups
}

#[test]
fn the_signal_summary_digest_equals_the_captured_reply() {
    let c = capture();
    let want = captured(&c, "signal_summary", "subject_ref", "signal");
    assert_eq!(want.len(), 4);
    assert_eq!(
        fold(&events(&c, false), "subject_ref", "signal", true),
        want
    );
}

#[test]
fn the_actor_link_digest_equals_the_captured_reply() {
    let c = capture();
    let want = captured(&c, "actor_link", "actor_ref", "target_ref");
    assert_eq!(want.len(), 2);
    assert_eq!(
        fold(&events(&c, false), "actor_ref", "target_ref", true),
        want
    );
}

/// Without the tenant terms the foreign row joins a group, so the filter is what fences it.
#[test]
fn the_foreign_tenant_row_is_fenced_by_the_filter() {
    let c = capture();
    let want = captured(&c, "signal_summary", "subject_ref", "signal");
    let open = fold(&events(&c, false), "subject_ref", "signal", false);
    assert_ne!(open, want);
    assert_eq!(
        open.iter().map(|g| g.rows).sum::<usize>(),
        want.iter().map(|g| g.rows).sum::<usize>() + 1
    );
}

#[test]
fn a_changed_signal_changes_the_digest() {
    let c = capture();
    let want = captured(&c, "signal_summary", "subject_ref", "signal");
    assert_ne!(fold(&events(&c, true), "subject_ref", "signal", true), want);
}
