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
//! The digest keys are SQL `COALESCE`s there. `group_by_first_of` reads them from the event's
//! own columns inside the fold; the `subject_ref` and `target_ref` columns exist only as a
//! second way to the same answer. `event_refs` is not compared.

use std::sync::Arc;

use arrow::{
    array::{ArrayRef, Int64Array, RecordBatch, StringArray},
    datatypes::{Field, Schema},
};
use lance_graph_dt64::dr::{LocalMap, TileMap, ValueKey, Width};
use o2_substrate::{Filter, Key, PairGroup, Refusal, Scope, StreamSource, TIMESTAMP};
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
        ("account_ref", text(&field("account_ref"))),
        ("resource_ref", text(&field("resource_ref"))),
        ("policy_ref", text(&field("policy_ref"))),
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

const SUBJECT: [&str; 3] = ["account_ref", "resource_ref", "policy_ref"];
const TARGET: [&str; 2] = ["resource_ref", "policy_ref"];
const SUBJECT_KEY: Side<'static> = Side::Entity(&SUBJECT);
const SIGNAL: Side<'static> = Side::Property("signal");

/// The entities the test's tile holds. The order is not the order the stream meets them in,
/// so a position can only come from the map. No signal is here: a signal is a property.
const ENTITIES: [&str; 3] = [
    "synthetic-policy-01",
    "synthetic-mailbox-01",
    "synthetic-actor-01",
];

/// The caller's DT reading of a value key: the identity it names.
fn identity(key: &ValueKey) -> Option<u64> {
    ENTITIES
        .iter()
        .position(|n| *n == key.0)
        .map(|i| 1_000 + i as u64)
}

fn tile() -> LocalMap {
    let globals: Vec<u64> = (0..ENTITIES.len() as u64).map(|i| 1_000 + i).collect();
    LocalMap::prepare(Width::W64, &globals).unwrap()
}

fn name(map: TileMap<'_>, local: u32) -> String {
    ENTITIES[(map.global(local as u8).unwrap() - 1_000) as usize].to_string()
}

fn tenant(r: &o2_substrate::Reader<'_>, on: bool) -> Filter {
    if on {
        Filter::and([
            r.eq_text("customer_code", "LAB").unwrap(),
            r.eq_text("tenant_alias", "lab-1").unwrap(),
        ])
    } else {
        r.all()
    }
}

/// The digest over precomputed key columns: the fused pair fold, named by the code table.
fn fold_columns(rows: &[Map<String, Value>], hi: &str, lo: &str) -> Vec<PairGroup> {
    let mut source = StreamSource::new(CLASS, READER);
    source.append(&batch(rows)).unwrap();
    let r = source.reader().unwrap();
    let mut groups = r.group_by_pair(tenant(&r, true), hi, lo).unwrap();
    groups.sort();
    groups
}

/// One side of a digest key in the test: entity columns, or one property column.
#[derive(Clone, Copy)]
enum Side<'a> {
    Entity(&'a [&'a str]),
    Property(&'a str),
}

fn key<'a>(side: Side<'a>, map: TileMap<'a>) -> Key<'a> {
    match side {
        Side::Entity(columns) => Key::Entity {
            columns,
            map,
            identity: &identity,
        },
        Side::Property(column) => Key::Property { column },
    }
}

/// The digest over the event's own columns: entities placed by the tile and named back
/// through it, a property named by the code table.
fn fold_placed(
    rows: &[Map<String, Value>],
    hi: Side<'_>,
    lo: Side<'_>,
    fenced: bool,
) -> Result<Vec<PairGroup>, Refusal> {
    let mut source = StreamSource::new(CLASS, READER);
    source.append(&batch(rows)).unwrap();
    let r = source.reader().unwrap();
    let tile = tile();
    let (hi_key, lo_key) = (key(hi, tile.view()), key(lo, tile.view()));
    let text = |side: Side<'_>, at: u32| match side {
        Side::Entity(_) => name(tile.view(), at),
        Side::Property(column) => r.label(column, at).unwrap().to_string(),
    };
    let placed = r.group_by_first_of(tenant(&r, fenced), &hi_key, &lo_key)?;
    let mut groups: Vec<PairGroup> = placed
        .iter()
        .map(|g| PairGroup {
            hi: text(hi, g.hi),
            lo: text(lo, g.lo),
            rows: g.rows,
            first_us: g.first_us,
            last_us: g.last_us,
        })
        .collect();
    groups.sort();
    Ok(groups)
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
    let rows = events(&c, false);
    assert_eq!(
        fold_placed(&rows, SUBJECT_KEY, SIGNAL, true),
        Ok(want.clone())
    );
    assert_eq!(fold_columns(&rows, "subject_ref", "signal"), want);
}

#[test]
fn the_actor_link_digest_equals_the_captured_reply() {
    let c = capture();
    let want = captured(&c, "actor_link", "actor_ref", "target_ref");
    assert_eq!(want.len(), 2);
    let rows = events(&c, false);
    assert_eq!(
        fold_placed(
            &rows,
            Side::Entity(&["actor_ref"]),
            Side::Entity(&TARGET),
            true
        ),
        Ok(want.clone())
    );
    assert_eq!(fold_columns(&rows, "actor_ref", "target_ref"), want);
}

/// Without the tenant terms the foreign row joins a group, so the filter is what fences it.
#[test]
fn the_foreign_tenant_row_is_fenced_by_the_filter() {
    let c = capture();
    let want = captured(&c, "signal_summary", "subject_ref", "signal");
    let open = fold_placed(&events(&c, false), SUBJECT_KEY, SIGNAL, false).unwrap();
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
    assert_ne!(
        fold_placed(&events(&c, true), SUBJECT_KEY, SIGNAL, true),
        Ok(want)
    );
}

/// The order of the columns is the key: a row holding two of them takes the first.
#[test]
fn the_first_column_a_row_holds_names_its_group() {
    let c = capture();
    let mut rows = events(&c, false);
    rows[0].insert("policy_ref".into(), "synthetic-policy-01".into());
    let by = |hi: &[&str]| fold_placed(&rows, Side::Entity(hi), SIGNAL, true).unwrap();
    let want = captured(&c, "signal_summary", "subject_ref", "signal");
    assert_eq!(by(&SUBJECT), want);
    assert_ne!(by(&["policy_ref", "account_ref", "resource_ref"]), want);
}

/// A key the tile does not place is refused once a row is counted under it, and only then.
#[test]
fn a_counted_row_without_a_position_is_refused() {
    let c = capture();
    let mut rows = events(&c, false);
    let foreign = rows.len() - 1;
    rows[foreign].insert("account_ref".into(), "k02-actor".into());
    let want = captured(&c, "signal_summary", "subject_ref", "signal");
    assert_eq!(fold_placed(&rows, SUBJECT_KEY, SIGNAL, true), Ok(want));
    assert_eq!(
        fold_placed(&rows, SUBJECT_KEY, SIGNAL, false),
        Err(Refusal::Unplaced("k02-actor".to_string()))
    );
}

/// A signal is a property: with the signal side asked as an entity, the tile holds no
/// position for it and the fold is refused instead of answered.
#[test]
fn a_property_asked_as_an_entity_is_refused() {
    let c = capture();
    let rows = events(&c, false);
    let refused = fold_placed(&rows, SUBJECT_KEY, Side::Entity(&["signal"]), true);
    assert!(matches!(refused, Err(Refusal::Unplaced(_))), "{refused:?}");
}
