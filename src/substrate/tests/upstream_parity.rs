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

use std::sync::Arc;

use arrow::{
    array::{Float64Array, Int64Array, RecordBatch, StringArray},
    datatypes::{DataType, Field, Schema},
};
use o2_substrate::{LaneTable, Refusal};
use serde_json::Value;

/// The log half of the fixture `tests/parity/o2_parity.py` ingests, row for row.
fn fixture(mutate: bool) -> RecordBatch {
    let n = 300i64;
    let mut level: Vec<&str> = (0..n)
        .map(|i| ["info", "warn", "error"][(i % 3) as usize])
        .collect();
    if mutate {
        level[7] = "error";
    }
    let service: Vec<String> = (0..n).map(|i| format!("svc-{}", i % 5)).collect();
    let status: Vec<i64> = (0..n)
        .map(|i| [200, 200, 404, 500][(i % 4) as usize])
        .collect();
    let latency: Vec<i64> = (0..n).map(|i| (i * 37) % 251).collect();
    let tenant: Vec<String> = (0..n).map(|i| format!("t{}", i % 2)).collect();
    let schema = Schema::new(vec![
        Field::new("level", DataType::Utf8, false),
        Field::new("service", DataType::Utf8, false),
        Field::new("status", DataType::Int64, false),
        Field::new("latency_ms", DataType::Int64, false),
        Field::new("tenant", DataType::Utf8, false),
    ]);
    RecordBatch::try_new(
        Arc::new(schema),
        vec![
            Arc::new(StringArray::from(level)),
            Arc::new(StringArray::from(service)),
            Arc::new(Int64Array::from(status)),
            Arc::new(Int64Array::from(latency)),
            Arc::new(StringArray::from(tenant)),
        ],
    )
    .unwrap()
}

/// What the published upstream v1.1.2 binary answered for the same fixture.
fn upstream(query: &str) -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/parity/upstream-v1.1.2.json"
    );
    let capture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    capture["sql"][query]["hits"].clone()
}

fn filter_and_not(table: &LaneTable) -> usize {
    let filter = o2_substrate::Filter::and(vec![
        table.eq_text("level", "error").unwrap(),
        table.ne_int("status", 200).unwrap(),
        table.eq_text("tenant", "t1").unwrap(),
    ]);
    table.count(filter).unwrap()
}

#[test]
fn lane_answers_equal_the_upstream_capture() {
    let table = LaneTable::from_batch(&fixture(false)).unwrap();

    assert_eq!(
        table.count(table.all()).unwrap() as u64,
        upstream("count_all")[0]["c"]
    );
    assert_eq!(
        filter_and_not(&table) as u64,
        upstream("filter_and_not")[0]["c"]
    );

    let sums = upstream("sum_min_max");
    assert_eq!(table.sum(table.all(), "latency_ms").unwrap(), sums[0]["s"]);
    assert_eq!(
        table.min(table.all(), "latency_ms").unwrap().unwrap() as i64,
        sums[0]["mn"]
    );
    assert_eq!(
        table.max(table.all(), "latency_ms").unwrap().unwrap() as i64,
        sums[0]["mx"]
    );

    let mut by_level = table.count_by_text("level").unwrap();
    by_level.sort();
    let want: Vec<(String, usize)> = upstream("count_by_level")
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            (
                h["level"].as_str().unwrap().to_string(),
                h["c"].as_u64().unwrap() as usize,
            )
        })
        .collect();
    assert_eq!(by_level, want);

    let services = table.count_by_text("service").unwrap().len() as u64;
    assert_eq!(services, upstream("distinct_service")[0]["c"]);
}

#[test]
fn a_changed_row_changes_the_lane_answers() {
    let table = LaneTable::from_batch(&fixture(true)).unwrap();
    assert_ne!(
        filter_and_not(&table) as u64,
        upstream("filter_and_not")[0]["c"].as_u64().unwrap()
    );
    let errors = table
        .count(table.eq_text("level", "error").unwrap())
        .unwrap();
    assert_eq!(errors, 101);
}

/// The fixture splits 200 / not-200 evenly, so only an uneven value tells `!=` from `==`.
#[test]
fn not_equal_is_not_equal() {
    let table = LaneTable::from_batch(&fixture(false)).unwrap();
    assert_eq!(
        table.count(table.ne_int("status", 404).unwrap()).unwrap(),
        225
    );
}

#[test]
fn a_text_the_column_never_held_counts_zero() {
    let table = LaneTable::from_batch(&fixture(false)).unwrap();
    assert_eq!(
        table
            .count(table.eq_text("level", "fatal").unwrap())
            .unwrap(),
        0
    );
}

#[test]
fn what_has_no_lane_is_refused() {
    let floats = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Float64,
            false,
        )])),
        vec![Arc::new(Float64Array::from(vec![1.5]))],
    )
    .unwrap();
    assert_eq!(
        LaneTable::from_batch(&floats).err(),
        Some(Refusal::Type("value".to_string(), DataType::Float64))
    );

    let wide = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)])),
        vec![Arc::new(Int64Array::from(vec![i64::from(i32::MAX) + 1]))],
    )
    .unwrap();
    assert_eq!(
        LaneTable::from_batch(&wide).err(),
        Some(Refusal::Range("n".to_string(), i64::from(i32::MAX) + 1))
    );

    let table = LaneTable::from_batch(&fixture(false)).unwrap();
    assert_eq!(
        table.eq_text("status", "200").err(),
        Some(Refusal::Kind("status".to_string()))
    );
    assert_eq!(
        table.sum(table.all(), "nope").err(),
        Some(Refusal::Column("nope".to_string()))
    );
}
