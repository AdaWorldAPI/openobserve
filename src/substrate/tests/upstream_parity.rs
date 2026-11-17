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
use o2_substrate::{Filter, LaneTable, Refusal, TIMESTAMP};
use serde_json::Value;

/// A minute boundary, as the fixture's base is; captured times are relative to it.
const BASE_US: i64 = 1_800_000_000_000_000;

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
    let time: Vec<i64> = (0..n).map(|i| BASE_US + i * 1_000_000).collect();
    let schema = Schema::new(vec![
        Field::new(TIMESTAMP, DataType::Int64, false),
        Field::new("level", DataType::Utf8, false),
        Field::new("service", DataType::Utf8, false),
        Field::new("status", DataType::Int64, false),
        Field::new("latency_ms", DataType::Int64, false),
        Field::new("tenant", DataType::Utf8, false),
    ]);
    RecordBatch::try_new(
        Arc::new(schema),
        vec![
            Arc::new(Int64Array::from(time)),
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
    let filter = Filter::and(vec![
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

#[test]
fn time_buckets_and_grouped_answers_equal_the_upstream_capture() {
    let table = LaneTable::from_batch(&fixture(false)).unwrap();

    let buckets: Vec<(i64, u64)> = table
        .count_by_time(60_000_000)
        .unwrap()
        .into_iter()
        .map(|(start, rows)| (start - BASE_US, rows as u64))
        .collect();
    let want: Vec<(i64, u64)> = upstream("histogram_1m")
        .as_array()
        .unwrap()
        .iter()
        .map(|h| (h["t"]["rel_us"].as_i64().unwrap(), h["c"].as_u64().unwrap()))
        .collect();
    assert_eq!(buckets, want);

    for hit in upstream("avg_by_tenant").as_array().unwrap() {
        let tenant = table
            .eq_text("tenant", hit["tenant"].as_str().unwrap())
            .unwrap();
        let avg = table.avg(tenant, "latency_ms").unwrap().unwrap();
        assert_eq!((avg * 1e6).round() / 1e6, hit["a"].as_f64().unwrap());
    }

    let pairs = upstream("group_two_keys");
    let mut rows = 0;
    for hit in pairs.as_array().unwrap() {
        let filter = Filter::and(vec![
            table
                .eq_text("service", hit["service"].as_str().unwrap())
                .unwrap(),
            table
                .eq_int("status", hit["status"].as_i64().unwrap() as i32)
                .unwrap(),
        ]);
        let got = table.count(filter).unwrap() as u64;
        assert_eq!(got, hit["c"].as_u64().unwrap());
        rows += got;
    }
    assert_eq!(rows, 300, "the upstream groups cover every row");
}

fn times(values: Vec<i64>) -> RecordBatch {
    RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            TIMESTAMP,
            DataType::Int64,
            false,
        )])),
        vec![Arc::new(Int64Array::from(values))],
    )
    .unwrap()
}

#[test]
fn a_time_the_lanes_cannot_hold_is_refused() {
    let far = BASE_US + (i64::from(i32::MAX) + 1) * 1_000;
    assert_eq!(
        LaneTable::from_batch(&times(vec![BASE_US, far])).err(),
        Some(Refusal::Precision(TIMESTAMP.to_string(), far))
    );
    let table = LaneTable::from_batch(&times(vec![BASE_US])).unwrap();
    assert_eq!(
        table.count_by_time(0).err(),
        Some(Refusal::Precision(TIMESTAMP.to_string(), 0))
    );
}

/// Microsecond times are kept exactly: a range bound one microsecond off moves one row.
#[test]
fn event_time_is_exact_to_the_microsecond() {
    let at = |ms: i64, us: i64| BASE_US + ms * 1_000 + us;
    let table = LaneTable::from_batch(&times(vec![
        at(0, 0),
        at(0, 999),
        at(1, 0),
        at(1, 1),
        at(7, 500),
    ]))
    .unwrap();
    let count = |start, end| table.count(table.time_range(start, end).unwrap()).unwrap();

    assert_eq!(count(at(0, 0), at(1, 0)), 2);
    assert_eq!(count(at(0, 1), at(1, 0)), 1);
    assert_eq!(count(at(0, 0), at(1, 1)), 3);
    assert_eq!(count(at(1, 1), at(1, 2)), 1);
    assert_eq!(count(i64::MIN / 2, i64::MAX / 2), 5);
    assert_eq!(count(at(8, 0), i64::MAX / 2), 0);
    assert_eq!(
        table.count_by_time(1_000).unwrap(),
        vec![(at(0, 0), 2), (at(1, 0), 2), (at(7, 0), 1)]
    );
    assert_eq!(table.count_by_time(500).unwrap().len(), 4);
}

/// SQL three-valued logic: a NULL operand matches neither a comparison nor its negation.
#[test]
fn null_is_neither_equal_nor_not_equal() {
    let batch = RecordBatch::try_new(
        Arc::new(Schema::new(vec![
            Field::new("level", DataType::Utf8, true),
            Field::new("status", DataType::Int64, true),
        ])),
        vec![
            Arc::new(StringArray::from(vec![
                Some("a"),
                None,
                Some("b"),
                Some("a"),
                None,
                Some("a"),
            ])),
            Arc::new(Int64Array::from(vec![
                Some(200),
                None,
                Some(404),
                None,
                Some(0),
                Some(200),
            ])),
        ],
    )
    .unwrap();
    let table = LaneTable::from_batch(&batch).unwrap();
    let a = || table.eq_text("level", "a").unwrap();

    assert_eq!(table.count(table.all()).unwrap(), 6);
    assert_eq!(table.count(a()).unwrap(), 3);
    assert_eq!(table.count(Filter::negate(a())).unwrap(), 1);
    assert_eq!(table.count(table.eq_int("status", 0).unwrap()).unwrap(), 1);
    assert_eq!(
        table.count(table.ne_int("status", 200).unwrap()).unwrap(),
        2
    );
    assert_eq!(
        table.count_by_text("level").unwrap(),
        vec![("a".to_string(), 3), ("b".to_string(), 1)]
    );

    assert_eq!(table.sum(table.all(), "status").unwrap(), 804);
    assert_eq!(table.min(table.all(), "status").unwrap(), Some(0));
    assert_eq!(table.avg(table.all(), "status").unwrap(), Some(201.0));
    assert_eq!(table.avg(a(), "status").unwrap(), Some(200.0));
    assert_eq!(
        table
            .avg(table.eq_text("level", "none").unwrap(), "status")
            .unwrap(),
        None
    );

    let null_time = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            TIMESTAMP,
            DataType::Int64,
            true,
        )])),
        vec![Arc::new(Int64Array::from(vec![Some(BASE_US), None]))],
    )
    .unwrap();
    assert_eq!(
        LaneTable::from_batch(&null_time).err(),
        Some(Refusal::Null(TIMESTAMP.to_string()))
    );
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

/// One column more than a 16-bit lane id addresses would alias column 0.
#[test]
fn more_columns_than_lane_ids_are_refused() {
    let columns = u16::MAX as usize + 2;
    let fields: Vec<Field> = (0..columns)
        .map(|i| Field::new(format!("c{i}"), DataType::Int64, false))
        .collect();
    let arrays = (0..columns)
        .map(|_| Arc::new(Int64Array::from(Vec::<i64>::new())) as Arc<dyn arrow::array::Array>)
        .collect();
    let too_wide = RecordBatch::try_new(Arc::new(Schema::new(fields)), arrays).unwrap();
    assert_eq!(
        LaneTable::from_batch(&too_wide).err(),
        Some(Refusal::Columns(columns))
    );
}
