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
use o2_substrate::{Refusal, ShadowStats, StreamKey, TIMESTAMP, append, fold, stats};

const BASE_US: i64 = 1_800_000_000_000_000;

fn batch(start: i64, levels: &[&str]) -> RecordBatch {
    let n = levels.len() as i64;
    RecordBatch::try_new(
        Arc::new(Schema::new(vec![
            Field::new(TIMESTAMP, DataType::Int64, false),
            Field::new("level", DataType::Utf8, false),
            Field::new("ratio", DataType::Float64, false),
        ])),
        vec![
            Arc::new(Int64Array::from(
                (0..n).map(|i| BASE_US + start + i).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(levels.to_vec())),
            Arc::new(Float64Array::from(vec![0.5; levels.len()])),
        ],
    )
    .unwrap()
}

fn errors(key: &StreamKey) -> usize {
    fold(key, 0, |acc, table| {
        Ok(acc + table.count(table.eq_text("level", "error")?)?)
    })
    .unwrap()
}

/// Each batch has its own dictionary, so the same text has different codes in the two tables.
#[test]
fn answers_fold_over_the_batches_of_one_stream() {
    let key = StreamKey::new("org", "logs", "fold");
    assert_eq!(append(&key, &batch(0, &["info", "error", "error"])), None);
    assert_eq!(
        append(&key, &batch(10, &["error", "warn", "info", "info"])),
        None
    );

    assert_eq!(errors(&key), 3);
    assert_eq!(
        fold(&key, 0, |acc, t| Ok(acc + t.count(t.all())?)).unwrap(),
        7
    );
    assert_eq!(
        stats(&key),
        ShadowStats {
            tables: 2,
            rows: 7,
            skipped_columns: 2,
            ..ShadowStats::default()
        }
    );
    assert_eq!(errors(&StreamKey::new("org", "logs", "other")), 0);
    assert_eq!(errors(&StreamKey::new("other", "logs", "fold")), 0);
}

#[test]
fn a_skipped_column_is_absent_and_a_batch_with_no_time_lane_is_counted() {
    let key = StreamKey::new("org", "logs", "refusals");
    assert_eq!(append(&key, &batch(0, &["info"])), None);
    let asked = fold(&key, 0i64, |acc, t| Ok(acc + t.sum(t.all(), "ratio")?));
    assert_eq!(asked, Err(Refusal::Column("ratio".to_string())));

    let far = (i64::from(i32::MAX) + 1) * 1_000;
    let wide = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new(
            TIMESTAMP,
            DataType::Int64,
            false,
        )])),
        vec![Arc::new(Int64Array::from(vec![BASE_US, BASE_US + far]))],
    )
    .unwrap();
    assert_eq!(
        append(&key, &wide),
        Some(Refusal::Precision(TIMESTAMP.to_string(), BASE_US + far))
    );
    let got = stats(&key);
    assert_eq!((got.tables, got.rows), (1, 1));
    assert_eq!((got.refused_batches, got.refused_rows), (1, 2));
}

#[test]
fn a_stream_keeps_its_newest_rows_under_the_bound() {
    let key = StreamKey::new("org", "logs", "bound");
    let levels = vec!["info"; 400_000];
    for i in 0..3 {
        assert_eq!(append(&key, &batch(i * 400_000, &levels)), None);
    }
    let got = stats(&key);
    assert_eq!(
        (got.tables, got.rows, got.evicted_rows),
        (2, 800_000, 400_000)
    );
    assert_eq!(
        fold(&key, 0, |acc, t| Ok(acc + t.count(t.all())?)).unwrap(),
        800_000
    );
}
