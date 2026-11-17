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
    array::{ArrayRef, Int64Array, RecordBatch, StringArray},
    datatypes::{Field, Schema},
};
use o2_substrate::{Refusal, Scope, StreamSource};

const CLASS: u32 = 0x0C1D_0001;
const READER: Scope = Scope { id: 1 };

fn batch(columns: Vec<(&str, ArrayRef)>) -> RecordBatch {
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

fn texts(v: &[Option<&str>]) -> ArrayRef {
    Arc::new(StringArray::from(v.to_vec()))
}

fn ints(v: &[Option<i64>]) -> ArrayRef {
    Arc::new(Int64Array::from(v.to_vec()))
}

#[test]
fn rows_appended_in_two_batches_answer_as_one() {
    let first = batch(vec![
        ("level", texts(&[Some("info"), Some("error"), Some("info")])),
        ("n", ints(&[Some(1), Some(2), Some(3)])),
    ]);
    let second = batch(vec![
        ("level", texts(&[Some("error"), Some("warn")])),
        ("n", ints(&[Some(10), Some(20)])),
    ]);
    let mut source = StreamSource::new(CLASS, READER);
    source.append(&first).unwrap();
    source.append(&second).unwrap();
    let r = source.reader().unwrap();
    assert_eq!(r.count(r.all()).unwrap(), 5);
    assert_eq!(r.count(r.eq_text("level", "error").unwrap()).unwrap(), 2);
    assert_eq!(r.sum(r.all(), "n").unwrap(), 36);
    assert_eq!(
        r.count_by_text("level").unwrap(),
        vec![
            ("info".to_string(), 2),
            ("error".to_string(), 2),
            ("warn".to_string(), 1),
        ]
    );
}

/// An absent cell reads value 0; only its presence bit tells it from a real 0.
#[test]
fn an_absent_cell_is_not_a_zero() {
    let first = batch(vec![("n", ints(&[Some(0), None, Some(5)]))]);
    let second = batch(vec![("level", texts(&[Some("info"), None]))]);
    let mut source = StreamSource::new(CLASS, READER);
    source.append(&first).unwrap();
    source.append(&second).unwrap();
    let r = source.reader().unwrap();
    assert_eq!(r.rows(), 5);
    // Rows 1, 3 and 4 hold no `n`; only row 0 holds a real 0.
    assert_eq!(r.count(r.eq_int("n", 0).unwrap()).unwrap(), 1);
    assert_eq!(r.count(r.ne_int("n", 0).unwrap()).unwrap(), 1);
    assert_eq!(r.min(r.all(), "n").unwrap(), Some(0));
    assert_eq!(r.avg(r.all(), "n").unwrap(), Some(2.5));
    // Rows 0..3 hold no `level`, so none of them is the text coded 0.
    assert_eq!(
        r.count_by_text("level").unwrap(),
        vec![("info".to_string(), 1)]
    );
}

#[test]
fn a_batch_with_a_changed_kind_changes_nothing() {
    let mut source = StreamSource::new(CLASS, READER);
    source
        .append(&batch(vec![("n", ints(&[Some(1)]))]))
        .unwrap();
    let changed = batch(vec![("m", ints(&[Some(7)])), ("n", texts(&[Some("one")]))]);
    assert_eq!(
        source.append(&changed).err(),
        Some(Refusal::Kind("n".to_string()))
    );
    let r = source.reader().unwrap();
    assert_eq!(r.rows(), 1);
    assert_eq!(
        r.sum(r.all(), "m").err(),
        Some(Refusal::Column("m".to_string()))
    );
}

/// A field the reader binds is resolved by its name, so a later field never shifts it.
#[test]
fn a_field_added_later_keeps_earlier_fields_in_place() {
    let mut source = StreamSource::new(CLASS, READER);
    source
        .append(&batch(vec![("n", ints(&[Some(4)]))]))
        .unwrap();
    source
        .append(&batch(vec![
            ("level", texts(&[Some("warn")])),
            ("n", ints(&[Some(6)])),
        ]))
        .unwrap();
    let r = source.reader().unwrap();
    assert_eq!(r.sum(r.all(), "n").unwrap(), 10);
    assert_eq!(r.count(r.eq_text("level", "warn").unwrap()).unwrap(), 1);
}
