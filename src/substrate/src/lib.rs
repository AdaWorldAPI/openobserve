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

mod store;

use std::sync::Arc;

use arrow::{
    array::{Array, Int64Array, RecordBatch, StringArray},
    datatypes::DataType,
};
use lance_graph_dir_sim::snapshot::Dict;
use lance_graph_mask_risc::{LaneRef, Planes, Scratch, Value, execute, words_for};
pub use lance_graph_quack::Filter;
use lance_graph_quack::{Agg, Cmp, Col, Mask, Query, lower};
pub use store::{ShadowStats, StreamKey, append, fold, stats};

/// The plane holding one set bit per row of the table.
const LIVE: Mask = Mask(0);
/// OpenObserve's event-time column, microseconds since the epoch.
pub const TIMESTAMP: &str = "_timestamp";
const US_PER_MS: i64 = 1_000;
/// Lanes and planes are addressed by 16-bit ids.
const MAX_IDS: usize = u16::MAX as usize + 1;

/// One stream batch as coded lanes: text columns are dictionary codes, integers are `i32`.
pub struct LaneTable {
    rows: usize,
    columns: Vec<Column>,
    lanes: Vec<Lane>,
    /// Plane 0 is the live plane; a nullable column's validity plane follows.
    planes: Vec<Vec<u64>>,
    nullable: Vec<(Col, Mask)>,
}

impl LaneTable {
    /// Refuses a column type or a value that has no lane, never truncates it.
    pub fn from_batch(batch: &RecordBatch) -> Result<Self, Refusal> {
        let (table, skipped) = Self::admit(batch)?;
        match skipped.into_iter().next() {
            Some(refusal) => Err(refusal),
            None => Ok(table),
        }
    }

    /// The batch without the columns that have no lane; those are named in the second value.
    /// An event time with no lane refuses the whole batch.
    pub fn admit(batch: &RecordBatch) -> Result<(Self, Vec<Refusal>), Refusal> {
        let rows = batch.num_rows();
        let mut skipped = Vec::new();
        let mut table = Self {
            rows,
            columns: Vec::with_capacity(batch.num_columns()),
            lanes: Vec::with_capacity(batch.num_columns()),
            planes: vec![ones(rows)],
            nullable: Vec::new(),
        };
        for (field, column) in batch.schema().fields().iter().zip(batch.columns()) {
            let name = field.name();
            let kind = match field.data_type() {
                DataType::Utf8 => table.push_text(column),
                DataType::Int64 if name == TIMESTAMP => table.push_time(column)?,
                DataType::Int64 => match table.push_int(name, column) {
                    Ok(kind) => kind,
                    Err(refusal) => {
                        skipped.push(refusal);
                        continue;
                    }
                },
                other => {
                    skipped.push(Refusal::Type(name.clone(), other.clone()));
                    continue;
                }
            };
            if column.null_count() != 0 {
                table.push_validity(name, &kind, column)?;
            }
            table.columns.push(Column {
                name: name.clone(),
                kind,
            });
            if table.lanes.len() > MAX_IDS || table.planes.len() > MAX_IDS {
                return Err(Refusal::Columns(batch.num_columns()));
            }
        }
        Ok((table, skipped))
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn all(&self) -> Filter {
        Filter::plane(LIVE)
    }

    /// A text the column never held matches no row, so the term is empty, not an error.
    pub fn eq_text(&self, column: &str, text: &str) -> Result<Filter, Refusal> {
        let (col, dict) = self.text(column)?;
        Ok(match dict.get(text) {
            Some(code) => Filter::cmp(col, Cmp::EqU32(code)),
            None => Filter::negate(Filter::plane(LIVE)),
        })
    }

    pub fn eq_int(&self, column: &str, value: i32) -> Result<Filter, Refusal> {
        Ok(Filter::cmp(self.int(column)?, Cmp::EqI32(value)))
    }

    pub fn ne_int(&self, column: &str, value: i32) -> Result<Filter, Refusal> {
        Ok(Filter::cmp(self.int(column)?, Cmp::NeI32(value)))
    }

    /// Event time in `[start_us, end_us)`.
    pub fn time_range(&self, start_us: i64, end_us: i64) -> Result<Filter, Refusal> {
        let time = self.time()?;
        Ok(Filter::and([
            time.at_or_after(start_us),
            Filter::negate(time.at_or_after(end_us)),
        ]))
    }

    /// Rows the filter holds for under SQL three-valued logic: a NULL operand is not a match.
    pub fn count(&self, filter: Filter) -> Result<usize, Refusal> {
        match self.run(filter, Agg::Count)? {
            Value::Count(n) => Ok(n),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    pub fn sum(&self, filter: Filter, column: &str) -> Result<i64, Refusal> {
        let col = self.int(column)?;
        match self.run(self.where_present(filter, col), Agg::SumI32(col))? {
            Value::SumI64(n) => Ok(n),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    pub fn min(&self, filter: Filter, column: &str) -> Result<Option<i32>, Refusal> {
        let col = self.int(column)?;
        self.extreme(self.where_present(filter, col), Agg::MinI32(col))
    }

    pub fn max(&self, filter: Filter, column: &str) -> Result<Option<i32>, Refusal> {
        let col = self.int(column)?;
        self.extreme(self.where_present(filter, col), Agg::MaxI32(col))
    }

    /// `None` when no row with a value passes, as SQL `AVG` over no values is NULL.
    pub fn avg(&self, filter: Filter, column: &str) -> Result<Option<f64>, Refusal> {
        let col = self.int(column)?;
        let rows = self.count(self.where_present(filter.clone(), col))?;
        if rows == 0 {
            return Ok(None);
        }
        Ok(Some(self.sum(filter, column)? as f64 / rows as f64))
    }

    /// Rows per distinct text of `column`, in the order the texts first appeared; NULL has none.
    pub fn count_by_text(&self, column: &str) -> Result<Vec<(String, usize)>, Refusal> {
        let (col, dict) = self.text(column)?;
        (0..dict.len() as u32)
            .map(|code| {
                let text = dict.resolve(code).unwrap_or_default().to_string();
                Ok((text, self.count(Filter::cmp(col, Cmp::EqU32(code)))?))
            })
            .collect()
    }

    /// Rows per `width_us` bucket of event time, as `(bucket start, rows)`; empty buckets are
    /// left out, and buckets align to the epoch as SQL `histogram` does.
    pub fn count_by_time(&self, width_us: i64) -> Result<Vec<(i64, usize)>, Refusal> {
        if width_us <= 0 {
            return Err(Refusal::Precision(TIMESTAMP.to_string(), width_us));
        }
        let time = self.time()?;
        let Some(end_us) = time.last_us(&self.lanes) else {
            return Ok(Vec::new());
        };
        let mut start_us = time.base_us.div_euclid(width_us) * width_us;
        let mut buckets = Vec::new();
        while start_us <= end_us {
            let rows = self.count(self.time_range(start_us, start_us + width_us)?)?;
            if rows != 0 {
                buckets.push((start_us, rows));
            }
            start_us += width_us;
        }
        Ok(buckets)
    }

    fn push_text(&mut self, column: &Arc<dyn Array>) -> Kind {
        let texts = column
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("Utf8 column is a StringArray");
        let mut dict = Dict::default();
        let codes = texts
            .iter()
            .map(|text| text.map_or(0, |t| dict.intern(t)))
            .collect();
        self.lanes.push(Lane::U32(codes));
        Kind::Text {
            lane: self.lanes.len() - 1,
            dict,
        }
    }

    fn push_int(&mut self, name: &str, column: &Arc<dyn Array>) -> Result<Kind, Refusal> {
        let ints = int64(column);
        let values = (0..ints.len())
            .map(|row| {
                if ints.is_null(row) {
                    return Ok(0);
                }
                let v = ints.value(row);
                i32::try_from(v).map_err(|_| Refusal::Range(name.to_string(), v))
            })
            .collect::<Result<Vec<i32>, Refusal>>()?;
        self.lanes.push(Lane::I32(values));
        Ok(Kind::Int {
            lane: self.lanes.len() - 1,
        })
    }

    fn push_time(&mut self, column: &Arc<dyn Array>) -> Result<Kind, Refusal> {
        let times = int64(column);
        if times.null_count() != 0 {
            return Err(Refusal::Null(TIMESTAMP.to_string()));
        }
        let base_us = times.values().iter().copied().min().unwrap_or(0);
        let mut whole_ms = Vec::with_capacity(times.len());
        let mut rest_us = Vec::with_capacity(times.len());
        for &us in times.values() {
            let offset = us - base_us;
            let ms = i32::try_from(offset / US_PER_MS)
                .map_err(|_| Refusal::Precision(TIMESTAMP.to_string(), us))?;
            whole_ms.push(ms);
            rest_us.push((offset % US_PER_MS) as i32);
        }
        self.lanes.push(Lane::I32(whole_ms));
        self.lanes.push(Lane::I32(rest_us));
        Ok(Kind::Time(TimeLanes {
            whole_ms: self.lanes.len() - 2,
            rest_us: self.lanes.len() - 1,
            base_us,
        }))
    }

    fn push_validity(
        &mut self,
        name: &str,
        kind: &Kind,
        column: &Arc<dyn Array>,
    ) -> Result<(), Refusal> {
        let lane = match kind {
            Kind::Text { lane, .. } | Kind::Int { lane } => *lane,
            Kind::Time(_) => return Err(Refusal::Null(name.to_string())),
        };
        let mut valid = vec![0u64; words_for(self.rows)];
        for row in (0..self.rows).filter(|&row| column.is_valid(row)) {
            valid[row / 64] |= 1 << (row % 64);
        }
        self.planes.push(valid);
        self.nullable
            .push((Col(lane as u16), Mask((self.planes.len() - 1) as u16)));
        Ok(())
    }

    /// `filter` narrowed to the rows where `col` holds a value, as SQL aggregates skip NULL.
    fn where_present(&self, filter: Filter, col: Col) -> Filter {
        match self.nullable.iter().find(|(c, _)| *c == col) {
            Some((_, valid)) => Filter::and([filter, Filter::is_not_null(*valid)]),
            None => filter,
        }
    }

    fn extreme(&self, filter: Filter, agg: Agg) -> Result<Option<i32>, Refusal> {
        match self.run(filter, agg)? {
            Value::OptI32(v) => Ok(v),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    fn run(&self, filter: Filter, agg: Agg) -> Result<Value, Refusal> {
        let filter = filter.sql_where(&self.nullable);
        let program =
            lower(&Query { filter, agg }).map_err(|e| Refusal::Lower(format!("{e:?}")))?;
        let lanes: Vec<LaneRef<'_>> = self.lanes.iter().map(Lane::borrow).collect();
        let masks: Vec<&[u64]> = self.planes.iter().map(Vec::as_slice).collect();
        let planes = Planes {
            n_rows: self.rows,
            masks: &masks,
            lanes: &lanes,
        };
        let mut scratch = Scratch::for_program(&program, self.rows)
            .map_err(|e| Refusal::Run(format!("{e:?}")))?;
        execute(&program, &planes, &mut scratch, None).map_err(|e| Refusal::Run(format!("{e:?}")))
    }

    fn column(&self, name: &str) -> Result<&Kind, Refusal> {
        self.columns
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.kind)
            .ok_or_else(|| Refusal::Column(name.to_string()))
    }

    fn text(&self, column: &str) -> Result<(Col, &Dict), Refusal> {
        match self.column(column)? {
            Kind::Text { lane, dict } => Ok((Col(*lane as u16), dict)),
            _ => Err(Refusal::Kind(column.to_string())),
        }
    }

    fn int(&self, column: &str) -> Result<Col, Refusal> {
        match self.column(column)? {
            Kind::Int { lane } => Ok(Col(*lane as u16)),
            _ => Err(Refusal::Kind(column.to_string())),
        }
    }

    fn time(&self) -> Result<&TimeLanes, Refusal> {
        match self.column(TIMESTAMP)? {
            Kind::Time(time) => Ok(time),
            _ => Err(Refusal::Kind(TIMESTAMP.to_string())),
        }
    }
}

struct Column {
    name: String,
    kind: Kind,
}

enum Kind {
    Text { lane: usize, dict: Dict },
    Int { lane: usize },
    Time(TimeLanes),
}

/// Event time split so each part fits a signed 32-bit lane: whole milliseconds after
/// `base_us`, and the microseconds left over (0..1000).
struct TimeLanes {
    whole_ms: usize,
    rest_us: usize,
    base_us: i64,
}

impl TimeLanes {
    fn at_or_after(&self, us: i64) -> Filter {
        let offset = us - self.base_us;
        let Ok(ms) = i32::try_from(offset.div_euclid(US_PER_MS)) else {
            return if offset < 0 {
                Filter::plane(LIVE)
            } else {
                Filter::negate(Filter::plane(LIVE))
            };
        };
        let rest = offset.rem_euclid(US_PER_MS) as i32;
        let whole = Col(self.whole_ms as u16);
        Filter::or([
            Filter::cmp(whole, Cmp::GtI32(ms)),
            Filter::and([
                Filter::cmp(whole, Cmp::EqI32(ms)),
                Filter::cmp(Col(self.rest_us as u16), Cmp::GeI32(rest)),
            ]),
        ])
    }

    fn last_us(&self, lanes: &[Lane]) -> Option<i64> {
        let (Lane::I32(whole), Lane::I32(rest)) = (&lanes[self.whole_ms], &lanes[self.rest_us])
        else {
            return None;
        };
        whole
            .iter()
            .zip(rest)
            .map(|(&ms, &us)| self.base_us + i64::from(ms) * US_PER_MS + i64::from(us))
            .max()
    }
}

enum Lane {
    U32(Vec<u32>),
    I32(Vec<i32>),
}

impl Lane {
    fn borrow(&self) -> LaneRef<'_> {
        match self {
            Lane::U32(values) => LaneRef::U32(values),
            Lane::I32(values) => LaneRef::I32(values),
        }
    }
}

/// Why a batch or a question has no answer on lanes.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    Type(String, DataType),
    /// A NULL where the lane has no validity plane: event time.
    Null(String),
    Range(String, i64),
    /// A time span or bucket width the lanes cannot hold.
    Precision(String, i64),
    Column(String),
    /// More lanes or planes than a 16-bit id addresses.
    Columns(usize),
    Kind(String),
    Lower(String),
    Run(String),
    Answer(String),
}

fn int64(column: &Arc<dyn Array>) -> &Int64Array {
    column
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Int64 column is an Int64Array")
}

fn ones(rows: usize) -> Vec<u64> {
    let mut plane = vec![u64::MAX; words_for(rows)];
    if let Some(last) = plane.last_mut()
        && rows % 64 != 0
    {
        *last = (1u64 << (rows % 64)) - 1;
    }
    plane
}
