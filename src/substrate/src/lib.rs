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
    array::{Array, Int64Array, RecordBatch, StringArray},
    datatypes::DataType,
};
use lance_graph_dir_sim::snapshot::Dict;
use lance_graph_mask_risc::{LaneRef, Planes, Scratch, Value, execute, words_for};
pub use lance_graph_quack::Filter;
use lance_graph_quack::{Agg, Cmp, Col, Mask, Query, lower};

/// The plane holding one set bit per row of the table.
const LIVE: Mask = Mask(0);

/// One stream batch as coded lanes: text columns are dictionary codes, integers are `i32`.
pub struct LaneTable {
    rows: usize,
    names: Vec<String>,
    lanes: Vec<Lane>,
    live: Vec<u64>,
}

impl LaneTable {
    /// Refuses a column type or an integer that has no lane, never truncates it.
    pub fn from_batch(batch: &RecordBatch) -> Result<Self, Refusal> {
        let rows = batch.num_rows();
        let schema = batch.schema();
        let mut names = Vec::with_capacity(batch.num_columns());
        let mut lanes = Vec::with_capacity(batch.num_columns());
        for (field, column) in schema.fields().iter().zip(batch.columns()) {
            if column.null_count() != 0 {
                return Err(Refusal::Null(field.name().clone()));
            }
            let lane = match field.data_type() {
                DataType::Utf8 => text_lane(column),
                DataType::Int64 => int_lane(field.name(), column)?,
                other => return Err(Refusal::Type(field.name().clone(), other.clone())),
            };
            names.push(field.name().clone());
            lanes.push(lane);
        }
        let mut live = vec![u64::MAX; words_for(rows)];
        if let Some(last) = live.last_mut()
            && rows % 64 != 0
        {
            *last = (1u64 << (rows % 64)) - 1;
        }
        Ok(Self {
            rows,
            names,
            lanes,
            live,
        })
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// A text the column never held matches no row, so the term is empty, not an error.
    pub fn eq_text(&self, column: &str, text: &str) -> Result<Filter, Refusal> {
        let (col, dict) = self.text(column)?;
        Ok(match dict.get(text) {
            Some(code) => Filter::cmp(col, Cmp::EqU32(code)),
            None => Filter::negate(Filter::plane(LIVE)),
        })
    }

    pub fn ne_int(&self, column: &str, value: i32) -> Result<Filter, Refusal> {
        Ok(Filter::cmp(self.int(column)?, Cmp::NeI32(value)))
    }

    pub fn all(&self) -> Filter {
        Filter::plane(LIVE)
    }

    pub fn count(&self, filter: Filter) -> Result<usize, Refusal> {
        match self.run(filter, Agg::Count)? {
            Value::Count(n) => Ok(n),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    pub fn sum(&self, filter: Filter, column: &str) -> Result<i64, Refusal> {
        match self.run(filter, Agg::SumI32(self.int(column)?))? {
            Value::SumI64(n) => Ok(n),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    pub fn min(&self, filter: Filter, column: &str) -> Result<Option<i32>, Refusal> {
        self.extreme(filter, Agg::MinI32(self.int(column)?))
    }

    pub fn max(&self, filter: Filter, column: &str) -> Result<Option<i32>, Refusal> {
        self.extreme(filter, Agg::MaxI32(self.int(column)?))
    }

    /// Rows per distinct text of `column`, in the order the texts first appeared.
    pub fn count_by_text(&self, column: &str) -> Result<Vec<(String, usize)>, Refusal> {
        let (col, dict) = self.text(column)?;
        (0..dict.len() as u32)
            .map(|code| {
                let text = dict.resolve(code).unwrap_or_default().to_string();
                Ok((text, self.count(Filter::cmp(col, Cmp::EqU32(code)))?))
            })
            .collect()
    }

    fn extreme(&self, filter: Filter, agg: Agg) -> Result<Option<i32>, Refusal> {
        match self.run(filter, agg)? {
            Value::OptI32(v) => Ok(v),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    fn run(&self, filter: Filter, agg: Agg) -> Result<Value, Refusal> {
        let program =
            lower(&Query { filter, agg }).map_err(|e| Refusal::Lower(format!("{e:?}")))?;
        let lanes: Vec<LaneRef<'_>> = self.lanes.iter().map(Lane::borrow).collect();
        let masks: [&[u64]; 1] = [&self.live];
        let planes = Planes {
            n_rows: self.rows,
            masks: &masks,
            lanes: &lanes,
        };
        let mut scratch = Scratch::for_program(&program, self.rows)
            .map_err(|e| Refusal::Run(format!("{e:?}")))?;
        execute(&program, &planes, &mut scratch, None).map_err(|e| Refusal::Run(format!("{e:?}")))
    }

    fn position(&self, column: &str) -> Result<usize, Refusal> {
        self.names
            .iter()
            .position(|n| n == column)
            .ok_or_else(|| Refusal::Column(column.to_string()))
    }

    fn text(&self, column: &str) -> Result<(Col, &Dict), Refusal> {
        let i = self.position(column)?;
        match &self.lanes[i] {
            Lane::Text { dict, .. } => Ok((Col(i as u16), dict)),
            Lane::Int(_) => Err(Refusal::Kind(column.to_string())),
        }
    }

    fn int(&self, column: &str) -> Result<Col, Refusal> {
        let i = self.position(column)?;
        match &self.lanes[i] {
            Lane::Int(_) => Ok(Col(i as u16)),
            Lane::Text { .. } => Err(Refusal::Kind(column.to_string())),
        }
    }
}

enum Lane {
    Text { codes: Vec<u32>, dict: Dict },
    Int(Vec<i32>),
}

impl Lane {
    fn borrow(&self) -> LaneRef<'_> {
        match self {
            Lane::Text { codes, .. } => LaneRef::U32(codes),
            Lane::Int(values) => LaneRef::I32(values),
        }
    }
}

/// Why a batch or a question has no answer on lanes.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    Type(String, DataType),
    Null(String),
    Range(String, i64),
    Column(String),
    Kind(String),
    Lower(String),
    Run(String),
    Answer(String),
}

fn text_lane(column: &Arc<dyn Array>) -> Lane {
    let texts = column
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("Utf8 column is a StringArray");
    let mut dict = Dict::default();
    let codes = texts.iter().flatten().map(|t| dict.intern(t)).collect();
    Lane::Text { codes, dict }
}

fn int_lane(name: &str, column: &Arc<dyn Array>) -> Result<Lane, Refusal> {
    let ints = column
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Int64 column is an Int64Array");
    ints.values()
        .iter()
        .map(|&v| i32::try_from(v).map_err(|_| Refusal::Range(name.to_string(), v)))
        .collect::<Result<Vec<i32>, Refusal>>()
        .map(Lane::Int)
}
