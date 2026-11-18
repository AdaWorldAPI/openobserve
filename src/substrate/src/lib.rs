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

mod source;

use lance_graph_contract::class_view::WideFieldMask;
pub use lance_graph_dt64::dr::Scope;
use lance_graph_dt64::{
    BindStore, ClassSchema, Extent, LaneRequest, LaneSource, RouteAt,
    dr::{Frame, TileMap, ValueKey},
};
use lance_graph_mask_risc::{Foreign, LaneRef, Out, Planes, Scratch, Value, execute, execute_into};
pub use lance_graph_quack::Filter;
use lance_graph_quack::{
    Agg, Cmp, Col, GroupAddr, GroupAgg, Mask, Query, lower, normalize_group_sink,
};
pub use source::{STREAM_REV, StreamSource, StreamView};

use crate::source::Values;

/// The plane holding one set bit per row of the stream.
const LIVE: Mask = Mask(0);
/// OpenObserve's event-time column, microseconds since the epoch.
pub const TIMESTAMP: &str = "_timestamp";
const US_PER_MS: i64 = 1_000;
/// A code no text is ever given: codes count up from 0 and a field's key set stays below this.
const NO_CODE: u32 = u32::MAX;
/// The route position a stream's class is bound at in a reader's own store.
const POSITION: u16 = 0;

/// Questions over one sealed frame of a stream, answered by folds over its borrowed lanes.
pub struct Reader<'s> {
    source: &'s StreamSource,
    frame: Frame,
    lanes: Vec<LaneRef<'s>>,
    /// `LIVE`, then field `i`'s presence plane at `i + 1`.
    masks: Vec<&'s [u64]>,
    nullable: Vec<(Col, Mask)>,
}

impl StreamSource {
    /// Binds every field through DT64 once; the lanes are borrowed, never copied.
    pub fn reader(&self) -> Result<Reader<'_>, Refusal> {
        let view = self.basis();
        let mut store = BindStore::new();
        let schema = ClassSchema {
            schema_rev: STREAM_REV,
            field_count: view.len(),
            extent: Extent::DR64_CUBE,
        };
        store
            .register(&view, self.class(), schema, Vec::new())
            .map_err(|e| Refusal::Bind(format!("{e:?}")))?;
        let version = store
            .route(POSITION, self.class())
            .map_err(|e| Refusal::Bind(format!("{e:?}")))?;
        let frame = LaneSource::frames(self).seal();
        let positions: Vec<u8> = (0..view.len()).map(|i| i as u8).collect();
        let fields = WideFieldMask::from_positions(&positions);
        let request = LaneRequest {
            route: RouteAt {
                position: POSITION,
                version,
            },
            rev: STREAM_REV,
            fields: &fields,
            frame: &frame,
            scope: self.scope(),
            selection: self.space(),
        };
        let binding = store
            .bind_lanes(&view, LaneSource::frames(self), self, request)
            .map_err(|e| Refusal::Bind(format!("{e:?}")))?;
        let mut lanes = Vec::with_capacity(view.len());
        let mut masks = vec![self.live()];
        for item in binding
            .borrow_all_present(&store, &view, LaneSource::frames(self), self)
            .map_err(|e| Refusal::Bind(format!("{e:?}")))?
        {
            let (_, lane, presence) = item.map_err(|e| Refusal::Bind(format!("{e:?}")))?;
            lanes.push(lane);
            masks.push(presence);
        }
        let nullable = (0..lanes.len() as u16)
            .map(|i| (Col(i), Mask(i + 1)))
            .collect();
        Ok(Reader {
            source: self,
            frame,
            lanes,
            masks,
            nullable,
        })
    }
}

impl Reader<'_> {
    pub fn rows(&self) -> usize {
        self.source.rows()
    }

    /// A text the column never held compares against a code no row holds, so the term still
    /// reads the column and an absent cell stays UNKNOWN under `NOT`.
    pub fn eq_text(&self, column: &str, text: &str) -> Result<Filter, Refusal> {
        let col = self.text(column)?;
        let code = self
            .source
            .code(&self.frame, column, text)
            .unwrap_or(NO_CODE);
        Ok(Filter::cmp(col, Cmp::EqU32(code)))
    }

    pub fn eq_int(&self, column: &str, value: i32) -> Result<Filter, Refusal> {
        Ok(Filter::cmp(self.int(column)?, Cmp::EqI32(value)))
    }

    pub fn ne_int(&self, column: &str, value: i32) -> Result<Filter, Refusal> {
        Ok(Filter::cmp(self.int(column)?, Cmp::NeI32(value)))
    }

    pub fn all(&self) -> Filter {
        Filter::plane(LIVE)
    }

    /// Rows for which `filter`, read as SQL over the absent cells, is TRUE.
    pub fn count(&self, filter: Filter) -> Result<usize, Refusal> {
        match self.run(filter, Agg::Count)? {
            Value::Count(n) => Ok(n),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    /// Absent cells of `column` are skipped, as SQL aggregates skip NULL.
    pub fn sum(&self, filter: Filter, column: &str) -> Result<i64, Refusal> {
        let col = self.int(column)?;
        match self.run(self.present(filter, col), Agg::SumI32(col))? {
            Value::SumI64(n) => Ok(n),
            other => Err(Refusal::Answer(format!("{other:?}"))),
        }
    }

    pub fn min(&self, filter: Filter, column: &str) -> Result<Option<i32>, Refusal> {
        let col = self.int(column)?;
        self.extreme(self.present(filter, col), Agg::MinI32(col))
    }

    pub fn max(&self, filter: Filter, column: &str) -> Result<Option<i32>, Refusal> {
        let col = self.int(column)?;
        self.extreme(self.present(filter, col), Agg::MaxI32(col))
    }

    /// `None` when no row holds a value, as SQL `AVG` over no rows is NULL.
    pub fn avg(&self, filter: Filter, column: &str) -> Result<Option<f64>, Refusal> {
        let col = self.int(column)?;
        let rows = self.count(self.present(filter.clone(), col))?;
        if rows == 0 {
            return Ok(None);
        }
        Ok(Some(self.sum(filter, column)? as f64 / rows as f64))
    }

    /// Rows per distinct text of `column`, in code order; absent cells belong to no text.
    pub fn count_by_text(&self, column: &str) -> Result<Vec<(String, usize)>, Refusal> {
        let col = self.text(column)?;
        let at = self.position(column)?;
        let codes = self.source.field(at).values.text_codes().unwrap_or(0);
        (0..codes as u32)
            .map(|code| {
                let text = self
                    .source
                    .text(&self.frame, column, code)
                    .ok_or_else(|| Refusal::Answer(format!("{column} code {code} unmapped")))?
                    .to_string();
                Ok((text, self.count(Filter::cmp(col, Cmp::EqU32(code)))?))
            })
            .collect()
    }

    /// Rows per `width_us` bucket of event time, as `(bucket start, rows)`; empty buckets are
    /// left out, and buckets align to the epoch as SQL `histogram` does.
    pub fn count_by_time(&self, width_us: i64) -> Result<Vec<(i64, usize)>, Refusal> {
        let col = self.time()?;
        if width_us <= 0 || width_us % US_PER_MS != 0 {
            return Err(Refusal::Precision(TIMESTAMP.to_string(), width_us));
        }
        let base_us = self.source.base_us().unwrap_or(0);
        let (Some(first), Some(last)) = (
            self.extreme(self.present(self.all(), col), Agg::MinI32(col))?,
            self.extreme(self.present(self.all(), col), Agg::MaxI32(col))?,
        ) else {
            return Ok(Vec::new());
        };
        let end_us = base_us + i64::from(last) * US_PER_MS;
        let mut start_us = (base_us + i64::from(first) * US_PER_MS).div_euclid(width_us) * width_us;
        let mut buckets = Vec::new();
        while start_us <= end_us {
            let lo = to_offset_ms(start_us - base_us);
            let hi = to_offset_ms(start_us + width_us - base_us);
            let rows = self.count(Filter::and([
                Filter::cmp(col, Cmp::GeI32(lo)),
                Filter::cmp(col, Cmp::LtI32(hi)),
            ]))?;
            if rows != 0 {
                buckets.push((start_us, rows));
            }
            start_us += width_us;
        }
        Ok(buckets)
    }

    /// `GROUP BY hi, lo` over the rows of `filter` that hold both keys and a time: rows, first
    /// and last event time per group, in code order. Three folds; no row is built.
    pub fn group_by_pair(
        &self,
        filter: Filter,
        hi: &str,
        lo: &str,
    ) -> Result<Vec<PairGroup>, Refusal> {
        let (hi_col, lo_col, time) = (self.text(hi)?, self.text(lo)?, self.time()?);
        let codes = |column: &str| -> Result<usize, Refusal> {
            let at = self.position(column)?;
            Ok(self.source.field(at).values.text_codes().unwrap_or(0))
        };
        let (hi_codes, stride) = (codes(hi)?, codes(lo)?);
        let groups = hi_codes * stride;
        if groups == 0 {
            return Ok(Vec::new());
        }
        let key = GroupAddr::Pair {
            hi: hi_col,
            lo: lo_col,
            stride: stride as u32,
        };
        let keyed = [hi_col, lo_col, time]
            .into_iter()
            .fold(filter, |f, col| self.present(f, col));
        let fold = |agg: GroupAgg| -> Result<Vec<i64>, Refusal> {
            let mut sink = vec![0i64; groups];
            self.run_groups(keyed.clone(), key, agg, &mut sink)?;
            normalize_group_sink(agg.fold(), &mut sink);
            Ok(sink)
        };
        let rows = fold(GroupAgg::Count)?;
        let first = fold(GroupAgg::MinI32(time))?;
        let last = fold(GroupAgg::MaxI32(time))?;
        let base_us = self.source.base_us().unwrap_or(0);
        let name = |column: &str, code: usize| {
            self.source
                .text(&self.frame, column, code as u32)
                .map(str::to_string)
                .ok_or_else(|| Refusal::Answer(format!("{column} code {code} unmapped")))
        };
        (0..groups)
            .filter(|g| rows[*g] != 0)
            .map(|g| {
                Ok(PairGroup {
                    hi: name(hi, g / stride)?,
                    lo: name(lo, g % stride)?,
                    rows: rows[g] as usize,
                    first_us: base_us + first[g] * US_PER_MS,
                    last_us: base_us + last[g] * US_PER_MS,
                })
            })
            .collect()
    }

    /// `GROUP BY COALESCE(hi…), COALESCE(lo…)`, answered in DR's coordinates: each key is the
    /// first of its text columns a row holds, placed by the caller's tile map. Rows are
    /// folded by their own codes; the map places the groups, never the rows.
    pub fn group_by_first_of(
        &self,
        filter: Filter,
        hi: &Key<'_>,
        lo: &Key<'_>,
    ) -> Result<Vec<PlacedGroup>, Refusal> {
        let (hi, lo, time) = (self.side(hi)?, self.side(lo)?, self.time()?);
        let mut cells = vec![Cell::EMPTY; hi.positions * lo.positions];
        let timed = self.present(filter, time);
        for (kh, hi_place) in hi.places.iter().enumerate() {
            for (kl, lo_place) in lo.places.iter().enumerate() {
                let stride = lo_place.len();
                if hi_place.is_empty() || stride == 0 {
                    continue;
                }
                let key = GroupAddr::Pair {
                    hi: hi.cols[kh],
                    lo: lo.cols[kl],
                    stride: stride as u32,
                };
                let keyed = Filter::and([timed.clone(), hi.only(kh), lo.only(kl)]);
                let folded = self.fold_pair(keyed, key, time, hi_place.len() * stride)?;
                for (g, cell) in folded.into_iter().enumerate().filter(|(_, c)| c.rows != 0) {
                    let at_hi = hi_place[g / stride].clone().map_err(Refusal::Unplaced)?;
                    let at_lo = lo_place[g % stride].clone().map_err(Refusal::Unplaced)?;
                    cells[at_hi as usize * lo.positions + at_lo as usize].merge(cell);
                }
            }
        }
        let base_us = self.source.base_us().unwrap_or(0);
        Ok(cells
            .iter()
            .enumerate()
            .filter(|(_, c)| c.rows != 0)
            .map(|(g, c)| PlacedGroup {
                hi: (g / lo.positions) as u32,
                lo: (g % lo.positions) as u32,
                rows: c.rows as usize,
                first_us: base_us + c.first * US_PER_MS,
                last_us: base_us + c.last * US_PER_MS,
            })
            .collect())
    }

    /// Rows, first and last time per group of `key`: three programs.
    fn fold_pair(
        &self,
        filter: Filter,
        key: GroupAddr,
        time: Col,
        groups: usize,
    ) -> Result<Vec<Cell>, Refusal> {
        let fold = |agg: GroupAgg| -> Result<Vec<i64>, Refusal> {
            let mut sink = vec![0i64; groups];
            self.run_groups(filter.clone(), key, agg, &mut sink)?;
            normalize_group_sink(agg.fold(), &mut sink);
            Ok(sink)
        };
        let rows = fold(GroupAgg::Count)?;
        let first = fold(GroupAgg::MinI32(time))?;
        let last = fold(GroupAgg::MaxI32(time))?;
        Ok((0..groups)
            .map(|g| match rows[g] {
                0 => Cell::EMPTY,
                n => Cell {
                    rows: n,
                    first: first[g],
                    last: last[g],
                },
            })
            .collect())
    }

    /// Where DR's map places each code of each column of a key; an unplaced text keeps its
    /// name, so it is refused only if a row is counted under it.
    fn side(&self, key: &Key<'_>) -> Result<Side, Refusal> {
        let codes_of = |col: Col| self.source.field(col.0 as usize).values.text_codes();
        let (columns, map, identity) = match key {
            Key::Property { column } => {
                let col = self.text(column)?;
                let codes = codes_of(col).unwrap_or(0);
                return Ok(Side {
                    cols: vec![col],
                    places: vec![(0..codes as u32).map(Ok).collect()],
                    positions: codes,
                });
            }
            Key::Entity {
                columns,
                map,
                identity,
            } => (columns, map, identity),
        };
        let mut side = Side {
            cols: Vec::new(),
            places: Vec::new(),
            positions: map.width().positions(),
        };
        for column in *columns {
            let col = self.text(column)?;
            let mut place = Vec::new();
            for code in 0..codes_of(col).unwrap_or(0) as u32 {
                let text = self
                    .source
                    .text(&self.frame, column, code)
                    .ok_or_else(|| Refusal::Answer(format!("{column} code {code} unmapped")))?;
                place.push(
                    identity(&ValueKey(text.to_string()))
                        .and_then(|global| map.local(global).ok())
                        .map(u32::from)
                        .ok_or_else(|| text.to_string()),
                );
            }
            side.cols.push(col);
            side.places.push(place);
        }
        Ok(side)
    }

    /// DT's reading of a property group: the text `code` of `column` stands for.
    pub fn label(&self, column: &str, code: u32) -> Option<&str> {
        self.source.text(&self.frame, column, code)
    }

    fn present(&self, filter: Filter, col: Col) -> Filter {
        Filter::and([filter, Filter::is_not_null(Mask(col.0 + 1))])
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
        let rows = self.source.rows();
        let planes = Planes {
            n_rows: rows,
            masks: &self.masks,
            lanes: &self.lanes,
        };
        let mut scratch =
            Scratch::for_program(&program, rows).map_err(|e| Refusal::Run(format!("{e:?}")))?;
        execute(&program, &planes, &mut scratch, None).map_err(|e| Refusal::Run(format!("{e:?}")))
    }

    fn run_groups(
        &self,
        filter: Filter,
        key: GroupAddr,
        agg: GroupAgg,
        sink: &mut [i64],
    ) -> Result<(), Refusal> {
        let query = Query {
            filter: filter.sql_where(&self.nullable),
            agg: Agg::GroupReduce { key, agg },
        };
        let program = lower(&query).map_err(|e| Refusal::Lower(format!("{e:?}")))?;
        let rows = self.source.rows();
        let planes = Planes {
            n_rows: rows,
            masks: &self.masks,
            lanes: &self.lanes,
        };
        let mut scratch =
            Scratch::for_program(&program, rows).map_err(|e| Refusal::Run(format!("{e:?}")))?;
        execute_into(
            &program,
            &planes,
            &Foreign::NONE,
            &mut scratch,
            Out::I64(sink),
        )
        .map(|_| ())
        .map_err(|e| Refusal::Run(format!("{e:?}")))
    }

    fn position(&self, column: &str) -> Result<usize, Refusal> {
        self.source
            .field_index(column)
            .ok_or_else(|| Refusal::Column(column.to_string()))
    }

    fn kind(&self, column: &str) -> Result<(Col, &Values), Refusal> {
        let at = self.position(column)?;
        Ok((Col(at as u16), &self.source.field(at).values))
    }

    fn text(&self, column: &str) -> Result<Col, Refusal> {
        match self.kind(column)? {
            (col, Values::Text { .. }) => Ok(col),
            _ => Err(Refusal::Kind(column.to_string())),
        }
    }

    fn int(&self, column: &str) -> Result<Col, Refusal> {
        match self.kind(column)? {
            (col, Values::Int(_)) => Ok(col),
            _ => Err(Refusal::Kind(column.to_string())),
        }
    }

    fn time(&self) -> Result<Col, Refusal> {
        match self.kind(TIMESTAMP)? {
            (col, Values::Time(_)) => Ok(col),
            _ => Err(Refusal::Kind(TIMESTAMP.to_string())),
        }
    }
}

/// One key of [`Reader::group_by_first_of`]. This crate keeps neither a position map nor a
/// label table: an entity is placed by the caller's DR tile, a property stays the code DT's
/// code table gave it.
pub enum Key<'a> {
    /// The key names an entity: the first of `columns` a row holds, as SQL `COALESCE`.
    Entity {
        columns: &'a [&'a str],
        /// DR: the tile the entities are placed in.
        map: TileMap<'a>,
        /// DT: the identity a value key of these columns names, or `None`.
        identity: &'a dyn Fn(&ValueKey) -> Option<u64>,
    },
    /// The key is a property value. Its groups are the column's codes; no identity is
    /// involved. Name one with [`Reader::label`].
    Property { column: &'a str },
}

/// A key's columns with the position DR gives each of their codes.
struct Side {
    cols: Vec<Col>,
    /// Per column, code → the group's coordinate, or the text DR does not place.
    places: Vec<Vec<Result<u32, String>>>,
    /// Coordinates of the key: the tile's positions, or the property's codes.
    positions: usize,
}

impl Side {
    /// Rows whose key comes from column `k`: it holds a value and no earlier column does.
    fn only(&self, k: usize) -> Filter {
        let valid = |col: &Col| Mask(col.0 + 1);
        Filter::and(
            self.cols[..k]
                .iter()
                .map(|c| Filter::is_null(valid(c)))
                .chain([Filter::is_not_null(valid(&self.cols[k]))]),
        )
    }
}

/// One group's running answer across the folds that reach it.
#[derive(Clone, Copy)]
struct Cell {
    rows: i64,
    first: i64,
    last: i64,
}

impl Cell {
    const EMPTY: Cell = Cell {
        rows: 0,
        first: i64::MAX,
        last: i64::MIN,
    };

    fn merge(&mut self, other: Cell) {
        self.rows += other.rows;
        self.first = self.first.min(other.first);
        self.last = self.last.max(other.last);
    }
}

/// One group of [`Reader::group_by_first_of`]. Each side is a position in the caller's tile
/// for an entity key, or the column's code for a property key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlacedGroup {
    pub hi: u32,
    pub lo: u32,
    pub rows: usize,
    pub first_us: i64,
    pub last_us: i64,
}

/// One group of [`Reader::group_by_pair`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PairGroup {
    pub hi: String,
    pub lo: String,
    pub rows: usize,
    pub first_us: i64,
    pub last_us: i64,
}

/// Why a batch or a question has no answer on lanes.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    Type(String, arrow::datatypes::DataType),
    Range(String, i64),
    /// A time finer than the millisecond lane, or a span or width it cannot hold.
    Precision(String, i64),
    Column(String),
    /// More fields than a stream's basis holds.
    Columns(usize),
    Kind(String),
    /// DT64 refused to bind the stream's lanes.
    Bind(String),
    Lower(String),
    Run(String),
    Answer(String),
    /// A counted row holds a key text that DR's map gives no position.
    Unplaced(String),
}

/// Saturates: a bound past the lane's range still compares correctly against every offset.
fn to_offset_ms(offset_us: i64) -> i32 {
    (offset_us.div_euclid(US_PER_MS)).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}
