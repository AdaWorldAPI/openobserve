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

use std::{collections::HashMap, sync::Arc};

use arrow::{
    array::{Array, Int64Array, RecordBatch, StringArray},
    datatypes::DataType,
};
use lance_graph_contract::{
    class_view::{ClassId, ClassView},
    ontology::{DisplayTemplate, FieldRef},
};
use lance_graph_dt64::{
    CoordSpace, LaneAddr, LaneSource, MAX_FIELDS, PresenceSource, SchemaRev,
    dr::{CodeSpaceId, CodeTable, Frame, FrameRevisions, FrameStore, Scope, ValueKey},
    view_class,
};
use lance_graph_mask_risc::{LaneRef, words_for};

use crate::{Refusal, TIMESTAMP};

/// The one schema revision a stream's lanes are served under.
pub const STREAM_REV: SchemaRev = SchemaRev(1);
const US_PER_MS: i64 = 1_000;

/// One stream's rows as lanes it owns; a field's identity is its column name.
pub struct StreamSource {
    class: u32,
    scope: Scope,
    frames: FrameStore,
    codes: CodeTable<u32>,
    rows: usize,
    live: Vec<u64>,
    fields: Vec<StreamField>,
    /// Event time is stored as milliseconds after this, fixed by the first batch.
    base_us: Option<i64>,
}

pub(crate) struct StreamField {
    pub(crate) name: String,
    pub(crate) values: Values,
    /// One bit per row, set where the row holds a value.
    pub(crate) presence: Vec<u64>,
}

pub(crate) enum Values {
    /// Codes into the field's code space, numbered in the order keys first appeared.
    Text {
        codes: Vec<u32>,
        index: HashMap<String, u32>,
    },
    Int(Vec<i32>),
    Time(Vec<i32>),
}

impl StreamSource {
    pub fn new(class: u32, scope: Scope) -> Self {
        let frames = FrameStore::new(FrameRevisions {
            source: 0,
            relation_map: 0,
            coordinates: 1,
        });
        let codes = CodeTable::new(&frames);
        Self {
            class,
            scope,
            frames,
            codes,
            rows: 0,
            live: Vec::new(),
            fields: Vec::new(),
            base_us: None,
        }
    }

    /// Appends every row of `batch`; nothing changes when any column is refused. A field
    /// the batch lacks is absent on its rows, and a new field is absent on earlier rows.
    pub fn append(&mut self, batch: &RecordBatch) -> Result<(), Refusal> {
        let staged = self.stage(batch)?;
        let before = self.rows;
        let added = batch.num_rows();
        self.rows += added;
        grow(&mut self.live, self.rows);
        for row in before..self.rows {
            self.live[row / 64] |= 1 << (row % 64);
        }
        let mut changed = Vec::new();
        for column in staged {
            let at = match self.field_index(&column.name) {
                Some(at) => at,
                None => {
                    let field = StreamField::empty(column.name.clone(), &column.values, before);
                    self.fields.push(field);
                    self.fields.len() - 1
                }
            };
            if self.fields[at].extend(column, before, added) {
                changed.push(at);
            }
        }
        for field in &mut self.fields {
            field.pad(self.rows);
        }
        self.advance(&changed)
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    pub fn class(&self) -> u32 {
        self.class
    }

    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The row order every lane and presence plane is in.
    pub fn space(&self) -> CoordSpace {
        CoordSpace {
            population: u64::from(self.class),
            coordinates: 1,
        }
    }

    /// The field basis, one field per column in the order columns first appeared.
    pub fn basis(&self) -> StreamView {
        StreamView {
            class: view_class(self.class),
            fields: self
                .fields
                .iter()
                .map(|f| FieldRef::new(&f.name, &f.name))
                .collect(),
        }
    }

    /// The code `text` has in `column` under `frame`; `None` when the column never held it.
    pub fn code(&self, frame: &Frame, column: &str, text: &str) -> Option<u32> {
        self.codes
            .code(frame, &self.code_space(column), &ValueKey(text.to_string()))
            .ok()
    }

    /// The text `code` meant in `column` under `frame`.
    pub fn text(&self, frame: &Frame, column: &str, code: u32) -> Option<&str> {
        self.codes
            .key(frame, &self.code_space(column), code)
            .ok()
            .map(|k| k.0.as_str())
    }

    pub(crate) fn field(&self, at: usize) -> &StreamField {
        &self.fields[at]
    }

    pub(crate) fn field_index(&self, name: &str) -> Option<usize> {
        self.fields.iter().position(|f| f.name == name)
    }

    pub(crate) fn live(&self) -> &[u64] {
        &self.live
    }

    pub(crate) fn base_us(&self) -> Option<i64> {
        self.base_us
    }

    fn code_space(&self, column: &str) -> CodeSpaceId {
        CodeSpaceId {
            class: self.class,
            property: column.to_string(),
        }
    }

    /// One frame advance per append: through the code table when a code space grew.
    fn advance(&mut self, changed: &[usize]) -> Result<(), Refusal> {
        if changed.is_empty() {
            let r = self.frames.revisions();
            self.frames.advance(FrameRevisions {
                source: r.source.wrapping_add(1),
                ..r
            });
            return Ok(());
        }
        let spaces = changed
            .iter()
            .filter_map(|&at| match &self.fields[at].values {
                Values::Text { index, .. } => Some((
                    self.code_space(&self.fields[at].name),
                    index
                        .iter()
                        .map(|(k, &c)| (ValueKey(k.clone()), c))
                        .collect(),
                )),
                _ => None,
            })
            .collect();
        self.codes
            .advance(&mut self.frames, spaces)
            .map_err(|e| Refusal::Run(format!("{e:?}")))
    }

    fn stage(&mut self, batch: &RecordBatch) -> Result<Vec<Staged>, Refusal> {
        let schema = batch.schema();
        let mut staged = Vec::with_capacity(batch.num_columns());
        let mut base_us = self.base_us;
        for (field, column) in schema.fields().iter().zip(batch.columns()) {
            let name = field.name();
            let values = match field.data_type() {
                DataType::Utf8 => StagedValues::Text(text_values(column)),
                DataType::Int64 if name == TIMESTAMP => {
                    let base = *base_us.get_or_insert_with(|| min_valid(column));
                    StagedValues::Time(time_values(column, base)?)
                }
                DataType::Int64 => StagedValues::Int(int_values(name, column)?),
                other => return Err(Refusal::Type(name.clone(), other.clone())),
            };
            if let Some(at) = self.field_index(name)
                && !self.fields[at].values.same_kind(&values)
            {
                return Err(Refusal::Kind(name.clone()));
            }
            staged.push(Staged {
                name: name.clone(),
                values,
            });
        }
        let new = staged
            .iter()
            .filter(|s| self.field_index(&s.name).is_none())
            .count();
        if self.fields.len() + new > MAX_FIELDS {
            return Err(Refusal::Columns(self.fields.len() + new));
        }
        self.base_us = base_us;
        Ok(staged)
    }
}

impl LaneSource for StreamSource {
    type Lane<'a> = LaneRef<'a>;

    fn lane_of(
        &self,
        class: u32,
        rev: SchemaRev,
        _field: u8,
        basis: &FieldRef,
        frame: &Frame,
    ) -> Option<LaneAddr> {
        self.frames.check(frame).ok()?;
        if class != self.class || rev != STREAM_REV {
            return None;
        }
        // By the field's identity, never its position in the reader's basis.
        let at = self.field_index(basis.predicate_iri.as_str())?;
        Some(LaneAddr {
            space: self.space(),
            lane: u16::try_from(at).ok()?,
            scope: self.scope,
        })
    }

    fn borrow(&self, addr: &LaneAddr) -> Option<LaneRef<'_>> {
        if addr.space != self.space() {
            return None;
        }
        Some(match &self.fields.get(usize::from(addr.lane))?.values {
            Values::Text { codes, .. } => LaneRef::U32(codes),
            Values::Int(v) | Values::Time(v) => LaneRef::I32(v),
        })
    }

    fn frames(&self) -> &FrameStore {
        &self.frames
    }
}

impl PresenceSource for StreamSource {
    fn borrow_presence(&self, addr: &LaneAddr) -> Option<&[u64]> {
        if addr.space != self.space() {
            return None;
        }
        self.fields
            .get(usize::from(addr.lane))
            .map(|f| f.presence.as_slice())
    }
}

/// A stream's field basis as the ClassView DT64 binds it against.
pub struct StreamView {
    class: ClassId,
    fields: Vec<FieldRef>,
}

impl StreamView {
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl ClassView for StreamView {
    fn fields(&self, class: ClassId) -> &[FieldRef] {
        if class == self.class {
            &self.fields
        } else {
            &[]
        }
    }

    fn template(&self, _class: ClassId) -> DisplayTemplate {
        DisplayTemplate::Detail
    }

    fn dolce_category_id(&self, _class: ClassId) -> u8 {
        0
    }
}

impl StreamField {
    fn empty(name: String, like: &StagedValues, rows: usize) -> Self {
        let values = match like {
            StagedValues::Text(_) => Values::Text {
                codes: vec![0; rows],
                index: HashMap::new(),
            },
            StagedValues::Int(_) => Values::Int(vec![0; rows]),
            StagedValues::Time(_) => Values::Time(vec![0; rows]),
        };
        let mut presence = Vec::new();
        grow(&mut presence, rows);
        Self {
            name,
            values,
            presence,
        }
    }

    /// Appends one batch's values from row `from`; true when a new text key was coded.
    fn extend(&mut self, column: Staged, from: usize, added: usize) -> bool {
        grow(&mut self.presence, from + added);
        let mut grew = false;
        let cells: Vec<Option<()>> = match (&mut self.values, column.values) {
            (Values::Text { codes, index }, StagedValues::Text(texts)) => texts
                .into_iter()
                .map(|t| {
                    let Some(t) = t else {
                        codes.push(0);
                        return None;
                    };
                    let next = index.len() as u32;
                    let code = *index.entry(t).or_insert_with(|| {
                        grew = true;
                        next
                    });
                    codes.push(code);
                    Some(())
                })
                .collect(),
            (Values::Int(lane), StagedValues::Int(v))
            | (Values::Time(lane), StagedValues::Time(v)) => v
                .into_iter()
                .map(|x| {
                    lane.push(x.unwrap_or(0));
                    x.map(|_| ())
                })
                .collect(),
            _ => unreachable!("kinds were checked when the batch was staged"),
        };
        for (i, cell) in cells.into_iter().enumerate() {
            if cell.is_some() {
                let row = from + i;
                self.presence[row / 64] |= 1 << (row % 64);
            }
        }
        grew
    }

    /// Rows past this field's last value are absent: value 0, presence bit 0.
    fn pad(&mut self, rows: usize) {
        grow(&mut self.presence, rows);
        match &mut self.values {
            Values::Text { codes, .. } => codes.resize(rows, 0),
            Values::Int(v) | Values::Time(v) => v.resize(rows, 0),
        }
    }
}

impl Values {
    /// How many codes a text field has issued; `None` for any other kind.
    pub(crate) fn text_codes(&self) -> Option<usize> {
        match self {
            Values::Text { index, .. } => Some(index.len()),
            _ => None,
        }
    }

    fn same_kind(&self, staged: &StagedValues) -> bool {
        matches!(
            (self, staged),
            (Values::Text { .. }, StagedValues::Text(_))
                | (Values::Int(_), StagedValues::Int(_))
                | (Values::Time(_), StagedValues::Time(_))
        )
    }
}

struct Staged {
    name: String,
    values: StagedValues,
}

enum StagedValues {
    Text(Vec<Option<String>>),
    Int(Vec<Option<i32>>),
    Time(Vec<Option<i32>>),
}

fn grow(plane: &mut Vec<u64>, rows: usize) {
    plane.resize(words_for(rows), 0);
}

fn text_values(column: &Arc<dyn Array>) -> Vec<Option<String>> {
    column
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("Utf8 column is a StringArray")
        .iter()
        .map(|t| t.map(str::to_string))
        .collect()
}

fn ints(column: &Arc<dyn Array>) -> &Int64Array {
    column
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Int64 column is an Int64Array")
}

fn int_values(name: &str, column: &Arc<dyn Array>) -> Result<Vec<Option<i32>>, Refusal> {
    ints(column)
        .iter()
        .map(|v| {
            v.map(|v| i32::try_from(v).map_err(|_| Refusal::Range(name.to_string(), v)))
                .transpose()
        })
        .collect()
}

fn min_valid(column: &Arc<dyn Array>) -> i64 {
    ints(column).iter().flatten().min().unwrap_or(0)
}

fn time_values(column: &Arc<dyn Array>, base_us: i64) -> Result<Vec<Option<i32>>, Refusal> {
    ints(column)
        .iter()
        .map(|us| {
            us.map(|us| {
                let offset = us - base_us;
                if offset % US_PER_MS != 0 {
                    return Err(Refusal::Precision(TIMESTAMP.to_string(), us));
                }
                i32::try_from(offset / US_PER_MS)
                    .map_err(|_| Refusal::Precision(TIMESTAMP.to_string(), us))
            })
            .transpose()
        })
        .collect()
}
