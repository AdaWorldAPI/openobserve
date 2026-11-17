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

use std::{
    collections::{HashMap, VecDeque},
    sync::{LazyLock, RwLock},
};

use arrow::array::RecordBatch;

use crate::{LaneTable, Refusal};

/// The shadow copy is for comparison, so each stream keeps only its newest rows.
const MAX_ROWS_PER_STREAM: usize = 1_000_000;

static STREAMS: LazyLock<RwLock<HashMap<StreamKey, Stream>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub org: String,
    pub stream_type: String,
    pub stream: String,
}

impl StreamKey {
    pub fn new(org: &str, stream_type: &str, stream: &str) -> Self {
        Self {
            org: org.to_string(),
            stream_type: stream_type.to_string(),
            stream: stream.to_string(),
        }
    }
}

/// What the shadow copy of one stream holds and what it could not take.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShadowStats {
    pub tables: usize,
    pub rows: usize,
    /// Rows dropped to stay under the per-stream bound.
    pub evicted_rows: usize,
    pub refused_batches: usize,
    pub refused_rows: usize,
    /// Columns left out of an admitted batch, counted once per batch.
    pub skipped_columns: usize,
}

#[derive(Default)]
struct Stream {
    tables: VecDeque<LaneTable>,
    stats: ShadowStats,
}

/// Appends one written batch to the stream's shadow copy. It never fails the write that
/// called it: a batch with no lanes is counted and returned as the refusal.
pub fn append(key: &StreamKey, batch: &RecordBatch) -> Option<Refusal> {
    let admitted = LaneTable::admit(batch);
    let mut streams = STREAMS.write().unwrap_or_else(|e| e.into_inner());
    let stream = streams.entry(key.clone()).or_default();
    let (table, skipped) = match admitted {
        Ok(admitted) => admitted,
        Err(refusal) => {
            stream.stats.refused_batches += 1;
            stream.stats.refused_rows += batch.num_rows();
            return Some(refusal);
        }
    };
    stream.stats.skipped_columns += skipped.len();
    stream.stats.rows += table.rows();
    stream.stats.tables += 1;
    stream.tables.push_back(table);
    while stream.stats.rows > MAX_ROWS_PER_STREAM && stream.tables.len() > 1 {
        if let Some(oldest) = stream.tables.pop_front() {
            stream.stats.rows -= oldest.rows();
            stream.stats.evicted_rows += oldest.rows();
            stream.stats.tables -= 1;
        }
    }
    None
}

pub fn stats(key: &StreamKey) -> ShadowStats {
    let streams = STREAMS.read().unwrap_or_else(|e| e.into_inner());
    streams
        .get(key)
        .map(|s| s.stats.clone())
        .unwrap_or_default()
}

/// Folds `answer` over the stream's tables, oldest first. Dictionary codes are per table, so
/// the question is asked of each table and the answers are combined by the caller's fold.
pub fn fold<T>(
    key: &StreamKey,
    init: T,
    mut answer: impl FnMut(T, &LaneTable) -> Result<T, Refusal>,
) -> Result<T, Refusal> {
    let streams = STREAMS.read().unwrap_or_else(|e| e.into_inner());
    let Some(stream) = streams.get(key) else {
        return Ok(init);
    };
    stream
        .tables
        .iter()
        .try_fold(init, |acc, table| answer(acc, table))
}
