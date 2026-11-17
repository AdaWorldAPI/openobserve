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

//! Embeds the built web UI (`web/dist`) into the binary.
//!
//! This lives in its own leaf crate so the embed only re-runs when
//! `web/dist` changes, not on every rebuild of the API crate.
//!
//! For that to hold, the dependency list here must stay small and stable:
//! anything this crate depends on rebuilds the embed again whenever it
//! changes. `config` in particular used to be a dependency, which
//! meant every `config` edit paid the embed cost. Config values the UI routes
//! need are passed in as arguments instead — see [`ui_routes`].

mod ui;

pub use ui::ui_routes;

// build.rs reads the folder from the next line and writes one table entry per file, sorted
// by path. A missing folder gives an empty table.
// #[folder = "../../web/dist/"]
include!(concat!(env!("OUT_DIR"), "/web_assets.rs"));

pub struct WebAssets;

impl WebAssets {
    pub fn get(path: &str) -> Option<&'static [u8]> {
        ASSETS
            .binary_search_by(|(name, _)| (*name).cmp(path))
            .ok()
            .map(|at| ASSETS[at].1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `get` is a binary search, so it only finds every file while the table is sorted.
    #[test]
    fn every_embedded_file_is_found_with_its_own_bytes() {
        for (name, bytes) in ASSETS {
            assert_eq!(WebAssets::get(name), Some(*bytes), "{name}");
        }
        assert_eq!(WebAssets::get("no/such/file"), None);
    }
}
