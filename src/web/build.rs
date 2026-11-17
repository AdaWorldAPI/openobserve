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
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rerun-if-changed={manifest_dir}/src/lib.rs");

    // Read the embed folder from the `#[folder = "..."]` line in lib.rs
    // instead of hardcoding it: e2e workflows rewrite that line to a
    // path outside the repo, and this keeps the tracking in sync.
    let lib = fs::read_to_string(format!("{manifest_dir}/src/lib.rs"))
        .expect("failed to read src/lib.rs");
    let folder = lib
        .split("#[folder = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("no #[folder = \"...\"] line found in src/lib.rs");
    let dist = Path::new(manifest_dir).join(folder);

    // Nothing else tracks the folder, so without this a rebuilt web/dist
    // would silently ship stale embedded assets.
    println!("cargo:rerun-if-changed={}", dist.display());

    // A wrong or missing folder embeds zero assets and only fails at runtime
    // with a blank UI (openobserve/openobserve#13197).
    if !dist.join("index.html").is_file() {
        println!(
            "cargo:warning={} does not contain index.html; the binary will serve an empty web UI",
            dist.display()
        );
    }

    let mut files = Vec::new();
    collect(&dist, &dist, &mut files);
    files.sort();
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set")).join("web_assets.rs");
    fs::write(&out, table(&files)).expect("failed to write the asset table");
}

/// Every file under `dir`, as (path relative to `root` with `/` separators, absolute path).
fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, files);
        } else if let Ok(rel) = path.strip_prefix(root) {
            let rel = rel.to_string_lossy().replace('\\', "/");
            let abs = path.canonicalize().unwrap_or(path);
            files.push((rel, abs));
        }
    }
}

// One `include_bytes!` per file: the compiler copies the bytes without parsing them. A
// literal with one number per byte needs tens of GB of compiler memory for a 67 MB UI.
fn table(files: &[(String, PathBuf)]) -> String {
    let mut src = String::from("static ASSETS: &[(&str, &[u8])] = &[\n");
    for (rel, abs) in files {
        let abs = abs.display().to_string();
        src.push_str(&format!("    ({rel:?}, include_bytes!({abs:?})),\n"));
    }
    src.push_str("];\n");
    src
}
