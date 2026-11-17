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

//! ZITADEL login for the OSS build: OIDC authorization code with PKCE on `ogar-oidc` and
//! `ogar-auth`. No OpenObserve crate depends on `ogar-*` except this one.

pub mod config;
pub mod flow;
pub mod http;

use std::sync::OnceLock;

pub use config::{PolicyRole, TenantRow, ZitadelConfig};
pub use flow::{Admitted, LOGIN_TTL_SECS, Refusal, SESSION_SCHEME, Started, Zitadel};
pub use http::{OidcHttp, ReqwestHttp};

/// Key prefix (the kv "org") under which pending logins are kept, keyed by `state`.
pub const STATE_KV_ORG: &str = "o2_zitadel_login";

static ZITADEL: OnceLock<Option<Zitadel>> = OnceLock::new();

/// The process-wide ZITADEL login, read from the environment once. `None`: not configured, or the
/// configuration was refused (logged), which leaves login as it is without the feature.
pub fn zitadel() -> Option<&'static Zitadel> {
    ZITADEL
        .get_or_init(|| match Zitadel::from_env() {
            Ok(z) => z,
            Err(e) => {
                log::error!("ZITADEL login disabled, configuration refused: {e}");
                None
            }
        })
        .as_ref()
}

pub fn active() -> bool {
    zitadel().is_some()
}

/// `native_login_enabled` as the UI sees it: password login is on unless ZITADEL is active and
/// `O2_ZITADEL_NATIVE_LOGIN` is not set.
pub fn native_login_enabled() -> bool {
    zitadel().is_none_or(|z| z.config().native_login)
}

/// May this user sign in with a password? Only root, and only while break-glass is on, once
/// ZITADEL is active with native login off.
pub fn password_login_allowed(is_root: bool) -> bool {
    password_login_policy(
        zitadel().map(|z| (z.config().native_login, z.config().root_break_glass)),
        is_root,
    )
}

/// `active` is `(native_login, root_break_glass)` of the active configuration, `None` without one.
pub fn password_login_policy(active: Option<(bool, bool)>, is_root: bool) -> bool {
    match active {
        None | Some((true, _)) => true,
        Some((false, break_glass)) => is_root && break_glass,
    }
}

/// `state` from the cookie equals `state` from the query, compared in constant time.
pub fn state_matches(cookie: Option<&str>, query: Option<&str>) -> bool {
    let (Some(cookie), Some(query)) = (cookie, query) else {
        return false;
    };
    if cookie.is_empty() || cookie.len() != query.len() {
        return false;
    }
    cookie
        .bytes()
        .zip(query.bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// The auth string that makes the request trusted as a ZITADEL session: only a stored session
/// value of this scheme is marked, so no other stored token rides the marker.
pub fn session_auth(marker: &str, session_id: &str, stored: &str) -> Option<String> {
    stored
        .starts_with(SESSION_SCHEME)
        .then(|| format!("{marker}{session_id}::{stored}"))
}

/// The session payload of a `Zitadel ` auth string, only when it came out of a live server-side
/// session. The same string from a client carries nothing.
pub fn session_payload(auth: &str, from_session: bool) -> Option<&str> {
    if !from_session {
        return None;
    }
    auth.strip_prefix(SESSION_SCHEME)
}
