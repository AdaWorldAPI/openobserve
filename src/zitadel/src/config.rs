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

use std::fmt;

use ogar_auth::identity::Issuer;
use serde::Deserialize;

pub const DEFAULT_ORG_CLAIM: &str = "urn:zitadel:iam:user:resourceowner:id";
/// Scope that makes ZITADEL put the user's organization id into the ID token.
pub const ORG_SCOPE: &str = "urn:zitadel:iam:user:resourceowner";

/// The roles a policy row may grant. `root`, `service_account` and `sre_agent` have no variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyRole {
    Admin,
    Editor,
    Viewer,
    User,
}

impl PolicyRole {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "editor" => Some(Self::Editor),
            "viewer" => Some(Self::Viewer),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

/// One tenant row of `O2_ZITADEL_POLICY`: a ZITADEL organization mapped to an OpenObserve org.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantRow {
    pub org: String,
    pub o2_org: String,
    pub role: PolicyRole,
    pub email_domains: Vec<String>,
}

/// Everything read from `O2_ZITADEL_*`. The client secret never appears in `Debug`.
#[derive(Clone)]
pub struct ZitadelConfig {
    pub issuer: Issuer,
    pub client_id: String,
    pub redirect_url: String,
    pub(crate) client_secret: Option<String>,
    pub tenants: Vec<TenantRow>,
    pub org_claim: String,
    pub native_login: bool,
    pub root_break_glass: bool,
}

impl fmt::Debug for ZitadelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZitadelConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_url", &self.redirect_url)
            .field("tenants", &self.tenants.len())
            .finish_non_exhaustive()
    }
}

/// A refused configuration. The message names the variable or row, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn cfg_err(msg: impl Into<String>) -> ConfigError {
    ConfigError(msg.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RowJson {
    org: String,
    o2_org: String,
    role: String,
    email_domains: Vec<String>,
}

impl ZitadelConfig {
    /// `Ok(None)` unless issuer, client id and redirect URL are all set. A bad value is an error.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ConfigError> {
        let present = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let (Some(issuer), Some(client_id), Some(redirect_url)) = (
            present("O2_ZITADEL_ISSUER"),
            present("O2_ZITADEL_CLIENT_ID"),
            present("O2_ZITADEL_REDIRECT_URL"),
        ) else {
            if present("O2_ZITADEL_ISSUER").is_some()
                || present("O2_ZITADEL_CLIENT_ID").is_some()
                || present("O2_ZITADEL_REDIRECT_URL").is_some()
            {
                log::warn!(
                    "ZITADEL login stays off: O2_ZITADEL_ISSUER, _CLIENT_ID and _REDIRECT_URL are all required"
                );
            }
            return Ok(None);
        };
        let issuer = Issuer::new(&issuer)
            .map_err(|_| cfg_err("O2_ZITADEL_ISSUER is not an https issuer"))?;
        if !redirect_url.starts_with("https://") || !redirect_url.ends_with("/config/redirect") {
            return Err(cfg_err(
                "O2_ZITADEL_REDIRECT_URL must be an https URL ending in /config/redirect",
            ));
        }
        let tenants = match present("O2_ZITADEL_POLICY") {
            Some(text) => parse_policy(&text)?,
            None => Vec::new(),
        };
        Ok(Some(Self {
            issuer,
            client_id,
            redirect_url,
            client_secret: present("O2_ZITADEL_CLIENT_SECRET"),
            tenants,
            org_claim: present("O2_ZITADEL_ORG_CLAIM")
                .unwrap_or_else(|| DEFAULT_ORG_CLAIM.to_string()),
            native_login: parse_bool(present("O2_ZITADEL_NATIVE_LOGIN"), false)
                .ok_or_else(|| cfg_err("O2_ZITADEL_NATIVE_LOGIN must be true or false"))?,
            root_break_glass: parse_bool(present("O2_ZITADEL_ROOT_BREAK_GLASS"), true)
                .ok_or_else(|| cfg_err("O2_ZITADEL_ROOT_BREAK_GLASS must be true or false"))?,
        }))
    }

    /// The row whose ZITADEL organization id is `org`.
    pub fn tenant(&self, org: &str) -> Option<&TenantRow> {
        self.tenants.iter().find(|t| t.org == org)
    }
}

fn parse_bool(v: Option<String>, default: bool) -> Option<bool> {
    match v.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None => Some(default),
        Some("true" | "1") => Some(true),
        Some("false" | "0") => Some(false),
        Some(_) => None,
    }
}

/// The policy document: a JSON array of tenant rows. Unknown fields, a duplicate `org`, an empty
/// id or domain list and a role other than admin/editor/viewer/user are refused.
pub fn parse_policy(text: &str) -> Result<Vec<TenantRow>, ConfigError> {
    let rows: Vec<RowJson> = serde_json::from_str(text).map_err(|e| {
        cfg_err(format!(
            "O2_ZITADEL_POLICY: not a JSON array of tenant rows (line {})",
            e.line()
        ))
    })?;
    let mut out: Vec<TenantRow> = Vec::with_capacity(rows.len());
    for (i, r) in rows.into_iter().enumerate() {
        let row = i + 1;
        let org = r.org.trim().to_string();
        let o2_org = r.o2_org.trim().to_string();
        if org.is_empty() || o2_org.is_empty() {
            return Err(cfg_err(format!("policy row {row}: empty org or o2_org")));
        }
        let role = PolicyRole::parse(r.role.trim()).ok_or_else(|| {
            cfg_err(format!(
                "policy row {row}: role must be admin, editor, viewer or user"
            ))
        })?;
        if out.iter().any(|t| t.org == org) {
            return Err(cfg_err(format!("policy row {row}: duplicate org")));
        }
        let email_domains: Vec<String> = r
            .email_domains
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .collect();
        if email_domains.is_empty()
            || email_domains
                .iter()
                .any(|d| d.is_empty() || d.contains('@'))
        {
            return Err(cfg_err(format!(
                "policy row {row}: email_domains must list bare domains"
            )));
        }
        out.push(TenantRow {
            org,
            o2_org,
            role,
            email_domains,
        });
    }
    Ok(out)
}
