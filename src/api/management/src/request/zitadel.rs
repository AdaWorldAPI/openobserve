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

use std::collections::HashMap;

use axum::{
    body::Body,
    extract::Query,
    http::{StatusCode, header},
    response::Response,
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use bytes::Bytes;
use config::{
    Config, get_config, ider,
    meta::user::{DBUser, UserOrg, UserRole},
    utils::{base64, json, rand::generate_random_string},
};
use db::user::is_root_user;
use o2_zitadel::{Admitted, PolicyRole, STATE_KV_ORG, pending_cap_reached, pending_expired};
use openobserve_api_common::auth::validator::ID_TOKEN_HEADER;
use openobserve_core::{kv, organization, session, users};

use crate::common::meta::{
    http::HttpResponse as MetaHttpResponse,
    user::{AuthTokens, UserOrgRole},
};

const LOGIN_STATE_COOKIE: &str = "o2_login_state";
const LOGIN_STATE_MAX_AGE_SECS: i64 = 600;
// Written over a consumed state so a second callback finds nothing to take.
const STATE_USED: &[u8] = b"used";

/// `GET /config/dex_login`: the authorize URL as a JSON string, with the state cookie set.
pub async fn login() -> Response {
    let Some(zitadel) = o2_zitadel::zitadel() else {
        return status_only(StatusCode::NOT_FOUND);
    };
    let started = match zitadel.start().await {
        Ok(started) => started,
        Err(refusal) => {
            log::error!("zitadel login could not start: {}", refusal.class());
            return login_state_unavailable();
        }
    };
    match sweep_pending().await {
        Ok(remaining) if !pending_cap_reached(remaining) => {}
        Ok(_) => {
            log::error!("zitadel pending logins are at the cap");
            return login_state_unavailable();
        }
        Err(error) => {
            log::error!("failed to sweep zitadel login state: {error}");
            return login_state_unavailable();
        }
    }
    if let Err(error) = kv::set(STATE_KV_ORG, &started.state, started.pending.clone().into()).await
    {
        log::error!("failed to save zitadel login state: {error}");
        return login_state_unavailable();
    }
    let mut resp = MetaHttpResponse::json(&started.url);
    let cookie = login_state_cookie(&started.state, LOGIN_STATE_MAX_AGE_SECS, &get_config());
    if let Ok(value) = header::HeaderValue::from_str(&cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, value);
    }
    resp
}

/// `GET /config/redirect`: the provider's callback. Every refusal is one generic 401.
pub async fn redirect(
    cookies: CookieJar,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let Some(zitadel) = o2_zitadel::zitadel() else {
        return status_only(StatusCode::NOT_FOUND);
    };
    let state = query.get("state").map(String::as_str);
    let cookie_state = cookies.get(LOGIN_STATE_COOKIE).map(|c| c.value());
    if !o2_zitadel::state_matches(cookie_state, state) {
        return refuse("state", false);
    }
    let pending = match take_pending(state.unwrap_or_default()).await {
        Ok(pending) => pending,
        Err(error) => {
            log::error!("failed to take zitadel login state: {error}");
            return login_state_unavailable();
        }
    };
    let code = query.get("code").map(String::as_str);
    match zitadel
        .finish(pending.as_deref(), code, query.contains_key("error"))
        .await
    {
        Ok(admitted) => complete(&admitted).await,
        Err(refusal) => refuse(refusal.class(), true),
    }
}

/// `GET /config/dex_refresh`: 200 while the session's ID token still verifies, else the session
/// is removed and the cookie cleared. The token is never rotated.
pub async fn refresh(cookies: CookieJar) -> Response {
    let Some(zitadel) = o2_zitadel::zitadel() else {
        return status_only(StatusCode::NOT_FOUND);
    };
    let session_id = session_id_of(&cookies);
    let stored = match &session_id {
        Some(id) => session::get_session(id).await,
        None => None,
    };
    if let Some(payload) = stored
        .as_deref()
        .and_then(|value| o2_zitadel::session_payload(value, true))
        && zitadel.verify_session(payload).await.is_ok()
    {
        return status_only(StatusCode::OK);
    }
    if let Some(id) = &session_id {
        session::remove_session(id).await;
    }
    let mut cookie = auth_cookie(&AuthTokens::default(), &get_config());
    cookie.set_max_age(time::Duration::seconds(
        db::password_policy::cookie_max_age_secs().await,
    ));
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::SET_COOKIE, cookie.to_string())
        .body(Body::empty())
        .unwrap()
}

/// Provision the user, open the session and send the browser to the UI callback.
async fn complete(admitted: &Admitted) -> Response {
    if let Err(class) = provision(admitted).await {
        return refuse(class, true);
    }
    let session_id = ider::uuid();
    if session::set_session(&session_id, &admitted.session_value())
        .await
        .is_none()
    {
        log::error!("failed to store zitadel session");
        return status_only(StatusCode::SERVICE_UNAVAILABLE);
    }
    let cfg = get_config();
    let tokens = AuthTokens {
        access_token: format!("session {session_id}"),
        refresh_token: String::new(),
    };
    let max_age = db::password_policy::cookie_max_age_secs().await;
    let mut auth = auth_cookie(&tokens, &cfg);
    auth.set_expires(time::OffsetDateTime::now_utc() + time::Duration::seconds(max_age));
    let id_token = json::to_string(&json::json!({
        "email": admitted.email,
        "name": admitted.name,
        "family_name": admitted.family_name,
        "given_name": admitted.given_name,
        "is_valid": true,
    }))
    .unwrap_or_default();
    let location = format!(
        "{}{}/web/cb#id_token={}.{}",
        cfg.common.web_url,
        cfg.common.base_uri,
        ID_TOKEN_HEADER,
        base64::encode(&id_token)
    );
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, auth.to_string())
        .header(
            header::SET_COOKIE,
            login_state_cookie("", 0, &cfg).to_string(),
        )
        .body(Body::empty())
        .unwrap()
}

/// Make the account exist in the row's org. The error is the refusal class to log.
async fn provision(admitted: &Admitted) -> Result<(), &'static str> {
    if is_root_user(&admitted.email) {
        return Err("root-user");
    }
    let role = user_role(admitted.role);
    match db::user::get_user_by_email(&admitted.email).await {
        Some(existing) => {
            if existing
                .organizations
                .iter()
                .any(|org| org.role.is_service_account())
            {
                return Err("service-account");
            }
            if existing
                .organizations
                .iter()
                .any(|org| org.name == admitted.o2_org)
            {
                return Ok(());
            }
            add_to_org(admitted, role).await
        }
        None => create_user(admitted, role).await,
    }
}

async fn add_to_org(admitted: &Admitted, role: UserRole) -> Result<(), &'static str> {
    let initiator = get_config().auth.root_user_email.clone();
    let role = UserOrgRole {
        base_role: role,
        custom_role: None,
    };
    match users::add_user_to_org(&admitted.o2_org, &admitted.email, role, &initiator).await {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            log::error!("zitadel user could not join org: status {}", resp.status());
            Err("provision")
        }
        Err(error) => {
            log::error!("zitadel user could not join org: {error}");
            Err("provision")
        }
    }
}

/// An external user has no password and no salt, so no password can ever match it.
async fn create_user(admitted: &Admitted, role: UserRole) -> Result<(), &'static str> {
    if let Err(error) = organization::check_and_create_org(&admitted.o2_org).await {
        log::error!("zitadel org could not be prepared: {error}");
        return Err("provision");
    }
    let (first_name, last_name) =
        if admitted.given_name.is_empty() && admitted.family_name.is_empty() {
            (admitted.name.clone(), String::new())
        } else {
            (admitted.given_name.clone(), admitted.family_name.clone())
        };
    let user = DBUser {
        email: admitted.email.clone(),
        first_name,
        last_name,
        password: String::new(),
        salt: String::new(),
        organizations: vec![UserOrg {
            name: admitted.o2_org.clone(),
            org_name: admitted.o2_org.clone(),
            token: generate_random_string(16),
            rum_token: Some(format!("rum{}", generate_random_string(16))),
            role,
        }],
        is_external: true,
        password_ext: Some(String::new()),
    };
    db::user::add(&user).await.map_err(|error| {
        log::error!("zitadel user could not be created: {error}");
        "provision"
    })
}

/// Delete expired pending logins; the count of those that remain.
async fn sweep_pending() -> Result<usize, anyhow::Error> {
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let mut remaining = 0;
    for key in kv::list(STATE_KV_ORG, "").await? {
        let expired = match kv::get_optional(STATE_KV_ORG, &key).await? {
            Some(record) => pending_expired(&String::from_utf8_lossy(&record), now),
            None => continue,
        };
        if expired {
            kv::delete(STATE_KV_ORG, &key).await?;
        } else {
            remaining += 1;
        }
    }
    Ok(remaining)
}

/// Take the pending login out of the store so exactly one callback can use it.
async fn take_pending(state: &str) -> Result<Option<String>, anyhow::Error> {
    let Some(saved) = kv::get_optional(STATE_KV_ORG, state).await? else {
        return Ok(None);
    };
    let taken = kv::compare_and_set(
        STATE_KV_ORG,
        state,
        Some(&saved),
        Bytes::from_static(STATE_USED),
    )
    .await?;
    if !taken {
        return Ok(None);
    }
    let _ = kv::delete(STATE_KV_ORG, state).await;
    Ok(String::from_utf8(saved.to_vec()).ok())
}

fn session_id_of(cookies: &CookieJar) -> Option<String> {
    let cookie = cookies.get("auth_tokens")?;
    let raw = base64::decode_raw(cookie.value()).ok()?;
    let tokens: AuthTokens = json::from_str(std::str::from_utf8(&raw).ok()?).ok()?;
    tokens
        .access_token
        .strip_prefix("session ")
        .map(str::to_string)
}

fn user_role(role: PolicyRole) -> UserRole {
    match role {
        PolicyRole::Admin => UserRole::Admin,
        PolicyRole::Editor => UserRole::Editor,
        PolicyRole::Viewer => UserRole::Viewer,
        PolicyRole::User => UserRole::User,
    }
}

/// The one body every refusal gets; the class goes to the log only.
fn refuse(class: &str, clear_state_cookie: bool) -> Response {
    log::warn!("zitadel login refused: {class}");
    let mut resp = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("\"Unauthorized\""))
        .unwrap();
    if clear_state_cookie
        && let Ok(value) =
            header::HeaderValue::from_str(&login_state_cookie("", 0, &get_config()).to_string())
    {
        resp.headers_mut().append(header::SET_COOKIE, value);
    }
    resp
}

fn status_only(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap()
}

fn login_state_unavailable() -> Response {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(Body::from("login state unavailable"))
        .unwrap()
}

fn auth_cookie(tokens: &AuthTokens, conf: &Config) -> Cookie<'static> {
    let value = base64::encode(&json::to_string(tokens).unwrap_or_default());
    let mut cookie = Cookie::new("auth_tokens", value);
    cookie.set_http_only(true);
    cookie.set_secure(conf.auth.cookie_secure_only);
    cookie.set_path("/");
    cookie.set_same_site(same_site(conf));
    cookie
}

fn login_state_cookie(state: &str, max_age_secs: i64, conf: &Config) -> Cookie<'static> {
    let mut cookie = Cookie::new(LOGIN_STATE_COOKIE, state.to_string());
    cookie.set_max_age(time::Duration::seconds(max_age_secs));
    cookie.set_http_only(true);
    cookie.set_secure(conf.auth.cookie_secure_only);
    cookie.set_path("/");
    cookie.set_same_site(same_site(conf));
    cookie
}

// Must ride the top-level GET back from the provider, so never Strict.
fn same_site(conf: &Config) -> SameSite {
    if conf.auth.cookie_same_site_lax {
        SameSite::Lax
    } else {
        SameSite::None
    }
}
