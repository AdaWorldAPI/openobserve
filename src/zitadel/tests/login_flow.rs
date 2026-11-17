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

//! The ZITADEL login flow against a fake provider: ES256 tokens signed with a real key and
//! checked by the real verifier. Only discovery, the JWKS and the token endpoint are in memory.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use o2_zitadel::{
    LOGIN_TTL_SECS, MAX_PENDING_LOGINS, OidcHttp, PolicyRole, Refusal, SESSION_SCHEME, Zitadel,
    ZitadelConfig, config::parse_policy, password_login_policy, pending_cap_reached,
    pending_expired, session_auth, session_payload, state_matches,
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://idp.example";
const CLIENT_ID: &str = "o2-client";
const REDIRECT: &str = "https://o2.example/config/redirect";
const ORG: &str = "300000000000000001";
const POLICY: &str = r#"[{"org":"300000000000000001","o2_org":"acme","role":"editor","email_domains":["example.com"]}]"#;

struct Fake {
    forms: Mutex<Vec<Vec<(String, String)>>>,
    id_token: Mutex<String>,
}

struct Handle(Arc<Fake>);

impl OidcHttp for Handle {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            if url == format!("{ISSUER}/.well-known/openid-configuration") {
                Ok(json!({
                    "issuer": ISSUER,
                    "authorization_endpoint": "https://idp.example/oauth/v2/authorize",
                    "token_endpoint": "https://idp.example/oauth/v2/token",
                    "jwks_uri": "https://idp.example/oauth/v2/keys",
                })
                .to_string()
                .into_bytes())
            } else if url == "https://idp.example/oauth/v2/keys" {
                Ok(jwks().into_bytes())
            } else {
                Err(format!("unexpected GET {url}"))
            }
        })
    }

    fn post_form<'a>(
        &'a self,
        url: &'a str,
        form: &'a [(&'a str, &'a str)],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            if url != "https://idp.example/oauth/v2/token" {
                return Err(format!("unexpected POST {url}"));
            }
            let got = form
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            self.0.forms.lock().unwrap().push(got);
            let t = self.0.id_token.lock().unwrap().clone();
            Ok(json!({ "id_token": t }).to_string().into_bytes())
        })
    }
}

fn key() -> SigningKey {
    SigningKey::from_slice(&[1u8; 32]).expect("valid scalar")
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn jwks() -> String {
    let sec1 = key().verifying_key().to_sec1_bytes();
    json!({"keys": [{
        "kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig",
        "x": b64(&sec1[1..33]), "y": b64(&sec1[33..]),
    }]})
    .to_string()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(nonce: &str) -> Value {
    json!({
        "iss": ISSUER, "sub": "user-1", "aud": CLIENT_ID,
        "iat": now(), "exp": now() + 300, "nonce": nonce,
        "email": "ada@example.com", "email_verified": true,
        "name": "Ada Lovelace", "given_name": "Ada", "family_name": "Lovelace",
        "urn:zitadel:iam:user:resourceowner:id": ORG,
    })
}

fn sign_with(alg: &str, claims: &Value) -> String {
    let header = json!({"alg": alg, "kid": "k1", "typ": "JWT"});
    let input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig: Signature = key().sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

fn config(policy: &str) -> ZitadelConfig {
    let vars: HashMap<&str, &str> = HashMap::from([
        ("O2_ZITADEL_ISSUER", ISSUER),
        ("O2_ZITADEL_CLIENT_ID", CLIENT_ID),
        ("O2_ZITADEL_REDIRECT_URL", REDIRECT),
        ("O2_ZITADEL_POLICY", policy),
    ]);
    ZitadelConfig::from_vars(|k| vars.get(k).map(|v| v.to_string()))
        .expect("config parses")
        .expect("enabled")
}

fn harness() -> (Zitadel, Arc<Fake>) {
    let fake = Arc::new(Fake {
        forms: Mutex::new(Vec::new()),
        id_token: Mutex::new(String::new()),
    });
    let z = Zitadel::new(config(POLICY), Box::new(Handle(fake.clone()))).expect("builds");
    (z, fake)
}

fn query(url: &str) -> HashMap<String, String> {
    let (_, q) = url.split_once('?').expect("url has a query");
    q.split('&')
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap();
            (
                urlencoding::decode(k).unwrap().into_owned(),
                urlencoding::decode(v).unwrap().into_owned(),
            )
        })
        .collect()
}

/// A whole sign-in: start, have the provider sign a token after `tweak`, finish.
async fn sign_in(tweak: impl FnOnce(&mut Value)) -> Result<o2_zitadel::Admitted, Refusal> {
    let (z, fake) = harness();
    let started = z.start().await.expect("starts");
    let nonce = query(&started.url)["nonce"].clone();
    let mut c = claims(&nonce);
    tweak(&mut c);
    *fake.id_token.lock().unwrap() = sign_with("ES256", &c);
    z.finish(Some(&started.pending), Some("c1"), false).await
}

#[tokio::test]
async fn authorize_url_carries_pkce_state_nonce_client_redirect_and_scopes() {
    let (z, fake) = harness();
    let started = z.start().await.expect("starts");
    assert!(
        started
            .url
            .starts_with("https://idp.example/oauth/v2/authorize?")
    );
    let q = query(&started.url);
    assert_eq!(q["response_type"], "code");
    assert_eq!(q["client_id"], CLIENT_ID);
    assert_eq!(q["redirect_uri"], REDIRECT);
    assert_eq!(
        q["scope"],
        "openid email profile urn:zitadel:iam:user:resourceowner"
    );
    assert_eq!(q["state"], started.state);
    assert_eq!(q["code_challenge_method"], "S256");
    assert!(!q["nonce"].is_empty());
    assert_ne!(q["state"], q["nonce"]);

    *fake.id_token.lock().unwrap() = sign_with("ES256", &claims(&q["nonce"]));
    z.finish(Some(&started.pending), Some("c1"), false)
        .await
        .expect("admitted");
    let form: HashMap<String, String> = fake.forms.lock().unwrap()[0].iter().cloned().collect();
    assert_eq!(
        q["code_challenge"],
        b64(&Sha256::digest(form["code_verifier"].as_bytes())),
        "the verifier sent to the token endpoint is the one the challenge commits to"
    );
    assert_eq!(form["code"], "c1");
    assert_eq!(form["redirect_uri"], REDIRECT);
}

#[tokio::test]
async fn a_valid_token_in_a_listed_org_and_domain_is_admitted_with_the_rows_org_and_role() {
    let a = sign_in(|_| {}).await.expect("admitted");
    assert_eq!(a.o2_org, "acme");
    assert_eq!(a.role, PolicyRole::Editor);
    assert_eq!(a.email, "ada@example.com");
    assert_eq!(a.sub, "user-1");
    assert_eq!(a.family_name, "Lovelace");
}

#[tokio::test]
async fn a_replayed_or_missing_state_is_refused() {
    let (z, _) = harness();
    let r = z.finish(None, Some("c1"), false).await;
    assert_eq!(r.unwrap_err(), Refusal::State);
}

#[tokio::test]
async fn an_expired_pending_login_is_refused() {
    let (z, _) = harness();
    let old = json!({"verifier": "v", "nonce": "n", "created": now() - 601}).to_string();
    let r = z.finish(Some(&old), Some("c1"), false).await;
    assert_eq!(r.unwrap_err(), Refusal::State);
}

#[test]
fn a_cookie_state_that_differs_from_the_query_state_is_refused() {
    assert!(state_matches(Some("abc"), Some("abc")));
    assert!(!state_matches(Some("abc"), Some("abd")));
    assert!(!state_matches(Some("abc"), None));
    assert!(!state_matches(None, Some("abc")));
    assert!(!state_matches(Some(""), Some("")));
}

#[tokio::test]
async fn a_provider_error_instead_of_a_code_is_refused() {
    let (z, _) = harness();
    let started = z.start().await.unwrap();
    let r = z.finish(Some(&started.pending), None, true).await;
    assert_eq!(r.unwrap_err(), Refusal::Provider);
}

#[tokio::test]
async fn a_wrong_nonce_is_refused() {
    let r = sign_in(|c| c["nonce"] = json!("someone-elses")).await;
    assert_eq!(r.unwrap_err(), Refusal::Token);
}

#[tokio::test]
async fn a_wrong_audience_is_refused() {
    let r = sign_in(|c| c["aud"] = json!("another-client")).await;
    assert_eq!(r.unwrap_err(), Refusal::Token);
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let r = sign_in(|c| c["exp"] = json!(now() - 3600)).await;
    assert_eq!(r.unwrap_err(), Refusal::Token);
}

#[tokio::test]
async fn an_rs256_token_is_refused() {
    let (z, fake) = harness();
    let started = z.start().await.unwrap();
    let nonce = query(&started.url)["nonce"].clone();
    *fake.id_token.lock().unwrap() = sign_with("RS256", &claims(&nonce));
    let r = z.finish(Some(&started.pending), Some("c1"), false).await;
    assert_eq!(r.unwrap_err(), Refusal::Token);
}

#[tokio::test]
async fn an_unverified_email_is_refused() {
    let r = sign_in(|c| c["email_verified"] = json!(false)).await;
    assert_eq!(r.unwrap_err(), Refusal::UnverifiedEmail);
}

#[tokio::test]
async fn an_organization_the_policy_does_not_list_is_refused() {
    let r = sign_in(|c| c["urn:zitadel:iam:user:resourceowner:id"] = json!("999")).await;
    assert_eq!(r.unwrap_err(), Refusal::UnknownOrg);
}

#[tokio::test]
async fn a_token_without_an_organization_is_refused() {
    let r = sign_in(|c| {
        c.as_object_mut()
            .unwrap()
            .remove("urn:zitadel:iam:user:resourceowner:id");
    })
    .await;
    assert_eq!(r.unwrap_err(), Refusal::UnknownOrg);
}

#[tokio::test]
async fn an_email_domain_outside_the_row_is_refused() {
    let r = sign_in(|c| c["email"] = json!("ada@evil.example")).await;
    assert_eq!(r.unwrap_err(), Refusal::Domain);
}

#[test]
fn a_policy_row_with_a_reserved_role_is_refused_at_parse() {
    for role in ["root", "service_account", "sre_agent"] {
        let text = format!(
            r#"[{{"org":"1","o2_org":"acme","role":"{role}","email_domains":["example.com"]}}]"#
        );
        assert!(parse_policy(&text).is_err(), "{role}");
    }
    assert!(parse_policy(POLICY).is_ok());
}

#[test]
fn a_duplicate_org_is_refused_at_parse() {
    let row = r#"{"org":"1","o2_org":"acme","role":"viewer","email_domains":["example.com"]}"#;
    assert!(parse_policy(&format!("[{row},{row}]")).is_err());
    assert!(parse_policy(&format!("[{row}]")).is_ok());
}

#[test]
fn an_unknown_policy_field_is_refused_at_parse() {
    let text = r#"[{"org":"1","o2_org":"acme","role":"viewer","email_domains":["example.com"],"extra":1}]"#;
    assert!(parse_policy(text).is_err());
}

#[tokio::test]
async fn a_stored_session_verifies_to_its_email_and_an_expired_one_does_not() {
    let a = sign_in(|_| {}).await.expect("admitted");
    let value = a.session_value();
    let payload = session_payload(&value, true).expect("session value carries the scheme");
    let (z, _) = harness();
    let again = z.verify_session(payload).await.expect("still valid");
    assert_eq!(again.email, "ada@example.com");

    let expired = json!({
        "id_token": sign_with("ES256", &{
            let mut c = claims("n1");
            c["exp"] = json!(now() - 3600);
            c
        }),
        "nonce": "n1",
    })
    .to_string();
    assert_eq!(
        z.verify_session(&expired).await.unwrap_err(),
        Refusal::Token
    );
}

#[test]
fn the_session_scheme_is_taken_only_from_a_server_side_session() {
    let raw = format!("{SESSION_SCHEME}{{\"id_token\":\"x\",\"nonce\":\"y\"}}");
    assert!(session_payload(&raw, true).is_some());
    assert!(session_payload(&raw, false).is_none());
    assert!(session_payload("Basic abc", true).is_none());
}

#[test]
fn only_a_zitadel_session_value_gets_the_session_marker() {
    let stored = format!("{SESSION_SCHEME}{{}}");
    assert_eq!(
        session_auth("Session::", "sid", &stored).as_deref(),
        Some("Session::sid::Zitadel {}")
    );
    assert!(session_auth("Session::", "sid", "Basic abc").is_none());
}

#[test]
fn password_login_is_root_only_with_break_glass_once_native_login_is_off() {
    // (native_login, root_break_glass)
    assert!(
        password_login_policy(None, false),
        "inactive: nobody is refused"
    );
    assert!(
        password_login_policy(Some((true, true)), false),
        "native on"
    );
    assert!(
        password_login_policy(Some((false, true)), true),
        "root break-glass"
    );
    assert!(
        !password_login_policy(Some((false, true)), false),
        "non-root refused"
    );
    assert!(
        !password_login_policy(Some((false, false)), true),
        "break-glass off"
    );
}

#[test]
fn pending_login_expires_at_the_ttl_and_unreadable_records_are_expired() {
    let record = |created: u64| format!(r#"{{"verifier":"v","nonce":"n","created":{created}}}"#);
    let now = 10_000;
    assert!(!pending_expired(&record(now), now), "fresh");
    assert!(
        !pending_expired(&record(now - LOGIN_TTL_SECS + 1), now),
        "just inside"
    );
    assert!(
        pending_expired(&record(now - LOGIN_TTL_SECS), now),
        "at the ttl"
    );
    assert!(pending_expired(&record(0), now), "old");
    assert!(pending_expired("used", now), "consumed marker");
    assert!(pending_expired("", now), "empty");
}

#[test]
fn pending_login_cap_refuses_only_past_the_limit() {
    assert!(!pending_cap_reached(0));
    assert!(!pending_cap_reached(MAX_PENDING_LOGINS));
    assert!(pending_cap_reached(MAX_PENDING_LOGINS + 1));
}
