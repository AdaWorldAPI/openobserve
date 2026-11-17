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
    sync::RwLock,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ogar_auth::{
    federation::{AssertionVerifier, LoginError, TrustedIssuers, VerifiedClaims, establish},
    identity::ExternalIdentity,
    user::{AuthBinding, ProviderId, User, UserId, UserStore},
};
use ogar_oidc::{Client, Discovery, IdToken, KeySet, OidcError, OidcVerifier};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    config::{ConfigError, ORG_SCOPE, PolicyRole, ZitadelConfig},
    http::{OidcHttp, ReqwestHttp},
};

/// How long a started login may take.
pub const LOGIN_TTL_SECS: u64 = 600;
/// Pending logins kept at once; past it a new login is refused rather than stored.
pub const MAX_PENDING_LOGINS: usize = 10_000;
/// Prefix of the session value; the validator takes this scheme only from a server-side session.
pub const SESSION_SCHEME: &str = "Zitadel ";
const PROVIDER: ProviderId = ProviderId("zitadel");

/// Why a login or a session was refused. Only [`Refusal::class`] is ever logged or shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No, mismatching, replayed or expired `state`.
    State,
    /// The provider returned an error instead of a code.
    Provider,
    /// Discovery, JWKS or the token endpoint failed.
    Upstream,
    /// The ID token did not verify.
    Token,
    /// The token names no organization, or one the policy does not list.
    UnknownOrg,
    /// The verified email is not in the organization's domains.
    Domain,
    /// The provider did not mark the email verified, or sent none.
    UnverifiedEmail,
}

impl Refusal {
    pub fn class(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Provider => "provider",
            Self::Upstream => "upstream",
            Self::Token => "token",
            Self::UnknownOrg => "unknown-org",
            Self::Domain => "domain",
            Self::UnverifiedEmail => "unverified-email",
        }
    }
}

/// A started login: the authorize URL, the `state` for the cookie and the server-side record to
/// keep under `state` until the callback consumes it.
pub struct Started {
    pub url: String,
    pub state: String,
    pub pending: String,
}

/// A login the policy admitted. Built only from an ID token `establish` accepted.
#[derive(Debug, Clone)]
pub struct Admitted {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub o2_org: String,
    pub role: PolicyRole,
    id_token: String,
    nonce: String,
}

impl Admitted {
    /// The value to store in the session: `Zitadel ` and the ID token with its nonce, enough to
    /// verify it again on every request.
    pub fn session_value(&self) -> String {
        let payload = SessionPayload {
            id_token: self.id_token.clone(),
            nonce: self.nonce.clone(),
        };
        format!(
            "{SESSION_SCHEME}{}",
            serde_json::to_string(&payload).unwrap_or_default()
        )
    }
}

/// The sign-in state of one process: configuration, provider access and key cache.
pub struct Zitadel {
    cfg: ZitadelConfig,
    http: Box<dyn OidcHttp>,
    trusted: TrustedIssuers,
    endpoints: RwLock<Option<Endpoints>>,
    verifier: RwLock<OidcVerifier>,
}

impl Zitadel {
    pub fn new(cfg: ZitadelConfig, http: Box<dyn OidcHttp>) -> Result<Self, ConfigError> {
        let mut trusted = TrustedIssuers::new();
        trusted
            .insert(cfg.issuer.clone(), PROVIDER)
            .map_err(|_| ConfigError("issuer registered twice".to_string()))?;
        let mut verifier = OidcVerifier::new();
        verifier.add_client(Client::new(
            cfg.issuer.clone(),
            cfg.client_id.clone(),
            KeySet::default(),
        ));
        Ok(Self {
            cfg,
            http,
            trusted,
            endpoints: RwLock::new(None),
            verifier: RwLock::new(verifier),
        })
    }

    /// `Ok(None)` when ZITADEL login is not configured.
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let Some(cfg) = ZitadelConfig::from_vars(|k| std::env::var(k).ok())? else {
            return Ok(None);
        };
        let http = ReqwestHttp::new().map_err(ConfigError)?;
        Self::new(cfg, Box::new(http)).map(Some)
    }

    pub fn config(&self) -> &ZitadelConfig {
        &self.cfg
    }

    /// Start a login: PKCE verifier, `state` and `nonce`, and the authorize URL.
    pub async fn start(&self) -> Result<Started, Refusal> {
        let ep = self.endpoints().await?;
        let state = random_token();
        let nonce = random_token();
        let verifier = random_token();
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let pending = serde_json::to_string(&Pending {
            verifier,
            nonce: nonce.clone(),
            created: now_unix(),
        })
        .map_err(|_| Refusal::Upstream)?;
        let scope = format!("openid email profile {ORG_SCOPE}");
        let q = [
            ("response_type", "code"),
            ("client_id", self.cfg.client_id.as_str()),
            ("redirect_uri", self.cfg.redirect_url.as_str()),
            ("scope", scope.as_str()),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        let query = q
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let sep = if ep.authorization.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(Started {
            url: format!("{}{sep}{query}", ep.authorization),
            state,
            pending,
        })
    }

    /// Finish a login. `pending` is the record [`Zitadel::start`] returned, already taken out of
    /// the store (single use); `None` means the state was unknown or replayed.
    pub async fn finish(
        &self,
        pending: Option<&str>,
        code: Option<&str>,
        provider_error: bool,
    ) -> Result<Admitted, Refusal> {
        let pending: Pending = pending
            .and_then(|p| serde_json::from_str(p).ok())
            .ok_or(Refusal::State)?;
        if now_unix().saturating_sub(pending.created) >= LOGIN_TTL_SECS {
            return Err(Refusal::State);
        }
        if provider_error {
            return Err(Refusal::Provider);
        }
        let code = code.filter(|c| !c.is_empty()).ok_or(Refusal::Provider)?;
        let ep = self.endpoints().await?;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.cfg.redirect_url.as_str()),
            ("client_id", self.cfg.client_id.as_str()),
            ("code_verifier", pending.verifier.as_str()),
        ];
        if let Some(s) = &self.cfg.client_secret {
            form.push(("client_secret", s.as_str()));
        }
        let resp = self
            .http
            .post_form(&ep.token, &form)
            .await
            .map_err(|_| Refusal::Upstream)?;
        let v: Value = serde_json::from_slice(&resp).map_err(|_| Refusal::Upstream)?;
        let token = v
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or(Refusal::Upstream)?;
        self.admit(token, &pending.nonce).await
    }

    /// Verify the ID token a session stores (`payload` is the value after [`SESSION_SCHEME`])
    /// as at sign-in: signature, issuer, audience, expiry, nonce and the policy.
    pub async fn verify_session(&self, payload: &str) -> Result<Admitted, Refusal> {
        let p: SessionPayload = serde_json::from_str(payload).map_err(|_| Refusal::Token)?;
        self.admit(&p.id_token, &p.nonce).await
    }

    async fn admit(&self, token: &str, nonce: &str) -> Result<Admitted, Refusal> {
        let claims = self.verify_claims(token, nonce).await?;
        let email = claims.email.clone().ok_or(Refusal::UnverifiedEmail)?;
        let payload = payload_claims(token).ok_or(Refusal::Token)?;
        let org = payload
            .get(self.cfg.org_claim.as_str())
            .and_then(Value::as_str)
            .ok_or(Refusal::UnknownOrg)?;
        let row = self.cfg.tenant(org).ok_or(Refusal::UnknownOrg)?;
        let domain = email_domain(&email).ok_or(Refusal::Domain)?;
        if !row.email_domains.contains(&domain) {
            return Err(Refusal::Domain);
        }
        let sub = claims.identity.subject().as_str().to_string();
        let store = GrantedStore {
            identity: claims.identity.clone(),
            user: User {
                id: UserId(0),
                subject: sub.clone(),
                tenant: org.parse().unwrap_or(0),
                roles: Vec::new(),
                memberships: Vec::new(),
                bindings: Vec::new(),
                key_refs: Vec::new(),
            },
        };
        let input = id_token_input(token, nonce);
        {
            let v = self.verifier.read().expect("verifier lock");
            establish(&*v, &self.trusted, &input, &store).map_err(|e| match e {
                LoginError::Verify(_) | LoginError::UntrustedIssuer | LoginError::Unbound => {
                    Refusal::Token
                }
            })?;
        }
        let text = |k: &str| {
            payload
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Ok(Admitted {
            sub,
            name: payload
                .get("name")
                .and_then(Value::as_str)
                .map_or_else(|| email.clone(), str::to_string),
            given_name: text("given_name"),
            family_name: text("family_name"),
            email,
            o2_org: row.o2_org.clone(),
            role: row.role,
            id_token: token.to_string(),
            nonce: nonce.to_string(),
        })
    }

    /// Verify an ID token, refetching the JWKS once on an unknown key (key rotation).
    async fn verify_claims(&self, token: &str, nonce: &str) -> Result<VerifiedClaims, Refusal> {
        let input = id_token_input(token, nonce);
        match self.verify_once(&input) {
            Err(OidcError::UnknownKey) => {
                self.refresh_keys().await?;
                self.verify_once(&input).map_err(|_| Refusal::Token)
            }
            other => other.map_err(|_| Refusal::Token),
        }
    }

    fn verify_once(&self, input: &IdToken) -> Result<VerifiedClaims, OidcError> {
        let v = self.verifier.read().expect("verifier lock");
        v.verify(&self.trusted, input)
    }

    async fn endpoints(&self) -> Result<Endpoints, Refusal> {
        if let Some(e) = self.endpoints.read().expect("endpoints lock").clone() {
            return Ok(e);
        }
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.cfg.issuer.as_str().trim_end_matches('/')
        );
        let doc = self.http.get(&url).await.map_err(|_| Refusal::Upstream)?;
        let d = Discovery::from_json(&self.cfg.issuer, &doc).map_err(|_| Refusal::Upstream)?;
        let v: Value = serde_json::from_slice(&doc).map_err(|_| Refusal::Upstream)?;
        let field = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .filter(|u| u.starts_with("https://"))
                .map(str::to_string)
                .ok_or(Refusal::Upstream)
        };
        let e = Endpoints {
            authorization: field("authorization_endpoint")?,
            token: field("token_endpoint")?,
            jwks: d.jwks_uri,
        };
        *self.endpoints.write().expect("endpoints lock") = Some(e.clone());
        Ok(e)
    }

    async fn refresh_keys(&self) -> Result<(), Refusal> {
        let ep = self.endpoints().await?;
        let doc = self
            .http
            .get(&ep.jwks)
            .await
            .map_err(|_| Refusal::Upstream)?;
        let keys = KeySet::from_jwks_json(&doc).map_err(|_| Refusal::Upstream)?;
        let mut v = self.verifier.write().expect("verifier lock");
        if let Some(c) = v.client_mut(&self.cfg.issuer) {
            c.set_keys(keys);
        }
        Ok(())
    }
}

/// Endpoints read from discovery.
#[derive(Clone)]
struct Endpoints {
    authorization: String,
    token: String,
    jwks: String,
}

/// What `start` keeps server-side under `state`.
#[derive(Serialize, Deserialize)]
struct Pending {
    verifier: String,
    nonce: String,
    created: u64,
}

/// What a session stores: enough to verify the ID token again.
#[derive(Serialize, Deserialize)]
struct SessionPayload {
    id_token: String,
    nonce: String,
}

/// The one-user store a login resolves against: `user` for exactly `identity`.
struct GrantedStore {
    identity: ExternalIdentity,
    user: User,
}

impl UserStore for GrantedStore {
    fn resolve(&self, _binding: &AuthBinding) -> Option<&User> {
        None
    }

    fn user(&self, id: UserId) -> Option<&User> {
        (id == self.user.id).then_some(&self.user)
    }

    fn resolve_external(&self, id: &ExternalIdentity) -> Option<&User> {
        (id == &self.identity).then_some(&self.user)
    }
}

/// Whether a stored pending record is past [`LOGIN_TTL_SECS`] at `now`. An unreadable record
/// (including a consumed-state marker) can never finish a login, so it counts as expired.
pub fn pending_expired(record: &str, now: u64) -> bool {
    serde_json::from_str::<Pending>(record)
        .map(|p| now.saturating_sub(p.created) >= LOGIN_TTL_SECS)
        .unwrap_or(true)
}

/// Whether `remaining` pending logins, after the expired ones are swept, leave no room.
pub fn pending_cap_reached(remaining: usize) -> bool {
    remaining > MAX_PENDING_LOGINS
}

fn id_token_input(token: &str, nonce: &str) -> IdToken {
    IdToken {
        token: token.to_string(),
        now_unix: now_unix(),
        nonce: Some(nonce.to_string()),
    }
}

/// The claims of an ID token the verifier has already accepted.
fn payload_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

/// Lowercased domain of `email`, `None` without a local part or a domain.
fn email_domain(email: &str) -> Option<String> {
    let (local, domain) = email.rsplit_once('@')?;
    (!local.is_empty() && !domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rng().fill(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
