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

use std::{future::Future, pin::Pin, time::Duration};

type HttpFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

/// The two provider calls the flow makes, so tests can run it without a network.
pub trait OidcHttp: Send + Sync {
    fn get<'a>(&'a self, url: &'a str) -> HttpFuture<'a>;
    fn post_form<'a>(&'a self, url: &'a str, form: &'a [(&'a str, &'a str)]) -> HttpFuture<'a>;
}

/// reqwest over rustls, 10 s timeout, https only, no redirects followed.
pub struct ReqwestHttp(reqwest::Client);

impl ReqwestHttp {
    pub fn new() -> Result<Self, String> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map(Self)
            .map_err(|_| "http client could not be built".to_string())
    }
}

impl OidcHttp for ReqwestHttp {
    fn get<'a>(&'a self, url: &'a str) -> HttpFuture<'a> {
        Box::pin(async move { body(self.0.get(url).send().await).await })
    }

    fn post_form<'a>(&'a self, url: &'a str, form: &'a [(&'a str, &'a str)]) -> HttpFuture<'a> {
        Box::pin(async move { body(self.0.post(url).form(form).send().await).await })
    }
}

async fn body(r: reqwest::Result<reqwest::Response>) -> Result<Vec<u8>, String> {
    let r = r.map_err(|_| "request failed".to_string())?;
    if !r.status().is_success() {
        return Err(format!("status {}", r.status().as_u16()));
    }
    r.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|_| "body read failed".to_string())
}
