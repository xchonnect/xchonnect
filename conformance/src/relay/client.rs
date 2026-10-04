//! Minimal blocking HTTP client for talking to a relay under test.

use serde_json::Value;
use std::sync::Mutex;
use std::time::Duration;
use ureq::http;

/// A fully read HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resp {
    pub(crate) status: u16,
    /// Header names lowercased, in the order received.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Resp {
    /// First value of a header (name is case-insensitive).
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Body parsed as JSON (`Null` if empty or not JSON).
    pub(crate) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// Body as lossy UTF-8, truncated for messages.
    pub(crate) fn body_text(&self) -> String {
        let s = String::from_utf8_lossy(&self.body);
        let mut out: String = s.chars().take(200).collect();
        if s.chars().count() > 200 {
            out.push('…');
        }
        out
    }

    /// Headers that must match for byte-identical responses (everything except `Date`),
    /// sorted so that header order does not matter.
    pub(crate) fn comparable_headers(&self) -> Vec<(String, String)> {
        let mut h: Vec<_> = self
            .headers
            .iter()
            .filter(|(k, _)| k != "date")
            .cloned()
            .collect();
        h.sort();
        h
    }

    /// Short description for failure messages.
    pub(crate) fn describe(&self) -> String {
        format!("HTTP {} {}", self.status, self.body_text())
    }
}

/// A request to send.
#[derive(Debug, Clone)]
pub(crate) struct Req {
    pub(crate) method: &'static str,
    pub(crate) path: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<Vec<u8>>,
}

impl Req {
    pub(crate) fn new(method: &'static str, path: impl Into<String>) -> Self {
        Req {
            method,
            path: path.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub(crate) fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_owned(), v.into()));
        self
    }

    pub(crate) fn bearer(self, token: &[u8]) -> Self {
        let v = format!("Bearer {}", xchonnect_core::b64::encode(token));
        self.header("authorization", v)
    }

    pub(crate) fn json(self, v: &Value) -> Self {
        self.raw_json(v.to_string().into_bytes())
    }

    pub(crate) fn raw_json(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self.header("content-type", "application/json")
    }
}

/// HTTP client bound to one relay base URL.
#[derive(Debug)]
pub(crate) struct Client {
    base: String,
    agent: ureq::Agent,
    /// Paths of responses that carried `Set-Cookie` (relays must never set cookies).
    pub(crate) cookies_seen: Mutex<Vec<String>>,
}

impl Client {
    pub(crate) fn new(base: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(90)))
            .build()
            .into();
        Client {
            base: base.trim_end_matches('/').to_owned(),
            agent,
            cookies_seen: Mutex::new(Vec::new()),
        }
    }

    /// Send a request; transport errors are returned as text.
    pub(crate) fn send(&self, req: &Req) -> Result<Resp, String> {
        let url = format!("{}{}", self.base, req.path);
        let mut b = http::Request::builder().method(req.method).uri(&url);
        for (k, v) in &req.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        let res = match &req.body {
            None => self.run(b, ()),
            Some(body) => self.run(b, body.clone()),
        }
        .map_err(|e| format!("{} {}: {e}", req.method, req.path))?;
        let status = res.status().as_u16();
        let headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .map(|(k, v)| {
                let v = String::from_utf8_lossy(v.as_bytes()).into_owned();
                (k.as_str().to_ascii_lowercase(), v)
            })
            .collect();
        let body = res
            .into_body()
            .with_config()
            .limit(16 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| format!("{} {}: reading body: {e}", req.method, req.path))?;
        if headers.iter().any(|(k, _)| k == "set-cookie") {
            self.cookies_seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(format!("{} {}", req.method, req.path));
        }
        Ok(Resp {
            status,
            headers,
            body,
        })
    }

    fn run<B: ureq::AsSendBody>(
        &self,
        b: http::request::Builder,
        body: B,
    ) -> Result<http::Response<ureq::Body>, String> {
        let req = b.body(body).map_err(|e| e.to_string())?;
        self.agent.run(req).map_err(|e| e.to_string())
    }
}
