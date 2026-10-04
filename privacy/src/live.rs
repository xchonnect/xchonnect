//! Driving a relay that runs as a real process, over HTTP.
//!
//! Used by `scripts/privacy-scan.sh`, which starts the relay against Postgres and the
//! gateway with their logs redirected to files, runs the same [`crate::flow`] as the
//! in-process checks, and then scans the database dump, the log files and the metrics.

use crate::flow::{CLIENT_IP, Call, Transport, USER_AGENT};
use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;
use xchonnect_core::b64;

/// A blocking HTTP client that always sends the planted client identity.
#[derive(Debug)]
pub struct HttpTransport {
    base: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    /// Talk to the relay at `base` (no trailing slash).
    pub fn new(base: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        HttpTransport {
            base: base.trim_end_matches('/').to_owned(),
            agent,
        }
    }

    /// `GET path`, returning the body as text (for `/metrics`).
    pub fn text(&self, path: &str) -> Result<String, String> {
        let url = format!("{}{path}", self.base);
        let res = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| format!("GET {path}: {e}"))?;
        res.into_body()
            .read_to_string()
            .map_err(|e| format!("GET {path}: {e}"))
    }

    /// Headers every request carries: the planted client identity, plus the capability
    /// token and business key of this call.
    fn headers(call: &Call<'_>) -> Vec<(&'static str, String)> {
        let mut h = vec![
            ("user-agent", USER_AGENT.to_owned()),
            ("x-forwarded-for", CLIENT_IP.to_owned()),
            ("x-real-ip", CLIENT_IP.to_owned()),
            ("forwarded", format!("for={CLIENT_IP}")),
        ];
        if let Some(t) = call.token {
            h.push((
                "authorization",
                format!("Bearer {}", b64::encode(t.expose())),
            ));
        }
        if let Some(k) = call.api_key {
            h.push(("xchonnect-api-key", k.to_owned()));
        }
        h
    }

    fn blocking(&self, call: &Call<'_>) -> Result<(u16, Value), String> {
        let url = format!("{}{}", self.base, call.path);
        let headers = Self::headers(call);
        let res = match call.method {
            method @ ("GET" | "DELETE") => {
                let mut req = if method == "GET" {
                    self.agent.get(&url)
                } else {
                    self.agent.delete(&url)
                };
                for (name, value) in &headers {
                    req = req.header(*name, value);
                }
                req.call()
            }
            method @ ("POST" | "PUT") => {
                let mut req = if method == "POST" {
                    self.agent.post(&url)
                } else {
                    self.agent.put(&url)
                };
                for (name, value) in &headers {
                    req = req.header(*name, value);
                }
                match &call.body {
                    Some(body) => req
                        .header("content-type", "application/json")
                        .send(body.to_string()),
                    None => req.send_empty(),
                }
            }
            other => return Err(format!("unsupported method {other}")),
        }
        .map_err(|e| format!("{} {}: {e}", call.method, call.path))?;
        let status = res.status().as_u16();
        let text = res
            .into_body()
            .read_to_string()
            .map_err(|e| format!("{} {}: {e}", call.method, call.path))?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::Null)))
    }
}

#[async_trait]
impl Transport for HttpTransport {
    async fn call(&self, call: Call<'_>) -> Result<(u16, Value), String> {
        // The flow is async so that it can also run against an in-process router; this
        // client is blocking, which a multi-threaded runtime allows here.
        tokio::task::block_in_place(|| self.blocking(&call))
    }
}
