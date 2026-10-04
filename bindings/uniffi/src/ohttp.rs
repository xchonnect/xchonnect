//! Oblivious HTTP client for wallets (spec 10, TASK-52).
//!
//! The wallet sends relay (and node) requests through an independent OHTTP relay: build
//! the inner request, [`OhttpClient::encapsulate`] it, `POST` the bytes to the OHTTP
//! relay with `Content-Type: message/ohttp-req` using the platform HTTP stack, and pass
//! the response body to [`OhttpResponseContext::decapsulate`].
//!
//! Key pinning: ship the relay operator's key configuration with the app
//! ([`ohttp_select_key`] turns a published list into a pin). To follow a rotation, fetch
//! `GET /.well-known/ohttp-keys` *through* the client and call [`ohttp_rotate_key`]; an
//! [`XchonnectError::OhttpKeyMismatch`] is a hard error (never fall back to direct
//! requests or an unpinned key silently).
//!
//! Encapsulated bodies and key configurations are raw bytes (HTTP bodies).

use crate::error::{Result, XchonnectError};
use std::sync::{Arc, Mutex};
use xchonnect_core::crypto::OsEntropy;
use xchonnect_core::ohttp as core_ohttp;

/// An HTTP header field.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct HttpHeader {
    /// Field name.
    pub name: String,
    /// Field value.
    pub value: String,
}

/// An inner HTTP request to encapsulate.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OhttpRequest {
    /// Method, e.g. `GET`.
    pub method: String,
    /// Scheme of the target (`https`).
    pub scheme: String,
    /// Authority of the target relay (host and optional port).
    pub authority: String,
    /// Path and query, starting with `/`.
    pub path: String,
    /// Header fields (e.g. `authorization`, `content-type`).
    pub headers: Vec<HttpHeader>,
    /// Content (empty for none).
    pub body: Vec<u8>,
}

/// A decapsulated inner HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct OhttpResponse {
    /// Status code.
    pub status: u16,
    /// Header fields (lowercase names).
    pub headers: Vec<HttpHeader>,
    /// Content.
    pub body: Vec<u8>,
}

/// An encapsulated request: send `body`, decapsulate the answer with `context`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct OhttpEncapsulated {
    /// The `message/ohttp-req` body to `POST` to the OHTTP relay.
    pub body: Vec<u8>,
    /// Single-use response context.
    pub context: Arc<OhttpResponseContext>,
}

/// OHTTP client for one pinned gateway key configuration.
#[derive(Debug, uniffi::Object)]
pub struct OhttpClient {
    inner: core_ohttp::Client,
}

#[uniffi::export]
impl OhttpClient {
    /// Client for an encoded key configuration (a pin from [`ohttp_select_key`] or
    /// [`ohttp_rotate_key`]).
    #[uniffi::constructor]
    pub fn new(key_config: Vec<u8>) -> Result<Arc<Self>> {
        Ok(Arc::new(OhttpClient {
            inner: core_ohttp::Client::new(core_ohttp::KeyConfig::decode(&key_config)?),
        }))
    }

    /// Key identifier of the pinned configuration.
    pub fn key_id(&self) -> u8 {
        self.inner.config().key_id()
    }

    /// Encode the request as binary HTTP and encapsulate it.
    pub fn encapsulate(&self, request: OhttpRequest) -> Result<OhttpEncapsulated> {
        let headers: Vec<(String, String)> = request
            .headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect();
        let req = core_ohttp::Request {
            method: &request.method,
            scheme: &request.scheme,
            authority: &request.authority,
            path: &request.path,
            headers: &headers,
            body: &request.body,
        };
        let (body, ctx) = self.inner.encapsulate(&mut OsEntropy, &req)?;
        Ok(OhttpEncapsulated {
            body,
            context: Arc::new(OhttpResponseContext {
                inner: Mutex::new(Some(ctx)),
            }),
        })
    }
}

/// Decapsulates the response to one request.
#[derive(Debug, uniffi::Object)]
pub struct OhttpResponseContext {
    inner: Mutex<Option<core_ohttp::ResponseContext>>,
}

#[uniffi::export]
impl OhttpResponseContext {
    /// Decrypt the `message/ohttp-res` body. Can be called once; a tampered or foreign
    /// response gives `Decrypt`.
    pub fn decapsulate(&self, response: Vec<u8>) -> Result<OhttpResponse> {
        let ctx = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| XchonnectError::State("OHTTP response already decapsulated".into()))?;
        let r = ctx.decapsulate(&response)?;
        Ok(OhttpResponse {
            status: r.status,
            headers: r
                .headers
                .into_iter()
                .map(|(name, value)| HttpHeader { name, value })
                .collect(),
            body: r.body,
        })
    }
}

/// The configuration to pin from an `application/ohttp-keys` list obtained out of band
/// (newest usable entry).
#[uniffi::export]
pub fn ohttp_select_key(key_configs: Vec<u8>) -> Result<Vec<u8>> {
    Ok(core_ohttp::select(&key_configs)?.encoded().to_vec())
}

/// Check a fetched key configuration list against the pin; returns the new pin (the
/// newest entry). `OhttpKeyMismatch` when the list no longer contains the pinned key.
#[uniffi::export]
pub fn ohttp_rotate_key(pinned: Vec<u8>, key_configs: Vec<u8>) -> Result<Vec<u8>> {
    let pinned = core_ohttp::KeyConfig::decode(&pinned)?;
    Ok(core_ohttp::rotate(&pinned, &key_configs)?
        .encoded()
        .to_vec())
}
