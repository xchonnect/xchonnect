//! The dApp side of origin verification (spec 6.1): an Ed25519 origin key and a tiny
//! HTTP server that publishes `/.well-known/xchonnect.json`.
//!
//! The document is swapped between checks, so the same wallet can be shown a correct
//! document, a forged one, one with an expired or unknown key, a malformed one, or none
//! at all. Nothing else is served, no redirect is ever sent and the connection is closed
//! after one request, which is what a wallet's fetch rules expect.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use xchonnect_core::b64;
use xchonnect_core::crypto::{Ed25519Seed, OsEntropy};
use xchonnect_core::uri::LocalSigner;

/// Path of the origin document (spec 6.1).
pub(crate) const WELL_KNOWN: &str = "/.well-known/xchonnect.json";
/// Longest request head the server reads before giving up.
const MAX_HEAD: usize = 8 * 1024;

/// What the server answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Served {
    /// `200` with this body.
    Body(Vec<u8>),
    /// `404`, as for a dApp that publishes no document.
    NotFound,
}

/// A running origin-document server.
#[derive(Debug)]
pub(crate) struct OriginServer {
    addr: SocketAddr,
    served: Arc<Mutex<Served>>,
    /// Number of requests answered, so a check can tell whether the wallet fetched at all.
    fetches: Arc<Mutex<usize>>,
}

impl OriginServer {
    /// Bind `listen` (e.g. `127.0.0.1:0`) and start serving in a background thread.
    pub(crate) fn start(listen: &str, initial: Served) -> Result<Self, String> {
        let listener =
            TcpListener::bind(listen).map_err(|e| format!("cannot bind {listen}: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("cannot read the listen address: {e}"))?;
        let served = Arc::new(Mutex::new(initial));
        let fetches = Arc::new(Mutex::new(0));
        let (s, f) = (Arc::clone(&served), Arc::clone(&fetches));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let body = lock(&s).clone();
                *lock(&f) += 1;
                let _ = answer(stream, &body);
            }
        });
        Ok(OriginServer {
            addr,
            served,
            fetches,
        })
    }

    /// Address the server listens on.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Replace the document served from now on.
    pub(crate) fn serve(&self, what: Served) {
        *lock(&self.served) = what;
    }

    /// Requests answered so far.
    pub(crate) fn fetches(&self) -> usize {
        *lock(&self.fetches)
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Read one request head and answer it.
fn answer(mut stream: TcpStream, served: &Served) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < MAX_HEAD {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        head.push(*byte.first().unwrap_or(&0));
    }
    let request = String::from_utf8_lossy(&head);
    let wanted = request
        .split_whitespace()
        .nth(1)
        .is_some_and(|p| p == WELL_KNOWN);
    let response = match served {
        Served::Body(body) if wanted => {
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 cache-control: no-store\r\naccess-control-allow-origin: *\r\nconnection: close\r\n\r\n",
                body.len()
            );
            [head.into_bytes(), body.clone()].concat()
        }
        _ => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec(),
    };
    stream.write_all(&response)?;
    stream.flush()
}

/// The dApp's origin key and the documents the suite publishes for it.
#[derive(Debug)]
pub(crate) struct Origin {
    /// Signs pairing URIs.
    pub(crate) signer: LocalSigner,
    /// dApp display name in the document.
    pub(crate) name: String,
    kid: String,
}

/// Key id the suite publishes.
const KID: &str = "conformance-1";

impl Origin {
    /// A fresh random origin key.
    pub(crate) fn random(name: &str) -> Result<Self, String> {
        let signer = LocalSigner::new(Ed25519Seed::random(&mut OsEntropy), KID)
            .map_err(|e| format!("cannot create the origin key: {e}"))?;
        Ok(Origin {
            signer,
            name: name.to_owned(),
            kid: KID.to_owned(),
        })
    }

    /// The correct document: this suite's key under the kid the URIs reference.
    pub(crate) fn good(&self) -> Served {
        self.document(&self.kid, &self.signer.public_key(), FAR_FUTURE)
    }

    /// A document that publishes a different key under the same kid: every signature the
    /// suite produces is then a forgery from the wallet's point of view.
    pub(crate) fn forged_key(&self) -> Served {
        self.document(&self.kid, &[0x42; 32], FAR_FUTURE)
    }

    /// The right key under a kid the URI does not reference (spec 6.1: the wallet
    /// selects by `i`, and an absent kid is an error).
    pub(crate) fn unknown_kid(&self) -> Served {
        self.document("some-other-key", &self.signer.public_key(), FAR_FUTURE)
    }

    /// The right key, but no longer valid.
    pub(crate) fn expired_key(&self) -> Served {
        self.document(&self.kid, &self.signer.public_key(), "2001-01-01")
    }

    /// Not a valid document for the schema (unsupported version).
    pub(crate) fn malformed(&self) -> Served {
        Served::Body(
            format!(
                r#"{{"v":2,"name":"{}","origin_keys":[{{"kid":"{}","pk":"{}","not_after":"{FAR_FUTURE}"}}]}}"#,
                self.name,
                self.kid,
                b64::encode(&self.signer.public_key())
            )
            .into_bytes(),
        )
    }

    fn document(&self, kid: &str, pk: &[u8; 32], not_after: &str) -> Served {
        Served::Body(
            format!(
                r#"{{"v":1,"name":"{}","origin_keys":[{{"kid":"{kid}","pk":"{}","not_after":"{not_after}"}}]}}"#,
                self.name,
                b64::encode(pk)
            )
            .into_bytes(),
        )
    }
}

/// `not_after` of a key that is valid for the foreseeable future.
const FAR_FUTURE: &str = "2099-12-31";

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, reason = "test code")]
mod tests {
    use super::*;
    use xchonnect_core::origin::OriginDocument;

    #[test]
    fn the_variants_differ_in_exactly_one_way() {
        let o = Origin::random("Conformance dApp").unwrap();
        let parse = |s: Served| match s {
            Served::Body(b) => OriginDocument::parse(&b),
            Served::NotFound => panic!("not a body"),
        };
        let now = 1_800_000_000;
        assert!(parse(o.good()).unwrap().key(KID, now).is_ok());
        assert_eq!(
            parse(o.forged_key()).unwrap().key(KID, now).unwrap().pk,
            [0x42; 32]
        );
        assert!(parse(o.unknown_kid()).unwrap().key(KID, now).is_err());
        assert!(parse(o.expired_key()).unwrap().key(KID, now).is_err());
        assert!(parse(o.malformed()).is_err());
    }

    #[test]
    fn the_server_serves_only_the_well_known_path() {
        let o = Origin::random("Conformance dApp").unwrap();
        let s = OriginServer::start("127.0.0.1:0", o.good()).unwrap();
        let get = |path: &str| {
            let mut c = TcpStream::connect(s.addr()).unwrap();
            c.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
                .unwrap();
            let mut out = String::new();
            let _ = c.read_to_string(&mut out);
            out
        };
        assert!(get(WELL_KNOWN).contains("200 OK"));
        assert!(get("/").contains("404"));
        s.serve(Served::NotFound);
        assert!(get(WELL_KNOWN).contains("404"));
        assert_eq!(s.fetches(), 3);
    }
}
