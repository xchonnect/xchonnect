//! Log capture.
//!
//! Relay and gateway write through `tracing`. The checks install a subscriber whose
//! writer is an in-memory buffer at `TRACE` level, so *everything* either service emits
//! — including from background tasks such as the push dispatcher — ends up in one
//! artefact that can be scanned.

use std::io;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// An in-memory log buffer.
#[derive(Clone, Debug, Default)]
pub struct Capture {
    buf: Arc<Mutex<Vec<u8>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Capture {
    /// Everything written so far.
    pub fn bytes(&self) -> Vec<u8> {
        lock(&self.buf).clone()
    }

    /// Everything written so far, as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    /// Drop what was written so far.
    pub fn clear(&self) {
        lock(&self.buf).clear();
    }
}

impl io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        lock(&self.buf).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn subscriber(capture: &Capture) -> impl tracing::Subscriber + Send + Sync + use<> {
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_target(true)
        .finish()
}

/// Capture every log line of the process, from every thread and task.
///
/// The global subscriber can only be installed once per process, so repeated calls
/// return the same buffer. Use one integration-test binary per global capture.
pub fn global() -> Capture {
    static INSTALLED: OnceLock<Capture> = OnceLock::new();
    INSTALLED
        .get_or_init(|| {
            let capture = Capture::default();
            // A pre-existing subscriber means some other test installed one; the buffer
            // then stays empty, which `inventory::verify` reports as an unverified
            // surface rather than a silent pass.
            let _ = tracing::subscriber::set_global_default(subscriber(&capture));
            capture
        })
        .clone()
}

/// Capture log lines of the current thread only (synchronous checks).
pub fn scoped() -> (Capture, tracing::subscriber::DefaultGuard) {
    let capture = Capture::default();
    let guard = tracing::subscriber::set_default(subscriber(&capture));
    (capture, guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_capture_sees_log_lines() {
        let (capture, _guard) = scoped();
        tracing::info!("hello from the relay");
        tracing::trace!(detail = 7, "trace level is captured too");
        let text = capture.text();
        assert!(text.contains("hello from the relay"), "{text}");
        assert!(text.contains("detail=7"), "{text}");
        capture.clear();
        assert!(capture.text().is_empty());
    }
}
