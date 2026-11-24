//! The HTTP *port* (in the ports-and-adapters sense): a small abstraction over
//! a blocking GET, so the discovery/download logic depends only on this trait
//! and never on a concrete client.
//!
//! - Native builds supply [`crate::UreqClient`] (ureq + rustls + RustCrypto).
//! - A future WASM/web build can implement this same trait over the browser
//!   `fetch` API as an adapter, with no change to the discovery logic.
//!
//! This module is WASM-safe (no native-only deps), so it compiles into the
//! browser target alongside the pure discovery parser.

use std::error::Error;
use std::fmt;

/// A minimal HTTP response: the status code plus the raw body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// A transport-level failure from an [`HttpClient`] — DNS, connect, TLS, I/O,
/// or a body that exceeded the byte cap.
///
/// A non-2xx HTTP status is **not** an error here: it is a successful response
/// and surfaces via [`HttpResponse::status`], leaving the status policy to the
/// caller (discovery wants the status for diagnostics; download treats non-2xx
/// as a per-URL failure).
/// A transport-level failure from an [`HttpClient`] or an error during
/// bundle discovery, download, or caching.
#[derive(Debug)]
pub enum FetchError {
    /// A freeform error message or transport failure without an underlying typed cause.
    Message(String),
    /// An I/O failure, optionally with contextual operation information.
    Io {
        context: Option<String>,
        source: std::io::Error,
    },
    /// A JSON serialization or deserialization failure.
    Json {
        context: Option<String>,
        source: serde_json::Error,
    },
    /// A UTF-8 decoding failure.
    Utf8 {
        context: Option<String>,
        source: std::str::Utf8Error,
    },
}

impl FetchError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: Some(context.into()),
            source,
        }
    }

    pub fn json(context: impl Into<String>, source: serde_json::Error) -> Self {
        Self::Json {
            context: Some(context.into()),
            source,
        }
    }

    pub fn utf8(context: impl Into<String>, source: std::str::Utf8Error) -> Self {
        Self::Utf8 {
            context: Some(context.into()),
            source,
        }
    }

    pub fn context(self, context: impl Into<String>) -> Self {
        let context = context.into();
        match self {
            Self::Message(msg) => Self::Message(format!("{context}: {msg}")),
            Self::Io {
                context: prev,
                source,
            } => Self::Io {
                context: Some(match prev {
                    Some(p) => format!("{context}: {p}"),
                    None => context,
                }),
                source,
            },
            Self::Json {
                context: prev,
                source,
            } => Self::Json {
                context: Some(match prev {
                    Some(p) => format!("{context}: {p}"),
                    None => context,
                }),
                source,
            },
            Self::Utf8 {
                context: prev,
                source,
            } => Self::Utf8 {
                context: Some(match prev {
                    Some(p) => format!("{context}: {p}"),
                    None => context,
                }),
                source,
            },
        }
    }
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
            Self::Io {
                context: Some(ctx),
                source,
            } => write!(f, "{ctx}: {source}"),
            Self::Io {
                context: None,
                source,
            } => write!(f, "{source}"),
            Self::Json {
                context: Some(ctx),
                source,
            } => write!(f, "{ctx}: {source}"),
            Self::Json {
                context: None,
                source,
            } => write!(f, "{source}"),
            Self::Utf8 {
                context: Some(ctx),
                source,
            } => write!(f, "{ctx}: {source}"),
            Self::Utf8 {
                context: None,
                source,
            } => write!(f, "{source}"),
        }
    }
}

impl Error for FetchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Message(_) => None,
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Utf8 { source, .. } => Some(source),
        }
    }
}

pub type Result<T, E = FetchError> = std::result::Result<T, E>;

impl From<std::io::Error> for FetchError {
    fn from(source: std::io::Error) -> Self {
        Self::Io {
            context: None,
            source,
        }
    }
}

impl From<serde_json::Error> for FetchError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json {
            context: None,
            source,
        }
    }
}

impl From<std::str::Utf8Error> for FetchError {
    fn from(source: std::str::Utf8Error) -> Self {
        Self::Utf8 {
            context: None,
            source,
        }
    }
}

/// A response observed *without* following redirects: status, raw `Location`
/// and the bounded response body.
///
/// A caller that treats `Location` as a fetchable URL is trusting remote input,
/// so the value is handed over unparsed and the policy stays with the caller
/// (see the `btarchive` module, which admits only one host suffix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectResponse {
    pub status: u16,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

/// A blocking HTTP GET. Implementors are the *adapters* (native `ureq` today,
/// browser `fetch` tomorrow); everything else in this crate is the *port* that
/// depends only on this trait.
///
/// `Sync` is required so a single client can be borrowed across the download
/// worker threads in [`crate::download_bundles`].
pub trait HttpClient: Sync {
    /// GET `url` with the given extra request `headers`, reading at most
    /// `max_bytes` of the response body.
    ///
    /// A non-2xx status must be returned in the [`HttpResponse`], not as an
    /// error; only transport-level problems return [`FetchError`].
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<HttpResponse, FetchError>;

    /// GET `url` **without following redirects**, reporting the status and the
    /// `Location` header instead of fetching what it points at.
    ///
    /// This is an *optional* capability, defaulted to unsupported, because only an
    /// adapter can decide who follows a redirect and no caller can retrofit it: by
    /// the time a following adapter returns, the redirect target has already been
    /// downloaded. Endpoints whose 302 target is the payload — a `btarchive` zip is
    /// hundreds of megabytes — must be able to stop at the `Location` and hand the
    /// URL to something that streams, rather than pull the body into a `Vec<u8>`
    /// under a byte cap.
    ///
    /// The default returns [`FetchError`] so an adapter that cannot express this
    /// (the browser `fetch` build) keeps compiling and says so at runtime, instead
    /// of every adapter growing a method it has no use for.
    fn get_redirect(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_bytes: u64,
    ) -> Result<RedirectResponse, FetchError> {
        let _ = (url, headers, max_bytes);
        Err(FetchError::new(
            "this HttpClient adapter does not support redirect inspection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn io_error_preserves_cause_and_context() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let fetch_err = FetchError::io("open /path", io_err);

        assert_eq!(fetch_err.to_string(), "open /path: file missing");
        let source = fetch_err.source().expect("has source");
        let downcasted = source
            .downcast_ref::<io::Error>()
            .expect("downcasts to io::Error");
        assert_eq!(downcasted.kind(), io::ErrorKind::NotFound);

        // Nested context keeps root source
        let wrapped = fetch_err.context("step 1");
        assert_eq!(wrapped.to_string(), "step 1: open /path: file missing");
        assert_eq!(
            wrapped
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn json_and_utf8_errors_preserve_causes() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let fetch_json = FetchError::from(json_err);
        assert!(fetch_json.source().is_some());

        let bytes = [0xff];
        #[allow(invalid_from_utf8)]
        let utf8_err = std::str::from_utf8(&bytes).unwrap_err();
        let fetch_utf8 = FetchError::from(utf8_err);
        assert!(fetch_utf8.source().is_some());
    }
}
