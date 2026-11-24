use std::error::Error;
use std::fmt;

fn combine_context(existing: Option<String>, new_ctx: String) -> Option<String> {
    Some(match existing {
        Some(prev) => format!("{new_ctx}: {prev}"),
        None => new_ctx,
    })
}

/// An error encountered during capture validation, archive decompression, or restoration.
#[derive(Debug)]
pub enum StoreError {
    /// A freeform error message or validation failure.
    Message(String),
    /// An I/O error, optionally with context.
    Io {
        context: Option<String>,
        source: std::io::Error,
    },
    /// A JSON serialization or deserialization error.
    Json {
        context: Option<String>,
        source: serde_json::Error,
    },
    /// A URL parsing error.
    Url {
        context: Option<String>,
        source: url::ParseError,
    },
    /// An error from the underlying HTTP client, optionally with context.
    Fetch {
        context: Option<String>,
        source: wa_fetch::FetchError,
    },
}

impl StoreError {
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }

    pub fn with_context(self, context: impl Into<String>) -> Self {
        let ctx = context.into();
        match self {
            Self::Message(msg) => Self::Message(format!("{ctx}: {msg}")),
            Self::Io { context, source } => Self::Io {
                context: combine_context(context, ctx),
                source,
            },
            Self::Json { context, source } => Self::Json {
                context: combine_context(context, ctx),
                source,
            },
            Self::Url { context, source } => Self::Url {
                context: combine_context(context, ctx),
                source,
            },
            Self::Fetch { context, source } => Self::Fetch {
                context: combine_context(context, ctx),
                source,
            },
        }
    }

    pub fn io_error(&self) -> Option<&std::io::Error> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }

    pub fn fetch_error(&self) -> Option<&wa_fetch::FetchError> {
        match self {
            Self::Fetch { source, .. } => Some(source),
            _ => None,
        }
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        match self {
            Self::Io { source, .. } => (source as &dyn std::any::Any).downcast_ref::<T>(),
            Self::Json { source, .. } => (source as &dyn std::any::Any).downcast_ref::<T>(),
            Self::Url { source, .. } => (source as &dyn std::any::Any).downcast_ref::<T>(),
            Self::Fetch { source, .. } => (source as &dyn std::any::Any).downcast_ref::<T>(),
            _ => None,
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => write!(f, "{msg}"),
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
            Self::Url {
                context: Some(ctx),
                source,
            } => write!(f, "{ctx}: {source}"),
            Self::Url {
                context: None,
                source,
            } => write!(f, "{source}"),
            Self::Fetch {
                context: Some(ctx),
                source,
            } => write!(f, "{ctx}: {source}"),
            Self::Fetch {
                context: None,
                source,
            } => write!(f, "{source}"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Message(_) => None,
            Self::Io { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Url { source, .. } => Some(source),
            Self::Fetch { source, .. } => Some(source),
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(source: std::io::Error) -> Self {
        Self::Io {
            context: None,
            source,
        }
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json {
            context: None,
            source,
        }
    }
}

impl From<url::ParseError> for StoreError {
    fn from(source: url::ParseError) -> Self {
        Self::Url {
            context: None,
            source,
        }
    }
}

impl From<wa_fetch::FetchError> for StoreError {
    fn from(source: wa_fetch::FetchError) -> Self {
        Self::Fetch {
            context: None,
            source,
        }
    }
}

pub(crate) trait StoreContext<T> {
    fn context(self, msg: impl Into<String>) -> Result<T, StoreError>;
    fn with_context<F, S>(self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce() -> S,
        S: Into<String>;
}

impl<T, E> StoreContext<T> for Result<T, E>
where
    E: Into<StoreError>,
{
    fn context(self, msg: impl Into<String>) -> Result<T, StoreError> {
        self.map_err(|e| e.into().with_context(msg))
    }

    fn with_context<F, S>(self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce() -> S,
        S: Into<String>,
    {
        self.map_err(|e| e.into().with_context(f()))
    }
}

impl<T> StoreContext<T> for Option<T> {
    fn context(self, msg: impl Into<String>) -> Result<T, StoreError> {
        self.ok_or_else(|| StoreError::msg(msg.into()))
    }

    fn with_context<F, S>(self, f: F) -> Result<T, StoreError>
    where
        F: FnOnce() -> S,
        S: Into<String>,
    {
        self.ok_or_else(|| StoreError::msg(f().into()))
    }
}

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::error::StoreError::msg(format!($($arg)*)))
    };
}

macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            return Err($crate::error::StoreError::msg(format!($($arg)*)));
        }
    };
}

pub(crate) use bail;
pub(crate) use ensure;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_accumulates_and_preserves_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let store_err = StoreError::from(io_err)
            .with_context("read lockfile /tmp/a")
            .with_context("restore");

        assert_eq!(
            store_err.to_string(),
            "restore: read lockfile /tmp/a: file not found"
        );
        assert!(store_err.source().is_some());
        assert_eq!(
            store_err.io_error().map(|e| e.kind()),
            Some(std::io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn fetch_error_retains_typed_source_with_context() {
        let fetch_err = wa_fetch::FetchError::new("network down");
        let store_err = StoreError::from(fetch_err)
            .with_context("downloading archive")
            .with_context("resolve");

        assert_eq!(
            store_err.to_string(),
            "resolve: downloading archive: network down"
        );
        assert!(store_err.source().is_some());
        assert!(store_err.fetch_error().is_some());
    }
}
