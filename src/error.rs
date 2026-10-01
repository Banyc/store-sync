//! The one error type every operation returns.
//!
//! The classes are the ones a caller must be able to tell apart, not the
//! modules that raise them: a mechanical I/O failure ([`Error::Io`]), a
//! record that is present but does not parse ([`Error::Json`]), a path or a
//! tree that is not what it claims to be ([`Error::Path`],
//! [`Error::Integrity`], [`Error::Materialization`]), a store mutation that
//! could not be made durable ([`Error::Store`]), a transport failure
//! ([`Error::Transport`]), and the closed refusals a caller reacts to
//! ([`Error::Preflight`], [`Error::NotFound`], [`Error::Ref`],
//! [`Error::Conflict`]).

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("path error: {0}")]
    Path(String),

    #[error("materialization error: {0}")]
    Materialization(String),

    #[error("digest/integrity error: {0}")]
    Integrity(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("preflight failed: {0}")]
    Preflight(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid reference: {0}")]
    Ref(String),

    #[error("conflict: {0}")]
    Conflict(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn path(msg: impl Into<String>) -> Self {
        Error::Path(msg.into())
    }
    pub fn materialization(msg: impl Into<String>) -> Self {
        Error::Materialization(msg.into())
    }
    pub fn integrity(msg: impl Into<String>) -> Self {
        Error::Integrity(msg.into())
    }
    pub fn store(msg: impl Into<String>) -> Self {
        Error::Store(msg.into())
    }
    pub fn transport(msg: impl Into<String>) -> Self {
        Error::Transport(msg.into())
    }
    pub fn preflight(msg: impl Into<String>) -> Self {
        Error::Preflight(msg.into())
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Error::NotFound(msg.into())
    }
    pub fn r#ref(msg: impl Into<String>) -> Self {
        Error::Ref(msg.into())
    }
    pub fn conflict(msg: impl Into<String>) -> Self {
        Error::Conflict(msg.into())
    }

    /// Append `context` to this error's message, PRESERVING its class.
    ///
    /// Used where a best-effort cleanup fails while an earlier failure is
    /// already being reported: the caller must see BOTH failures, and must
    /// still be able to tell the class of the underlying failure (a store
    /// I/O error stays [`Error::Store`], a conflicting CAS stays
    /// [`Error::Conflict`], and so on). The two variants that wrap a foreign
    /// error ([`Error::Io`], [`Error::Json`]) keep their class by rebuilding
    /// the inner error with the augmented message.
    pub fn with_context(self, context: impl std::fmt::Display) -> Self {
        let context = context.to_string();
        match self {
            Error::Io(e) => Error::Io(std::io::Error::new(e.kind(), format!("{e}; {context}"))),
            Error::Json(e) => Error::Json(<serde_json::Error as serde::de::Error>::custom(
                format!("{e}; {context}"),
            )),
            Error::Path(m) => Error::Path(format!("{m}; {context}")),
            Error::Materialization(m) => Error::Materialization(format!("{m}; {context}")),
            Error::Integrity(m) => Error::Integrity(format!("{m}; {context}")),
            Error::Store(m) => Error::Store(format!("{m}; {context}")),
            Error::Transport(m) => Error::Transport(format!("{m}; {context}")),
            Error::Preflight(m) => Error::Preflight(format!("{m}; {context}")),
            Error::NotFound(m) => Error::NotFound(format!("{m}; {context}")),
            Error::Ref(m) => Error::Ref(format!("{m}; {context}")),
            Error::Conflict(m) => Error::Conflict(format!("{m}; {context}")),
        }
    }
}
