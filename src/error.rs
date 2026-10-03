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
//! [`Error::Conflict`], [`Error::Reserved`], [`Error::LockContended`]).
//!
//! Within a class, where a caller has to DISTINGUISH one condition from
//! another in the same class, the condition is a TYPED value carried alongside
//! the message: [`MaterializationKind`], [`StoreKind`], [`TransportKind`],
//! and the pre-existing [`ReservedKind`]. The message is preserved VERBATIM
//! (the `Display` impl is byte-identical to the pre-typing one), so a caller
//! that already matches the text keeps working; the typed value is what a
//! caller should branch on. A class that carries no typed kind is one where
//! nothing in the crate — not a caller, not a test, not the crate's own
//! recovery advice — has to tell its conditions apart: the text is for a
//! human. `Error::materialization`/`store`/`transport` remain as the
//! untyped shorthand and produce the `Unclassified` kind.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("path error: {0}")]
    Path(String),

    /// A materialization refusal: the tree (or the wire as it describes one)
    /// holds something the crate cannot represent faithfully, or a
    /// sync-level preflight refused the run. The message is preserved
    /// verbatim; a caller branches on [`MaterializationKind`].
    #[error("materialization error: {message}")]
    Materialization {
        kind: MaterializationKind,
        message: String,
    },

    #[error("digest/integrity error: {0}")]
    Integrity(String),

    /// A store mutation that could not be made durable, or a substrate
    /// refusal. The message is preserved verbatim; a caller branches on
    /// [`StoreKind`].
    #[error("store error: {message}")]
    Store { kind: StoreKind, message: String },

    /// A transport failure. The message is preserved verbatim (including every
    /// far-side diagnostic); a caller branches on [`TransportKind`].
    #[error("transport error: {message}")]
    Transport {
        kind: TransportKind,
        message: String,
    },

    #[error("preflight failed: {0}")]
    Preflight(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid reference: {0}")]
    Ref(String),

    #[error("conflict: {0}")]
    Conflict(String),

    /// A TYPED reserved-spelling / residue refusal from the substrate's ONE gate
    /// (or a residue recovery). A consumer branches on [`ReservedKind`] instead
    /// of string-matching the message. The message KEEPS the historical
    /// `ResidueBelow` token, so a caller that already matches the text is
    /// unaffected.
    #[error("reserved spelling: {reason:?}: {message}")]
    Reserved {
        reason: ReservedKind,
        message: String,
    },

    /// The advisory lock is held by a LIVE holder. This is a TYPED contention
    /// signal, distinct from a real open/flock failure (which stays
    /// [`Error::Preflight`]): a caller that wants to RETRY a contended lock
    /// matches this variant instead of string-matching the holder message.
    /// The lock is non-blocking by design (`flock` `LOCK_NB` / `LockFileEx`
    /// with `LOCKFILE_FAIL_IMMEDIATELY`), so retrying is the caller's policy.
    #[error("lock contended: {0}")]
    LockContended(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The TYPED reason a reserved-spelling refusal was raised, carried by
/// [`Error::Reserved`] so a consumer can branch without string-matching.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedKind {
    /// The path names or descends through a destination RESIDUE: a stranded
    /// claim-aside that HOLDS the pre-replace original. Recover it with
    /// `sync::Residue::recover_to` or destroy it only with
    /// `sync::Residue::discard`.
    ResidueBelow,
    /// A discard/detection was handed a path whose final component is NOT a
    /// residue spelling.
    NotResidue,
    /// `sync::Residue::recover_to` found the target path already occupied (a
    /// regular file, a directory, OR a symlink), so overwriting it could
    /// destroy the entry there. Both the strand and the target are intact.
    RecoverTargetOccupied,
}

/// The TYPED reason a [`Error::Materialization`] refusal was raised.
///
/// Each variant is a condition a caller (or the crate's own tests) has to tell
/// apart from the others, because the recovery differs: the destination-side
/// tolerant canonicalizer RECORDS the address-fidelity refusals
/// ([`Self::AbsoluteSymlink`], [`Self::EscapingSymlink`], [`Self::HardLink`])
/// as `unsupported` rather than failing the tree, while a wire-unrepresentable
/// name or a malformed wire line fails BOTH forms (a tree the wire cannot
/// spell, or a far-side bug). A condition with no such consumer is left as
/// text under [`Self::Unclassified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializationKind {
    /// A symlink whose target is absolute. Tolerated for a DESTINATION
    /// (recorded in `DestinationTree::unsupported`), refused for a SOURCE.
    AbsoluteSymlink,
    /// A relative symlink whose spelled walk cannot be shown to stay inside
    /// the root: it pops above the root, or it passes THROUGH a symlink
    /// component the kernel would follow. Tolerated for a DESTINATION,
    /// refused for a SOURCE.
    EscapingSymlink,
    /// A regular file with link count > 1. Tolerated for a DESTINATION,
    /// refused for a SOURCE.
    HardLink,
    /// A non-regular, non-directory, non-symlink entry (a FIFO, socket, or
    /// device). Refused on BOTH forms: the applier has no primitive to remove
    /// it by name, and a read of it could block.
    SpecialFile,
    /// A name the manifest wire cannot represent faithfully: a NUL/LF/CR/TAB
    /// character, a spelling that is not already NFC, an absolute path, a
    /// traversal/empty component, or a component past the filesystem name
    /// bound.
    UnrepresentableName,
    /// A symlink TARGET the manifest wire cannot represent faithfully: an
    /// empty target, or one carrying NUL/LF/CR/TAB.
    UnrepresentableSymlinkTarget,
    /// A name or symlink target that is valid on disk but not valid UTF-8, so
    /// storing it in the string-typed manifest would be lossy.
    NotUtf8,
    /// Two entries normalize to the same manifest spelling, so the manifest
    /// could not name both.
    DuplicatePath,
    /// The manifest is not parent-closed: an entry's parent directory is
    /// missing or is not a `dir` entry, so the parent's spelling would be
    /// implicitly created rather than verified.
    ParentNotClosed,
    /// The two sync roots overlap: one is an ancestor of the other, so the run
    /// would copy a tree into its own subtree.
    RootsOverlap,
    /// A condition with no distinction any caller branches on; the message is
    /// for a human.
    Unclassified,
}

/// The TYPED reason a [`Error::Store`] refusal was raised.
///
/// These are the substrate refusals a caller or the crate's own external
/// tests distinguish from a plain mechanical I/O failure: the tree copy's
/// source-audit refusals (a symlink or special file where a directory was
/// expected, a hard link, an unlandable name, an overlapping source and
/// destination), the residue gate, and the visible-but-not-durable outcome a
/// caller must not read as a plain failure. Every other store error is a
/// mechanical I/O failure with no consumer-side branch, and stays
/// [`Self::Unclassified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreKind {
    /// The tree copy's source and destination overlap (the destination is
    /// inside the source, the source inside the destination, or they are the
    /// same directory), so the walk would copy a tree into itself without
    /// bound. Decided by directory IDENTITY, not spelling.
    CopyOverlap,
    /// The tree copy's top-level source is a symlink, refused rather than
    /// followed (regardless of a trailing separator).
    CopySourceIsSymlink,
    /// The tree copy's top-level source is not a directory.
    CopySourceNotADirectory,
    /// A source entry the copy must read is not a regular file (a FIFO,
    /// socket, or device), refused instead of blocking in `open(2)`.
    CopySourceNotRegular,
    /// A source entry is a hard link (link count > 1), which the crate refuses
    /// by rule so a copy cannot silently duplicate it into an independent file.
    CopyHardLink,
    /// A source symlink's target is invalid or cannot be shown to stay inside
    /// the root, so copying it as a link would land an escaping link.
    CopySymlinkTarget,
    /// A source entry's name cannot be landed faithfully: not valid UTF-8,
    /// wire-unrepresentable, or one of the crate's reserved/temp spellings.
    CopyUnlandableName,
    /// A residue recovery/discard was handed an entry that is not a regular
    /// file, a directory, or a symlink, so it cannot be recovered or discarded
    /// by name.
    ResidueNotAnEntry,
    /// The entry is VISIBLE but its durability is UNCONFIRMED: the publish
    /// step committed, but a later fsync failed, so the previous content is
    /// gone and the new content may not survive a crash. A caller must not
    /// read this as "the write failed" (retrying may be wrong) or as success.
    DurabilityUnconfirmed,
    /// A condition with no distinction any caller branches on; the message is
    /// for a human.
    Unclassified,
}

/// The TYPED reason a [`Error::Transport`] failure was raised.
///
/// The transport class spans several LAYERS (the ssh connection, the remote
/// shell, the far-side manifest script, the local runner's drain), and the
/// crate's own tests and its manifest classifier have to tell them apart: the
/// same non-zero exit status can come from any of them, and blaming the wrong
/// one was a real defect. The message preserves every diagnostic verbatim; a
/// caller branches on this kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    /// The transport failed BEFORE the far-side command could run: a
    /// connection/authentication/host-key/control-socket failure, or the
    /// runner's typed deadline that killed a still-running child. This is the
    /// "unreachable host" condition.
    BeforeCommand,
    /// The far-side `perl` program itself could not be started (the remote
    /// shell's 126/127, or an anchored not-found diagnostic).
    InterpreterMissing,
    /// The far-side manifest script RAN and exited non-zero (its own anchored
    /// `die` diagnostic is present).
    FarSideScript,
    /// The far-side command ran and exited, but the runner's bounded POST-EXIT
    /// output drain gave up, so the exit status it had collected was
    /// discarded. NOT the transport-before-command layer.
    OutputDrainGaveUp,
    /// No rule establishes the layer: the exit status and preserved stderr are
    /// reported as undetermined rather than attributed to a layer.
    Undetermined,
    /// The remote root EXISTS but is not a directory; it is refused rather
    /// than described as a tree. (On the local branch this is decided in
    /// process.)
    RootNotADirectory,
    /// The receiver-id marker is CONFIRMED absent: the far side has no store
    /// yet (the marker is created during provisioning). This is the "no store
    /// yet" condition, distinct from [`Self::BeforeCommand`] ("the host is
    /// unreachable").
    ReceiverIdMarkerAbsent,
    /// The receiver-id marker is present but is in the SOURCE TOOL's legacy
    /// `recv-<uuid-v7>` format, which this crate never adopts.
    ReceiverIdMarkerLegacyFormat,
    /// The receiver-id marker is present but matches neither this crate's
    /// format nor the legacy shape: a corrupted or foreign file. Never adopted.
    ReceiverIdMarkerMalformed,
    /// The entry is VISIBLE but its durability is UNCONFIRMED: the remote
    /// publish (rename) committed, but a later directory fsync failed. The
    /// remote counterpart of [`StoreKind::DurabilityUnconfirmed`].
    DurabilityUnconfirmed,
    /// A condition with no distinction any caller branches on; the message is
    /// for a human.
    Unclassified,
}

impl Error {
    /// A TYPED reserved-spelling refusal (see [`ReservedKind`]). The message
    /// keeps the `ResidueBelow` token for textual compatibility.
    pub fn reserved(kind: ReservedKind, msg: impl Into<String>) -> Self {
        Error::Reserved {
            reason: kind,
            message: msg.into(),
        }
    }

    /// The typed reserved-spelling reason, when this error is one.
    pub fn reserved_kind(&self) -> Option<ReservedKind> {
        match self {
            Error::Reserved { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// A TYPED materialization refusal (see [`MaterializationKind`]). The
    /// message is preserved verbatim.
    pub fn materialization_kind(kind: MaterializationKind, msg: impl Into<String>) -> Self {
        Error::Materialization {
            kind,
            message: msg.into(),
        }
    }

    /// The typed materialization reason, when this error is one.
    pub fn materialization_reason(&self) -> Option<MaterializationKind> {
        match self {
            Error::Materialization { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// A TYPED store refusal (see [`StoreKind`]). The message is preserved
    /// verbatim.
    pub fn store_kind(kind: StoreKind, msg: impl Into<String>) -> Self {
        Error::Store {
            kind,
            message: msg.into(),
        }
    }

    /// The typed store reason, when this error is one.
    pub fn store_reason(&self) -> Option<StoreKind> {
        match self {
            Error::Store { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// A TYPED transport failure (see [`TransportKind`]). The message is
    /// preserved verbatim.
    pub fn transport_kind(kind: TransportKind, msg: impl Into<String>) -> Self {
        Error::Transport {
            kind,
            message: msg.into(),
        }
    }

    /// The typed transport reason, when this error is one.
    pub fn transport_reason(&self) -> Option<TransportKind> {
        match self {
            Error::Transport { kind, .. } => Some(*kind),
            _ => None,
        }
    }
}

impl Error {
    pub fn path(msg: impl Into<String>) -> Self {
        Error::Path(msg.into())
    }
    pub fn materialization(msg: impl Into<String>) -> Self {
        Error::Materialization {
            kind: MaterializationKind::Unclassified,
            message: msg.into(),
        }
    }
    pub fn integrity(msg: impl Into<String>) -> Self {
        Error::Integrity(msg.into())
    }
    pub fn store(msg: impl Into<String>) -> Self {
        Error::Store {
            kind: StoreKind::Unclassified,
            message: msg.into(),
        }
    }
    pub fn transport(msg: impl Into<String>) -> Self {
        Error::Transport {
            kind: TransportKind::Unclassified,
            message: msg.into(),
        }
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

    /// The typed LOCK-CONTENTION signal ([`Error::LockContended`]): the
    /// advisory lock is held by a live holder, so a retrying caller reacts to
    /// this instead of string-matching the holder message.
    pub fn lock_contended(msg: impl Into<String>) -> Self {
        Error::LockContended(msg.into())
    }

    /// Append `context` to this error's message, PRESERVING its class AND its
    /// typed kind.
    ///
    /// Used where a best-effort cleanup fails while an earlier failure is
    /// already being reported: the caller must see BOTH failures, and must
    /// still be able to tell the class and the KIND of the underlying failure
    /// (a store I/O error stays [`Error::Store`], a conflicting CAS stays
    /// [`Error::Conflict`], a far-side script refusal keeps its
    /// [`TransportKind::FarSideScript`], and so on). The two variants that
    /// wrap a foreign error ([`Error::Io`], [`Error::Json`]) keep their class
    /// by rebuilding the inner error with the augmented message.
    pub fn with_context(self, context: impl std::fmt::Display) -> Self {
        let context = context.to_string();
        match self {
            Error::Io(e) => Error::Io(std::io::Error::new(e.kind(), format!("{e}; {context}"))),
            Error::Json(e) => Error::Json(<serde_json::Error as serde::de::Error>::custom(
                format!("{e}; {context}"),
            )),
            Error::Path(m) => Error::Path(format!("{m}; {context}")),
            Error::Materialization { kind, message } => Error::Materialization {
                kind,
                message: format!("{message}; {context}"),
            },
            Error::Integrity(m) => Error::Integrity(format!("{m}; {context}")),
            Error::Store { kind, message } => Error::Store {
                kind,
                message: format!("{message}; {context}"),
            },
            Error::Transport { kind, message } => Error::Transport {
                kind,
                message: format!("{message}; {context}"),
            },
            Error::Preflight(m) => Error::Preflight(format!("{m}; {context}")),
            Error::NotFound(m) => Error::NotFound(format!("{m}; {context}")),
            Error::Ref(m) => Error::Ref(format!("{m}; {context}")),
            Error::Conflict(m) => Error::Conflict(format!("{m}; {context}")),
            Error::Reserved { reason, message } => Error::Reserved {
                reason,
                message: format!("{message}; {context}"),
            },
            Error::LockContended(m) => Error::LockContended(format!("{m}; {context}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constraint #4, the text-compatibility half: typing the reasons did NOT
    /// change what a caller that matches the message sees. Every class keeps
    /// its historical `Display` prefix and prints the message VERBATIM.
    #[test]
    fn typed_reasons_preserve_the_historical_message_text() {
        assert_eq!(
            Error::materialization("boom").to_string(),
            "materialization error: boom"
        );
        assert_eq!(Error::store("boom").to_string(), "store error: boom");
        assert_eq!(
            Error::transport("boom").to_string(),
            "transport error: boom"
        );
        assert_eq!(
            Error::preflight("boom").to_string(),
            "preflight failed: boom"
        );
        assert_eq!(Error::not_found("boom").to_string(), "not found: boom");
        assert_eq!(Error::conflict("boom").to_string(), "conflict: boom");
        // A TYPED message is byte-identical to the untyped one at the same
        // text: the kind is carried out of band, never rendered.
        assert_eq!(
            Error::transport_kind(TransportKind::BeforeCommand, "boom").to_string(),
            Error::transport("boom").to_string()
        );
        assert_eq!(
            Error::materialization_kind(MaterializationKind::HardLink, "boom").to_string(),
            Error::materialization("boom").to_string()
        );
        assert_eq!(
            Error::store_kind(StoreKind::CopyOverlap, "boom").to_string(),
            Error::store("boom").to_string()
        );
    }

    /// `with_context` PRESERVES the class AND the typed kind on every class
    /// that carries one. A context-annotated error that lost its kind would be
    /// exactly the string-matching regression this constraint removes.
    #[test]
    fn with_context_preserves_the_typed_kind() {
        let e = Error::transport_kind(TransportKind::FarSideScript, "boom").with_context("ctx");
        assert_eq!(e.transport_reason(), Some(TransportKind::FarSideScript));
        assert_eq!(e.to_string(), "transport error: boom; ctx");

        let e = Error::materialization_kind(MaterializationKind::EscapingSymlink, "boom")
            .with_context("ctx");
        assert_eq!(
            e.materialization_reason(),
            Some(MaterializationKind::EscapingSymlink)
        );
        assert_eq!(e.to_string(), "materialization error: boom; ctx");

        let e = Error::store_kind(StoreKind::CopyHardLink, "boom").with_context("ctx");
        assert_eq!(e.store_reason(), Some(StoreKind::CopyHardLink));
        assert_eq!(e.to_string(), "store error: boom; ctx");

        let e = Error::reserved(ReservedKind::ResidueBelow, "boom").with_context("ctx");
        assert_eq!(e.reserved_kind(), Some(ReservedKind::ResidueBelow));
    }

    /// The untyped shorthand produces the `Unclassified` kind, so a kind-aware
    /// caller can see that no condition was named.
    #[test]
    fn the_untyped_shorthand_is_unclassified() {
        assert_eq!(
            Error::materialization("m").materialization_reason(),
            Some(MaterializationKind::Unclassified)
        );
        assert_eq!(
            Error::store("s").store_reason(),
            Some(StoreKind::Unclassified)
        );
        assert_eq!(
            Error::transport("t").transport_reason(),
            Some(TransportKind::Unclassified)
        );
        // The kind accessors are None on a different class.
        assert_eq!(Error::transport("t").store_reason(), None);
        assert_eq!(Error::store("s").transport_reason(), None);
    }
}
