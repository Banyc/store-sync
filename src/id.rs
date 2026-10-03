//! The validated identity newtype machinery.
//!
//! A value that names something in a store must be a safe single path
//! segment: the crate stores validated names VERBATIM, so the valid set must
//! be injective into the filesystem (see [`valid_name`]). The
//! [`id_newtype!`] macro wraps such a validated string in a newtype whose
//! construction validates the invariant, so an invalid value cannot exist.
//!
//! The composition here is deliberately small and domain-free:
//!
//! * [`id_newtype!`] — the validated newtype, with
//!   `parse`/`FromStr`/`TryFrom` and a serde `Deserialize` that routes every
//!   wire string through the same validation (fail closed). There is
//!   deliberately NO `Default` and no unchecked production constructor: an
//!   empty identity would be a malformed durable record constructible by
//!   anyone;
//! * [`valid_name`] — the single-safe-segment name rule, which ALSO refuses
//!   the crate's RESERVED spellings ([`crate::reserved::is_reserved_name`]): a
//!   name the crate accepts is always a name a whole-store sync can replicate
//!   and its sanctioned delete route can destroy. A consumer can ask the
//!   question directly through that public predicate;
//! * [`valid_hex_digest`] — the exactly-64-lowercase-hex sha256 rule;
//! * [`Identifier`] — the worked example newtype built from [`valid_name`].

/// The validated identity newtype: construction goes through [`parse`]
/// (or `FromStr`/`TryFrom`), which enforces the type's format rule, and the
/// serde `Deserialize` routes every wire string through the same validation
/// (an invalid wire identity fails deserialization — fail closed). The
/// UNCHECKED [`new`] constructor is `#[cfg(test)]` only: test fixtures may
/// build arbitrary ids, production never can.
///
/// `$validator` is a `fn(&str) -> bool` implementing the type's format rule.
#[macro_export]
macro_rules! id_newtype {
    ($name:ident, $validator:expr, $doc:expr) => {
        #[doc = $doc]
        // NOTE: deliberately NO `Default` — a `Default` identity would be an
        // EMPTY string, a malformed durable record constructible by anyone
        // (the exact gap this hardening closes). An identity can only be
        // built through the validated `parse` (or `FromStr`/`TryFrom`).
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validate `s` against the type's format rule and construct the
            /// identity. The invariant is enforced HERE: an invalid value is
            /// rejected before a value of this type can exist.
            pub fn parse(s: &str) -> $crate::error::Result<$name> {
                if !$validator(s) {
                    return Err($crate::error::Error::integrity(format!(
                        "invalid {} value {:?}",
                        stringify!($name),
                        s
                    )));
                }
                Ok($name(s.to_string()))
            }

            /// The validated identity string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The validated identity string, consumed.
            pub fn into_string(self) -> String {
                self.0
            }

            /// UNCHECKED constructor — TEST FIXTURES ONLY, `#[cfg(test)]`
            /// gated (not compiled into a production build). Production code
            /// must construct through [`Self::parse`] (or `FromStr`/`TryFrom`), so
            /// an invalid identity can never be built outside tests.
            #[cfg(test)]
            pub fn new(s: impl Into<String>) -> Self {
                $name(s.into())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::error::Error;
            fn from_str(s: &str) -> $crate::error::Result<$name> {
                $name::parse(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = $crate::error::Error;
            fn try_from(s: &str) -> $crate::error::Result<$name> {
                $name::parse(s)
            }
        }

        /// UNCHECKED conversion — TEST FIXTURES ONLY (mirrors `$name::new`,
        /// which is `#[cfg(test)]` gated like this conversion).
        /// NOTE: deliberately NO `From<String>`/`From<&str>` impl — clap's
        /// value-parser inference prefers those over `FromStr`, which would
        /// silently bypass validation in test builds (and `From<&str>` would
        /// conflict with the validated `TryFrom<&str>`).

        impl<'de> serde::Deserialize<'de> for $name {
            /// Wire strings go through the validated parse: an invalid wire
            /// identity fails deserialization (fail closed — a record that
            /// carries a malformed identity is never silently accepted).
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = <String as serde::Deserialize>::deserialize(deserializer)?;
                $name::parse(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

/// A valid 64-lowercase-hex sha256 digest, shared by test fixtures that need
/// a well-formed digest.
#[cfg(test)]
const DIGEST_TEST_HEX_1: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The name rule shared by the identifier-like validated values AND the
/// identity newtypes built on it (a single safe path segment): a SINGLE
/// FILESYSTEM-SAFE ASCII path segment — non-empty, at most
/// [`crate::atomic::NAME_MAX`] bytes, only `[a-zA-Z0-9._-]`, not a `.`/`..`
/// traversal component, never a leading dash, and NEVER a spelling that names
/// or can ALIAS the crate's own bookkeeping ([`crate::reserved::is_unaddressable_name`]):
/// the claim-aside namespace `.sync-aside.`, the operation-lock record spelling
/// `.<name>.operation.lock`, the application-store lock record `operation.lock`,
/// and any CASE ALIAS of those (on a case-insensitive filesystem
/// `.SYNC-ASIDE.1` IS `.sync-aside.1`).
///
/// A name becomes a directory/file component UNCHANGED (the store stores
/// validated names VERBATIM), so the rule must make the valid set INJECTIVE
/// into the filesystem: every excluded class is exactly a class that could
/// collide under an encoding or escape the forced namespace — separators
/// (`/`, `\`) would nest, whitespace/control/unicode would have to be
/// re-encoded (two distinct names collapsing onto one encoded name), `.`/`..`
/// escape the namespace, and a leading dash invites option-parser confusion.
/// A name longer than [`crate::atomic::NAME_MAX`] names no single directory
/// entry on any supported filesystem (`ENAMETOOLONG`), and a reserved spelling
/// (or a case alias of one) would collide with the crate's own bookkeeping.
/// The RESERVED spellings are excluded for a stronger reason: a whole-store
/// sync STRIPS them from both manifests before the diff, so an identity the
/// crate accepted but the sync cannot transfer (and cannot destroy through
/// its sanctioned delete route) would be a name the crate could never
/// replicate. No re-encoding is needed: the valid set is already
/// filesystem-safe, so two distinct valid names ALWAYS map to two distinct
/// path components.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= crate::atomic::NAME_MAX
        && !s.starts_with('-')
        && s != "."
        && s != ".."
        && !crate::reserved::is_unaddressable_name(s)
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

/// A valid sha256 digest: exactly 64 lowercase hex characters (the exact form
/// [`crate::digest::sha256_bytes`] produces). Any other string — empty, short,
/// long, uppercase, non-hex, or prefixed — is rejected.
pub fn valid_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

id_newtype!(
    Identifier,
    valid_name,
    "A validated identifier (a server, slot, target, or variant name): \
     non-empty, no surrounding whitespace, no control characters. Used for \
     the id-bearing fields that have no dedicated id type; fields with a \
     dedicated type keep it."
);

impl AsRef<std::path::Path> for Identifier {
    /// Identifiers are used directly as filesystem path segments (a remote
    /// directory is named by the identifier), so a validated identifier
    /// doubles as a path segment.
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::RngSeed;

    /// The identity newtype accepts every valid name and rejects every
    /// invalid class, through both `parse` and `FromStr`.
    #[test]
    fn identifier_accepts_valid_rejects_invalid() {
        for ok in ["s1", "production", "wave-1", "a", "a..b", "a.b", "a_b-c.d"] {
            let id = Identifier::parse(ok).expect("valid identifier parses");
            assert_eq!(id.as_str(), ok);
            assert_eq!(id.to_string(), ok);
            assert_eq!(ok.parse::<Identifier>().expect("from_str"), id);
        }
        for bad in [
            "",
            "   ",
            " x",
            "x ",
            "\u{0}",
            "a\nb",
            "a/b",
            "a\\b",
            ".",
            "..",
            "../x",
            "x/..",
            "α",
            "x y",
            "-lead",
            "a b",
            "a\u{1f}",
            // The crate's own RESERVED spellings are refused: a whole-store
            // sync strips them from both manifests, so an id the crate
            // accepted here could never be replicated or destroyed.
            ".sync-aside.1",
            "..sync-aside.1.operation.lock",
            ".001.operation.lock",
        ] {
            Identifier::parse(bad).expect_err("invalid identifier must be rejected");
            assert!(bad.parse::<Identifier>().is_err(), "{bad:?}");
        }
        // The near-miss `operation.lock` is NO LONGER a valid id: it is the
        // crate's own application-store lock record, which FileLock::acquire
        // truncates and rewrites, so an id that named it could not coexist
        // with the lock. Its case aliases are refused too (A3/A4).
        assert!(Identifier::parse("operation.lock").is_err());
        assert!(Identifier::parse("OPERATION.LOCK").is_err());
        assert!(Identifier::parse(".sync-aside").is_ok());
    }

    /// The reserved spellings the identifier refuses are the SAME set the
    /// crate's public reservation predicate names, and the identifier's
    /// rejection is observable through every construction path (parse,
    /// `FromStr`, and wire deserialization — fail closed).
    #[test]
    fn the_identifier_refuses_every_reserved_spelling() {
        for reserved in [
            ".sync-aside.1",
            ".sync-aside.",
            ".001.operation.lock",
            "..sync-aside.1.operation.lock",
        ] {
            assert!(
                crate::reserved::is_reserved_name(reserved),
                "the public predicate must call {reserved:?} reserved"
            );
            assert!(
                Identifier::parse(reserved).is_err(),
                "parse must refuse the reserved spelling {reserved:?}"
            );
            assert!(
                reserved.parse::<Identifier>().is_err(),
                "FromStr must refuse the reserved spelling {reserved:?}"
            );
            assert!(
                serde_json::from_str::<Identifier>(&format!("{reserved:?}")).is_err(),
                "wire deserialization must refuse the reserved spelling {reserved:?}"
            );
        }
        // A consumer can ask BEFORE failing, through the public predicate.
        assert!(crate::reserved::is_reserved_name(".sync-aside.1"));
        assert!(crate::reserved::is_reserved_path(
            "snapshots/.001.operation.lock"
        ));
        assert!(!crate::reserved::is_reserved_name("production"));
    }

    /// The id rule refuses the crate's own APPLICATION lock record and every
    /// case alias of a reserved spelling, through every construction path —
    /// so an identity the crate accepts can never be (or alias) the record
    /// `FileLock::acquire` truncates, on a case-insensitive filesystem too.
    #[test]
    fn the_identifier_refuses_the_lock_record_and_case_aliases() {
        assert!(crate::reserved::is_application_lock_name("operation.lock"));
        assert!(!crate::reserved::is_reserved_name("operation.lock"));
        for bad in [
            "operation.lock",
            "OPERATION.LOCK",
            "Operation.Lock",
            ".SYNC-ASIDE.1",
            ".Sync-Aside.1",
            ".001.OPERATION.LOCK",
        ] {
            assert!(Identifier::parse(bad).is_err(), "parse must refuse {bad:?}");
            assert!(
                bad.parse::<Identifier>().is_err(),
                "FromStr must refuse {bad:?}"
            );
            assert!(
                serde_json::from_str::<Identifier>(&format!("{bad:?}")).is_err(),
                "wire deserialization must refuse {bad:?}"
            );
        }
        // A genuinely distinct near-miss is still ordinary.
        assert!(Identifier::parse("a.operation.lock").is_ok());
        assert!(Identifier::parse("operation.lockx").is_ok());
    }

    /// The NAME_MAX bound the manifest documents is ENFORCED at the name
    /// boundary: a name the store would refuse with `ENAMETOOLONG` is refused
    /// by [`valid_name`]/[`Identifier::parse`] too, through every path.
    #[test]
    fn the_identifier_enforces_the_name_max_bound() {
        let max = crate::atomic::NAME_MAX;
        let at_max = "a".repeat(max);
        assert!(valid_name(&at_max), "a name at NAME_MAX is legal");
        assert!(Identifier::parse(&at_max).is_ok());
        for over in [max + 1, 256, 300] {
            let long = "a".repeat(over);
            assert!(
                !valid_name(&long),
                "a {over}-byte name must be refused by the name authority"
            );
            let err = Identifier::parse(&long).expect_err("parse must refuse an over-long name");
            assert!(
                matches!(err, crate::error::Error::Integrity(_)),
                "the refusal keeps the integrity class: {err:?}"
            );
            assert!(
                serde_json::from_str::<Identifier>(&format!("{long:?}")).is_err(),
                "wire deserialization must refuse an over-long name"
            );
        }
    }

    /// The serde wire path routes every string through the same validation:
    /// a valid wire string deserializes into the same value the validated
    /// parse builds, and an invalid wire string fails deserialization (fail
    /// closed — a malformed identity never becomes a value).
    #[test]
    fn identifier_wire_deserialization_fails_closed() {
        let wire: Identifier =
            serde_json::from_str("\"production\"").expect("valid wire identity deserializes");
        assert_eq!(
            wire,
            Identifier::parse("production").expect("canonical identity parses")
        );
        let err = serde_json::from_str::<Identifier>("\"../x\"")
            .expect_err("invalid wire identity must fail deserialization");
        assert!(
            err.to_string().contains("invalid Identifier value"),
            "the deserialization error is the identity's own validation error, got: {err}"
        );
    }

    /// A validated identifier doubles as a filesystem path segment: the
    /// identifier names the thing stored under a root, so `AsRef<Path>` is
    /// used directly as the component and the stored entry is reachable only
    /// through that validated name.
    #[test]
    fn identifier_doubles_as_a_path_segment() {
        let env = crate::test_support::fixture_env();
        let dir = crate::test_support::fixture_tmpdir(&env).expect("fixture tmpdir");
        let id = Identifier::parse("wave-1").expect("valid identifier");
        let path = dir.path().join(id.as_ref());
        assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("wave-1")));
        std::fs::write(&path, b"x").expect("write through the identifier path");
        assert_eq!(std::fs::read(&path).expect("read back"), b"x");
    }

    /// The digest predicate is exactly the 64-lowercase-hex sha256 form
    /// `crate::digest::sha256_bytes` produces; every other class is rejected.
    #[test]
    fn valid_hex_digest_requires_64_lowercase_hex() {
        assert_eq!(DIGEST_TEST_HEX_1, crate::digest::sha256_bytes(b""));
        assert!(valid_hex_digest(DIGEST_TEST_HEX_1));
        for bad in [
            "",
            "abc",
            &DIGEST_TEST_HEX_1.to_uppercase(),
            &format!("sha256-{DIGEST_TEST_HEX_1}"),
            &format!("{DIGEST_TEST_HEX_1}ff"),
            &DIGEST_TEST_HEX_1[..63],
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(!valid_hex_digest(bad), "{bad:?} must be rejected");
        }
    }

    /// The independent characterization of the name rule: a value is a safe
    /// filesystem ASCII single path segment iff it is non-empty, at most
    /// [`crate::atomic::NAME_MAX`] bytes, uses only `[a-zA-Z0-9._-]`, is not a
    /// `.`/`..` traversal component, never starts with `-` (a leading dash
    /// invites option-parser confusion), and names or can alias no crate
    /// bookkeeping spelling ([`crate::reserved::is_unaddressable_name`]).
    fn is_safe_segment(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= crate::atomic::NAME_MAX
            && !s.starts_with('-')
            && s != "."
            && s != ".."
            && !crate::reserved::is_unaddressable_name(s)
            && s.bytes().all(|b| {
                matches!(
                    b,
                    b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.'
                )
            })
    }

    /// Arbitrary name/path-segment values covering every traversal class:
    /// `..`, `.`, `/`, `\`, empty, whitespace, control characters, unicode,
    /// leading dashes, and clean single segments.
    fn arbitrary_segment_text() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                String::new(),
                ".".to_string(),
                "..".to_string(),
                "...".to_string(),
                "/".to_string(),
                "\\".to_string(),
                "a/b".to_string(),
                "a\\b".to_string(),
                "../x".to_string(),
                "x/..".to_string(),
                "./x".to_string(),
                "x/.".to_string(),
                " x".to_string(),
                "x ".to_string(),
                "x y".to_string(),
                "\u{0}".to_string(),
                "a\nb".to_string(),
                "α".to_string(),
                "-lead".to_string(),
                "-x".to_string(),
                "s1".to_string(),
                "wave-1".to_string(),
                "a..b".to_string(),
                "a.b".to_string(),
                "a_b-c.d9".to_string(),
                // The RESERVED spellings: refused even though they are safe
                // single segments, because a whole-store sync strips them.
                ".sync-aside.1".to_string(),
                ".sync-aside.123.0".to_string(),
                ".001.operation.lock".to_string(),
                // Near-misses that stay ORDINARY in the reserved MATCH (the
                // application lock record below is refused by the id rule as
                // UNaddressable, not by the reserved match).
                "sync-aside".to_string(),
                ".sync-aside".to_string(),
                "a.operation.lock".to_string(),
                // The crate's own lock record and its case alias: refused as
                // UNaddressable, not by the byte-exact reserved MATCH.
                "operation.lock".to_string(),
                "OPERATION.LOCK".to_string(),
            ]),
            prop::collection::vec(prop::char::any(), 0..12).prop_map(|v| v.into_iter().collect()),
        ]
    }

    proptest! {
        // THE PROPERTY: the identifier accepts EXACTLY the safe single-
        // segment values — every traversal class (`..`, `.`, `/`, `\`,
        // padding, control chars) is rejected, every clean single segment is
        // accepted. Bounded cases (`proptest_cases(64)` is 16 by default and
        // 64 with the full suite requested), fixed seed 0x5EED_5EED (house
        // style), no failure persistence — the identical vectors on every
        // run.
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(64),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn identifier_accepts_exactly_safe_single_segments(s in arbitrary_segment_text()) {
            let expected = is_safe_segment(&s);
            assert_eq!(
                Identifier::parse(&s).is_ok(),
                expected,
                "Identifier must accept exactly safe single segments: {s:?}"
            );
        }
    }

    /// An exhaustive (rather than random) check that `valid_name` agrees with
    /// its independent characterization over every string up to the allowed
    /// alphabet's length limit: one character by default, three characters
    /// when the full suite is requested. The alphabet includes the
    /// traversal (`/`, `\`, `.`), the leading-dash, and the separator classes
    /// so every rejection rule is exercised.
    #[test]
    fn valid_name_agrees_with_the_independent_characterization() {
        let max_len = if crate::test_support::slow_tests_enabled() {
            3
        } else {
            1
        };
        let alphabet = ['a', 'Z', '0', '-', '_', '.', '/', '\\'];
        for len in 1..=max_len {
            for combo in 0..alphabet.len().pow(len as u32) {
                let mut s = String::new();
                let mut n = combo;
                for _ in 0..len {
                    s.push(alphabet[n % alphabet.len()]);
                    n /= alphabet.len();
                }
                assert_eq!(valid_name(&s), is_safe_segment(&s), "{s:?}");
            }
        }
    }
}
