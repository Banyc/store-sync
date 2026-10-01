//! This file exists to prove the exported `id_newtype!` macro survives
//! call-site hygiene.
//!
//! Integration tests are separate crates linking `store_sync`, so this file
//! invokes `store_sync::id_newtype!` with NO `use store_sync::...` and NO
//! `use serde::...`. Every path the macro needs is qualified (`$crate::...`,
//! `serde::...`, `std::fmt::...`), so any reliance on call-site imports
//! would fail to compile here.

/// The validator the macro's `$validator` slot takes: the contract is a
/// plain `fn(&str) -> bool`.
fn valid_probe_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

store_sync::id_newtype!(
    ProbeId,
    valid_probe_id,
    "A downstream-crate identity newtype: a non-empty ASCII token."
);

#[test]
fn exported_macro_builds_a_validated_newtype_at_the_call_site() {
    let parsed = ProbeId::parse("probe-1").expect("valid id parses");
    assert_eq!(parsed.as_str(), "probe-1");
    assert_eq!(parsed.to_string(), "probe-1");
    assert_eq!(parsed.clone().into_string(), "probe-1");

    let via_from_str: ProbeId = "probe-1".parse().expect("FromStr");
    assert_eq!(parsed, via_from_str);

    let via_serde: ProbeId = serde_json::from_str("\"probe-1\"").expect("Deserialize");
    assert_eq!(parsed, via_serde);

    let err = serde_json::from_str::<ProbeId>("\"bad/name\"")
        .expect_err("an invalid wire string must fail Deserialize (fail closed)");
    assert!(
        err.to_string().contains("invalid ProbeId value"),
        "the deserialization error is the identity's own validation error, got: {err}"
    );
}
