//! This file exercises the exported `id_newtype!` macro at a call site that
//! imports nothing (`storekit::id_newtype!`, no `use`).
//!
//! LIMIT OF THIS TEST: an integration-test crate links the package's NORMAL
//! `[dependencies]` too (Cargo makes them available to `tests/`), so `serde`
//! and `serde_json` resolve here even if the macro expansion used a bare
//! `serde::` path. This file therefore CANNOT catch a regression to
//! consumer-unhygienic paths; the macro is written with `$crate::…` and
//! hand-written serde impls (see `id_newtype!`'s consumer contract) precisely
//! because a bare path compiles here yet fails in a real consumer. The
//! regression guard for THAT property is a consumer crate whose only
//! dependency is `storekit` (see the crate's `EXTRACTION.md` note); this
//! file remains the in-repo round-trip check for the generated impls.

/// The validator the macro's `$validator` slot takes: the contract is a
/// plain `fn(&str) -> bool`.
fn valid_probe_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

storekit::id_newtype!(
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
