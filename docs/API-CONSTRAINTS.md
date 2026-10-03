# API constraints

The public API exists to make the implementation small. Every constraint added
here is one the impl would otherwise re-derive, re-check, or document — and
each of the constraints below was earned by a defect that the *absence* of the
constraint made possible.

The measure of a constraint is not elegance; it is how many branches, checks and
sentences disappear from `src/`.

| # | Constraint | Removes from the impl | Status |
|---|---|---|---|
| 1 | **A mutation is named one way: `(&RootDir, &RootedRelativePath)`.** No public primitive takes a raw `&Path`. The path is parsed once, at the boundary, into a validated type; the type is the only input a mutating primitive accepts. | the private `validate_rel` guard (its looser rule was re-derived at every `_fd` primitive and at the Windows port's `rel_join`); the "which spelling did the caller use" branches; the public path-based `set_private`, `sync_parent_dir`, `ensure_private_dir(_durable)` and `remove_dir_all_path` spellings; and the *class* where a path-based primitive shipped missing the guard its `_fd` twin had. | **done** |
| 2 | **Ownership is one axis, not six entry points.** `sync`/`push`/`pull` × owned/unowned collapse to one function taking an `Ownership` value that only the lock-taking path can construct. | five near-duplicate entry bodies; the "call the right one" prose; a documented limitation that exists only because the weak path is a separate function. | **done** (`DestinationOwnership`; `DestinationOwnership::lock` is the unforgeable acquiring constructor) |
| 3 | **Containment has one authority and it consumes kinds, not resolutions.** A caller supplies an entry-kind view; it never supplies a resolution function. | three hand-rolled resolvers, one of which projected from the live source tree and accepted an escape while the other two refused it. Verified: all three views build `SymlinkContainmentIndex` from `live_entry_kinds`, the rule and the index are `pub(crate)`, and no API accepts a resolver. | **done** |
| 4 | **Every condition a caller must branch on is a typed value.** Each class whose conditions a caller must tell apart carries a public kind enum and every error variant names it: `ReservedKind` (reserved-spelling refusals), `MaterializationKind` (address-fidelity and wire refusals, plus `RootsOverlap`/`ParentNotClosed`), `StoreKind` (the tree copy's source-audit refusals, the residue gate, and visible-but-unconfirmed durability), and `TransportKind` (the manifest-failure LAYERS — unreachable host vs far-side script vs missing `perl` vs output-drain vs undetermined — the receiver-marker conditions, a non-directory root, and remote durability). The message is preserved VERBATIM so a text-matching caller keeps working; `with_context` preserves the kind. | string matching in callers (the manifest-failure layer tests, the copy-source-audit tests, the roots-overlap test and the receiver-marker tests all had to match message substrings to tell two conditions apart), and the mutation where two layers collapsed onto one kind stayed green under message assertions but is caught by the kind assertions. | **done** (`ReservedKind`, `MaterializationKind`, `StoreKind`, `TransportKind`) |
| 5 | **The reserved spellings a break may touch are a value, unforgeable outside the crate.** | the residual list as prose. | done (`Sanction`, `GuardedRel`) |
| 6 | **Every bound is a constant with its reason stated**, and no derived value feeds a length-limited resource unbounded. | ad-hoc length arithmetic at each site. | done |
| 7 | **One direction of data flow per type**: a type that is read is not the same type that is written. | mode/kind re-reads, and the checks that exist only to catch a caller passing the wrong one. | planned |
| 8 | **The crate's own contract is not reachable by accident**: the weak, unverified or unenforced path is reachable only through a name that states it. | the "documented but not enforced" bullets. | **done** (see "What constraint 8 closed" below; one stated residual remains by decision) |

## What constraint 8 closed

The audit is every PUBLIC path whose guarantee is weaker than the crate's
default, or that is unverified/unenforced. Each item is resolved as **N** (the
weak path is legitimate and its NAME now states it), **C** (the path is
constrained so it cannot be reached by accident), or **R** (a stated residual,
named AT the item with its reach).

* **C — the wire assembler's completeness precondition.**
  `manifest::canonicalize_remote_entries` takes the far side's stdout as `&str`
  but REQUIRES the caller to have checked the walk's exit status, which the
  signature does not carry. The public entry points are now
  `canonicalize_remote_entries_checked(output, root, exited_zero)` and
  `canonicalize_remote_entries_destination_checked(...)`; both refuse `false`
  with the TYPED `MaterializationKind::IncompleteListing` BEFORE assembly. The
  raw `(&str, &Path)` forms are `pub(crate)`, and the crate's OWN remote path
  passes `out.success()` at the call site, so the precondition is enforced by
  the type of call, not a paragraph. The pre-fix hole — "the string alone was
  enough to assemble an incomplete listing" — is closed by the API shape, and
  `checked_assembler_refuses_a_nonzero_walk_exit` pins the refusal and its
  typed kind.
* **C — the unconfined atomic replace.** `atomic::write_atomic_replace(path:
  &Path)` was the ONE public mutation that did not take `(&RootDir,
  &RootedRelativePath)`; it stayed public only because an integration test used
  it. It is now `pub(crate)` (test-only on Unix, where no production body
  needs it; the body of the fd surface on Windows), and a `compile_fail`
  doctest in `atomic`'s module docs proves a caller cannot name it. Its F-A1
  integration proof now drives the CONFINED public replace
  (`write_atomic_replace_fd`), assertions unchanged.
* **C — `Remote::exists`.** A public `bool` existence probe that swallowed
  EVERY error (permission, transport fault) as absence; the trait's own
  `metadata_opt` doc said callers must never consult it. It is REMOVED from
  the trait: `metadata_opt` is the only existence primitive, and the few tests
  that used it now branch on the typed `Ok(None)`/`Err` distinction.
* **R — `Remote::exec`.** The raw command seam: it runs a caller-built
  command, bypassing the operation lock, path confinement and the crate's own
  operation protocol. It cannot be closed without removing the seam every
  shelling-out `Remote` default is built on, so the reach is stated at the
  trait method.
* **R — `Remote::fsync_tree` / `Remote::fsync_parent` defaults.** Both default
  to a no-op; a production `Remote` that does not override silently makes
  nothing durable. The reach is named at each default (the production
  transports override both).
* **R — `Remote::remove_file_if`'s default.** The trait default is the
  NON-ATOMIC read-compare-remove; the reach is named at the default. The
  production path is additionally bounded to the ONE lock record the layout
  OWNS by an identity-checked `OwnedLockRecord` capability, so a public caller
  cannot break a record the protocol does not own.
* **R — `remote` weaker paths already named at the item**: the destination
  tolerance is reachable only through the `*_destination` names (`UnsupportedPolicy`
  is private); the Windows port's weaker guarantees are stated on every
  primitive and in `atomic::COMPONENT_CONFINED`; `Remote::copy_tree`'s SSH
  `cp -a` asymmetry is stated on the trait method; `EntryPolicy::AppendTail`
  carries its lost-update warning.
* **R — `reserved::is_reserved_name` / `is_reserved_path`** are NARROWER than
  `is_unaddressable_name` / `is_unaddressable_path` by design (byte-exact
  reserved MATCHING for the sync's strip, versus the identity rule). The
  README names this at the authority; they are not the "may I use this name"
  oracle.
* **Out of scope — `Tracer::new(enabled: bool)`.** Rule 2's boolean clause is
  about a DESTRUCTIVE choice; a tracer's `false` is the safe, side-effect-free
  default, so there is no weaker guarantee to name.

The one deliberate pin move this cost is recorded in `docs/CONSISTENCY.md`
("I"): gating the unconfined replace test-only on Unix removed its
`std::fs::rename` from the production count.

## Rules for adding a constraint

- **State what it removes.** A constraint that removes no branch is decoration.
- **Prove the delta.** Before replacing a runtime check with a type, enumerate
  what the check refused and what the type refuses. They are rarely equal — the
  validated-path type is *stricter* than the check it replaces, and that
  difference is a behaviour change, not a refactor.
- **Flipping a test that encoded the looser rule is explicit**, with the reason
  recorded. A silent flip is a lost assertion.
- **A constraint that only the crate can construct is worth more than one the
  caller can build**: unforgeable is the difference between a rule and a
  convention.
