# API constraints

The public API exists to make the implementation small. Every constraint added
here is one the impl would otherwise re-derive, re-check, or document — and
each of the constraints below was earned by a defect that the *absence* of the
constraint made possible.

The measure of a constraint is not elegance; it is how many branches, checks and
sentences disappear from `src/`.

| # | Constraint | Removes from the impl | Status |
|---|---|---|---|
| 1 | **A mutation is named one way: `(&RootDir, &RootedRelativePath)`.** No public primitive takes a raw `&Path`, with ONE tolerated, deliberately-named exception: `atomic::write_atomic_replace(&Path)` is the UNCONFINED form (see #8). The path is parsed once, at the boundary, into a validated type; the type is the only input a mutating primitive accepts. | the private `validate_rel` guard (its looser rule was re-derived at every `_fd` primitive and at the Windows port's `rel_join`); the "which spelling did the caller use" branches; the public path-based `set_private`, `sync_parent_dir`, `ensure_private_dir(_durable)` and `remove_dir_all_path` spellings; and the *class* where a path-based primitive shipped missing the guard its `_fd` twin had. | **done** |
| 2 | **Ownership is one axis, not six entry points.** `sync`/`push`/`pull` × owned/unowned collapse to one function taking an `Ownership` value that only the lock-taking path can construct. The lock records a run holds are part of the SAME axis, not a parallel API: `DestinationOwnership::Locked` (sibling record) and `DestinationOwnership::LockedWithInRoot` (sibling record + the caller's in-root `Layout::lock`) are two unforgeable values of the one enum, produced by `DestinationOwnership::lock` and `DestinationOwnership::lock_with_in_root_lock`. | five near-duplicate entry bodies; the "call the right one" prose; a documented limitation that exists only because the weak path is a separate function; a `bool` parameter on the acquiring constructor (the composition is a named enum value, never a flag). | **done** (`DestinationOwnership`; `DestinationOwnership::lock` is the unforgeable acquiring constructor; `lock_with_in_root_lock` is the composed one) |
| 3 | **Containment has one authority and it consumes kinds, not resolutions.** A caller supplies an entry-kind view; it never supplies a resolution function. | three hand-rolled resolvers, one of which projected from the live source tree and accepted an escape while the other two refused it. Verified: all three views build `SymlinkContainmentIndex` from `live_entry_kinds`, the rule and the index are `pub(crate)`, and no API accepts a resolver. | **done** |
| 4 | **Every condition a caller must branch on is a typed value.** Each class whose conditions a caller must tell apart carries a public kind enum and every error variant names it: `ReservedKind` (reserved-spelling refusals), `MaterializationKind` (address-fidelity and wire refusals, plus `RootsOverlap`/`ParentNotClosed`), `StoreKind` (the tree copy's source-audit refusals, the residue gate, and visible-but-unconfirmed durability), and `TransportKind` (the manifest-failure LAYERS — unreachable host vs far-side script vs missing `perl` vs output-drain vs undetermined — the receiver-marker conditions, a non-directory root, and remote durability). The message is preserved VERBATIM so a text-matching caller keeps working; `with_context` preserves the kind. | string matching in callers (the manifest-failure layer tests, the copy-source-audit tests, the roots-overlap test and the receiver-marker tests all had to match message substrings to tell two conditions apart), and the mutation where two layers collapsed onto one kind stayed green under message assertions but is caught by the kind assertions. | **done** (`ReservedKind`, `MaterializationKind`, `StoreKind`, `TransportKind`) |
| 5 | **The reserved spellings a break may touch are a value, unforgeable outside the crate.** | the residual list as prose. | done (`Sanction`, `GuardedRel`) |
| 6 | **Every bound is a constant with its reason stated**, and no derived value feeds a length-limited resource unbounded. | ad-hoc length arithmetic at each site. | done |
| 7 | **One direction of data flow per type**: a type that is read is not the same type that is written. | mode/kind re-reads, and the checks that exist only to catch a caller passing the wrong one. | **done** (see "What constraint 7 closed" below) |
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
* **N — the unconfined atomic replace.** `atomic::write_atomic_replace(path:
  &Path)` is the ONE public mutation that does not take `(&RootDir,
  &RootedRelativePath)`. Its first resolution here was **C** (demoted to
  `pub(crate)`) on the ground that no production body needed it — but that
  ground covered THIS CRATE's production, not the CONSUMER's interface. The
  reason C was wrong, in one line: **the justification covered the crate's own
  production, not the consumer's interface** (deploy's Windows port calls the
  path-based `write_atomic_replace` in its own `store::atomic::windows`). It is
  PUBLIC again, and its NAME states the weakness: the UNCONFINED,
  absolute-path form, the one to avoid when the confined
  `write_atomic_replace_fd` can name the destination. `docs/CONSISTENCY.md`
  axis M records the population error.
* **N — `Remote::exists`.** A `bool` existence probe that swallows EVERY error
  (permission, transport fault) as absence. Its first resolution here was
  **C** (deleted from the trait) on the ground that the crate's own production
  and tests never needed it — the same population error: **the justification
  covered the crate's own production, not the consumer's interface.** deploy's
  own transport trait DECLARES `exists` as a REQUIRED method and its production
  calls
  it. It is a DEFAULT method again, delegating to `metadata_opt` (so no
  implementor is forced to write it, and an implementor may override with a
  cheaper probe), and its doc states EXACTLY what it discards — a `false`
  conflates *absent* with *the probe could not tell* — pointing a caller that
  must distinguish the two at `metadata_opt`. Naming the weakness, not deleting
  the name, is what the constraint requires.
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
  tolerance is reachable only through the `*_destination` names (the tolerant
  sink `RecordUnsupported` is private); the Windows port's weaker guarantees
  are stated on every
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

The pin move this pass first made — gating the unconfined replace test-only on
Unix removed its `std::fs::rename` from the production count — was REVERSED
when the demotion was; `docs/CONSISTENCY.md` ("I") records both the move and
the reversal.

## What constraint 7 closed

The manifest is produced, serialized, transferred, and read back, so the same
facts cross the wire in both directions. Three places let one type carry both
directions; each is now two.

* **The entry kind and mode are VALIDATED values, not wire spellings.**
  `TreeEntry.entry_type` is an `EntryKind` and `TreeEntry.mode` is a `u32`;
  the strings `"file"`/`"dir"`/`"symlink"` and the four-digit octal mode exist
  only across `Serialize`/`Deserialize`. **Removed:** the
  per-consumer projections — nine `EntryKind::of` sites (six fallible, two
  silently DROPPING a path with `let Ok(..) else { continue }`, one filtering)
  and seven `parse_mode(&entry.mode)` re-reads, plus the raw kind-string
  comparisons the typed field replaces. **Refusals moved:** the
  `unknown manifest entry type` refusal and the `invalid manifest mode`
  refusal now fire at the ONE wire boundary (`Deserialize`), so a malformed
  record cannot become a `TreeEntry` at all. **Wire format:**
  byte-identical; pinned by
  `manifest_entries_serialize_to_the_same_wire_strings` (the `type` string and
  the octal `mode`) and by the local/remote byte-identity test.
  `EntryKind` now lives in `manifest` (re-exported from `sync::diff`), and
  `EntryKind::of`/`from_manifest` are gone — the field IS the value.
* **The destination observation is a distinct type.** `DestinationTree`'s
  canonical payload is `pub(crate)`, so a destination observation cannot be
  serialized as a `tree.json`, cannot be fed to `verify_tree_metadata`, and
  cannot be used as a SOURCE manifest at the public boundary. It exposes only
  destination-role accessors (`entries`, `tree_sha256`, ...). **The direction
  is a TYPE at the entry points:** `diff_source_and_destination(&TreeMetadata,
  &DestinationTree)` and `apply_manifests(&TreeMetadata, &DestinationTree)`
  take the destination type in the destination position, while `diff_trees`
  stays for two canonical manifests. Two `compile_fail` doctests prove the
  wrong direction does not typecheck, each `E0308`
  (`expected &TreeMetadata, found &DestinationTree`; and the swap is
  `expected &DestinationTree, found &TreeMetadata`). `DestinationTree.meta`
  becoming `pub(crate)` is a breaking change to that field — the direction is
  the point — and `unsupported` stays public; `tests/consumer_fit.rs` does not
  use either and still compiles and passes.
* **The strict SOURCE walk no longer builds the destination type.**
  `UnsupportedPolicy` (a runtime mode, re-read at three `match` sites in each
  of the local walk and the wire assembler) and the deferred
  `unsupported_reason: Option<...>` per-entry state are gone. The policy is a
  TYPE (`UnsupportedSink`: `RefuseUnsupported` / `RecordUnsupported`), so the
  strict path allocates no `unsupported` list, keeps no per-entry "was this
  tolerated" state, and returns `TreeMetadata` by construction —
  `canonicalize_tree` and `canonicalize_remote_entries` cannot produce a
  `DestinationTree`.

**The delta, measured.** The typed field is STRICTER at the boundary in one
way and identical everywhere else: a mode string longer than the twelve
permission bits (or any non-octal spelling) is refused by `Deserialize` rather
than masked by `parse_mode` at first use — the refusal is the same, its SITE
moved. No input the old projections accepted is now refused, and no branch that
was load-bearing (the guard, the lock, the audit, the copy) was touched. The
source audits' pinned maps are unchanged: no `libc` or `std::fs` symbol was
added or removed.

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
