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
| 3 | **Containment has one authority and it consumes kinds, not resolutions.** A caller supplies an entry-kind view; it never supplies a resolution function. | three hand-rolled resolvers, one of which projected from the live source tree and accepted an escape while the other two refused it. | partial |
| 4 | **Every condition a caller must branch on is a typed value.** | string matching in callers, and message-shape coupling in the impl. | partial (`ReservedKind`) |
| 5 | **The reserved spellings a break may touch are a value, unforgeable outside the crate.** | the residual list as prose. | done (`Sanction`, `GuardedRel`) |
| 6 | **Every bound is a constant with its reason stated**, and no derived value feeds a length-limited resource unbounded. | ad-hoc length arithmetic at each site. | done |
| 7 | **One direction of data flow per type**: a type that is read is not the same type that is written. | mode/kind re-reads, and the checks that exist only to catch a caller passing the wrong one. | planned |
| 8 | **The crate's own contract is not reachable by accident**: the weak, unverified or unenforced path is reachable only through a name that states it. | the "documented but not enforced" bullets. | planned |

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
