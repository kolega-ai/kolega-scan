# Versioning & Deprecation Policy (from v1.0.0)

We follow SemVer. What counts as MAJOR / MINOR / PATCH per surface, and
the deprecation path. The public surface is enumerated in [`PUBLIC_API.md`](../../PUBLIC_API.md)
and guarded by `tests/unit/test_public_surface_guard.py`.

## Output schemas
- **MAJOR**: remove/retype a field, change an enum value, change required-vs-optional.
- **MINOR**: add an optional field.
- **PATCH**: doc/generator change producing a byte-identical schema.
- Each schema's `$id` version moves independently of the package version.

## Detector interface + entry-point group
- **MAJOR**: change the `run` signature, required attributes, or the entry-point group name.
- **MINOR**: add an optional capability.

## CLI
- **MAJOR**: remove/rename a command or flag, change an exit code's meaning, change stdout shape.
- **MINOR**: add a command or optional flag.
- **PATCH**: help text / formatting.

## Python API
- **MAJOR**: remove/rename a public symbol or change a public signature incompatibly.
- **MINOR**: add a public symbol or optional parameter.

## Provisional items
`LLMClient` / `AgentResult` may change in MINOR releases (exempt from the MAJOR rule) until
promoted to stable in `PUBLIC_API.md`.

## Deprecation path
1. Mark deprecated: docstring note + `PUBLIC_API.md` annotation + (Python) a
   `DeprecationWarning`.
2. Keep for at least one MINOR release.
3. Remove only in the next MAJOR.

## Cluster labels
The `cluster_id` labels a distribution's detectors use are not part of the public
surface, so adding or changing them is **not** a version-affecting change; only the
`cluster_id` naming convention and its Finding/Detector coupling are.

## Making an intentional surface change
Edit the code, run `python scripts/regen_public_surface.py`, and commit the snapshot diff
in the same change — the guard then passes and the diff documents the surface change.
