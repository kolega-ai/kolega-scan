# Ground-Truth Slices

A **slice** is a named subset of GT repos used for targeted evaluation. The design
is **canonical findings + manifest slices**: GT lives once under
`ground-truth/findings/<repo>/ground-truth.json`; slices are thin YAML manifests
under `ground-truth/slices/` that reference repos by name. No GT is duplicated.

## Two forms (`oneOf`)

```yaml
# terminal — lists repos directly
repos:
  - realvuln-juice-shop
  - realvuln-dvws-node
```

```yaml
# composition — unions other slices
include:
  - human-curated
  - vibe-coded-python
  - js-ts
```

Exactly one of `repos` / `include` per file (validated against the packaged
`slice.schema.json`).

## Resolution semantics

`resolve_slice(name, slices_dir)` recursively flattens `include`, deduplicates,
and returns a **sorted** repo list (deterministic output). It
raises `SliceCycleError` on include cycles and `SliceReferenceError` on dangling
references.

## Orthogonal membership

`authorship` and `language` are independent per-repo properties, so a repo lands
in **every** slice whose rule it satisfies — overlap is by design:

| authorship | language | slices |
|---|---|---|
| human_authored | python | human-curated |
| llm_generated | python | vibe-coded-python |
| human_authored | javascript | human-curated **and** js-ts |
| llm_assisted | typescript | vibe-coded-python **and** js-ts |

## Adding a slice

Create one YAML file under `ground-truth/slices/<name>.yaml` (name matches
`^[a-z][a-z0-9-]+$`). Use `repos:` for a terminal set or `include:` to compose.
That is the only step.
