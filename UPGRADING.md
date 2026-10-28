# Upgrading

`seal` is pre-1.0: a minor release may break the API. This file records the
steps for every breaking change.

## From v0.2.x to the API-diff tooling

There are **no public API changes** in this migration. The wire format and the
importable API are unchanged; `apidiff` against `v0.2.0` reports no
incompatibilities.

### 1. Remove `api.txt` regeneration from your tooling

The `api.txt` golden file, `api_test.go`, `TestAPIGolden`, the `-update-api`
flag, and the `mise run api` task no longer exist. Remove any CI or developer
script step that invoked the old task or flag; `mise run api-diff` is the
replacement for pre-merge API review.

### 2. Use `apidiff` for pre-merge API review

```bash
mise run api-diff
```

This compares the current importable API with the last root tag and ignores
`internal/...`. Pre-1.0, incompatible changes are reported but do not fail the
gate. Run it before opening a PR that changes an exported declaration. After
1.0, set `API_DIFF_STRICT=1` in CI to make incompatible changes fail.

### 3. Use `gorelease` for release validation

`gorelease` requires a clean tree, so it is not part of the dirty-branch gate.
The release workflow runs it on a tagged commit:

```bash
go run golang.org/x/exp/cmd/gorelease@v0.0.0-20261014143641-f0251eb4aa3e \
  -base=latest -version=vX.Y.Z
```

Use `-base=none` only for the first release of a new module. For `seal`, the
base is the latest published root tag.

### 4. Expect a larger `mise run check`

`mise run check` now runs `fmt-check`, `lint`, `build`, `test-all`,
`generate-check`, `vuln`, and `api-diff`. The first run may download the pinned
`apidiff` and `govulncheck` tools. `generate-check` is a tripwire for this
library: it verifies that no sqlc, buf, or `go:generate` input has appeared; if
one does, replace it with a real generation check.

## From v0.1.0 to v0.2.0

v0.2.0 is additive. The wire format and public API are unchanged. CAS adopted
v0.1.0 and can upgrade without a migration. Consumers that run the conformance
suites gain the additional checks listed in `CHANGELOG.md`.

## Release policy

- `v0.x.0` may break; `v0.x.y` is a fix.
- Every breaking change gets a changelog entry and a section in this file.
- `apidiff` reports incompatible changes; they must be documented here before a
  release, even while pre-1.0 allows them.
- `main` is tagged only after `mise run check` passes, and the release workflow
  runs `gorelease` on the clean tag.
- 1.0 makes incompatible changes fail (`API_DIFF_STRICT=1`) until a new major
  module path exists.
