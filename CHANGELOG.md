# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-07

First release. Everything below is implemented and covered by the test suite
except where a note says otherwise.

### Added

- `pocgate baseline`: builds the target, starts its service, runs every
  declared PoC `repeats` times, and records `.pocgate/baseline.json`. A PoC that
  does not fire on every run produces `INCONCLUSIVE`, exits 3, and writes no
  baseline (an earlier one is removed first).
- `pocgate verify --patch`: copies the target into a scratch directory, applies
  a git-style diff with `patch -p1 --batch --forward`, rebuilds, replays every
  PoC, runs the regression command before and after, and writes signed evidence.
  The working tree is never modified.
- Four verdicts as process exit codes: `CLOSED` (0), `STILL_VULNERABLE` (1),
  `REGRESSION_BROKEN` (2), `INCONCLUSIVE` (3), decided by a three-leg
  conjunction: every PoC fired pre-patch, none fires post-patch, no new
  regression failure.
- Three-state PoC classification: a run is `FIRED`, `SILENT` (only with a
  declared `silent_exit`), or `UNOBSERVED`. An unobserved run forces
  `INCONCLUSIVE`, so a crash or a 500 can never be read as a fix.
- `pocgate verify --json` prints canonical evidence JSON on stdout; `--fail-on`
  turns the verdict into a 0/1 CI gate with closure risk ordered
  `CLOSED < REGRESSION_BROKEN < STILL_VULNERABLE < INCONCLUSIVE`.
- `pocgate attest verify --pubkey`: recomputes the canonical sha256 digest,
  verifies the ed25519 signature, and rejects a file that is not byte-for-byte
  canonical. Offline; a sibling `.pub` is not accepted as a trust anchor.
- `pocgate demo`: runs a bundled synthetic target through baseline, a good
  patch (`CLOSED`), a partial patch (`STILL_VULNERABLE`), and a patch that adds
  a failing test (`REGRESSION_BROKEN`), then verifies the evidence. Measured at
  9.4 s on darwin/arm64 with Go 1.24.1.
- `pocgate doctor`: reports shell and `patch` availability, Go and curl, spec
  validity, service port availability, and signing-key readiness, as text or
  `--json`.
- `pocgate init`: writes a commented `pocgate.yaml` starter with the `target`,
  `oracles`, `regression`, and `labels` blocks; `--force` overwrites.
- `internal/spec` rejects unknown fields, applies documented defaults, and
  validates every referenced PoC file.
- Baseline and verification agree on a tree digest (path, content, mode), and
  `verify` refuses a stale baseline, a changed `pocgate.yaml`, or a patch that
  edits a PoC.
- CI workflow (gofmt, vet, `-race` tests, build) and a tag-driven release
  workflow that attaches linux/darwin/windows binaries for amd64 and arm64.

### Known limitations

- Linux and macOS only; target process management assumes POSIX process groups.
- Regression reports are read from stdout; there is no report-path field yet.
- `--sandbox docker`, SARIF adapters, and the enterprise remediation pack are
  not implemented in this release.

[0.1.0]: https://github.com/SuperMarioYL/pocgate/releases/tag/v0.1.0
