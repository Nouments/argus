# Go architecture

This branch is an architecture-only refactor of `develop`.

- `apps/agent`: endpoint telemetry/collection application; existing implementation is preserved.
- `apps/core`: central SIEM application. Its `internal` packages represent SIEM capabilities, not independent microservices.
- `apps/tui`: interactive Bubble Tea-oriented client. UI concerns stay isolated from SIEM core internals.
- `apps/dashboard`: intentionally excluded from this refactor and must remain untouched.
- `pkg`: reusable cross-application contracts and cross-cutting packages only.
- `proto`: transport contracts grouped by bounded responsibility.
- `services/`: removed from the architecture because empty service directories were prematurely modeling capabilities as deployable microservices.

No Go implementation is introduced by this refactor.
