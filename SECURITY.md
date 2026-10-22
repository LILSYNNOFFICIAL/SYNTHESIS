# Security Policy

SYNTHESIS is an active-development security workspace, not a hardened production security product.

## Reporting

Please do not publish exploit details in public issues. Use GitHub's private vulnerability reporting if enabled, or contact the maintainers privately.

## Current safeguards

- Fixed allowlist of registered adapter IDs.
- Direct process invocation without shell interpolation.
- Host/IP/CIDR validation and bounded network scan scope.
- Explicit authorization acknowledgement before execution.
- AI output is advisory and cannot directly invoke tools.
- Child-process timeout and bounded output capture.
- Local-only Ollama endpoint; no cloud AI provider configured.
- No root privileges requested by the application.

These controls reduce risk but do not guarantee safety. Only assess assets you own or are explicitly authorized to test. Review every target and the expected impact before execution.
