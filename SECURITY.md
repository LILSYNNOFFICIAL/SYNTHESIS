# Security Policy

SYNTHESIS is an early development preview and is not yet a hardened production security product.

Please do not publish exploit details in public issues. Use GitHub private vulnerability reporting if enabled, or contact maintainers privately.

Current safeguards:
- Fixed allowlist of registered tool adapters.
- Arguments passed directly without shell interpretation.
- Target validation and authorization acknowledgement.
- AI plans are advisory and cannot directly invoke tools.
- No root privileges requested by the application.

These controls reduce risk but do not guarantee safety. Only test systems you own or are explicitly authorized to assess.
