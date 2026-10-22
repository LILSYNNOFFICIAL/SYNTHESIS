# Adding a SYNTHESIS adapter

SYNTHESIS deliberately does not execute arbitrary AI-generated shell commands. A new tool is added as a reviewed, fixed adapter in Rust and exposed through the existing tool catalog.

## Required implementation steps

1. Add the adapter ID, display name, category, description, executable, and impact label to `registry()`.
2. Add a fixed argument builder branch in `build_command()`. Never accept an executable name or raw argument string from the frontend or model.
3. Validate the target shape for that adapter. Reject option-like targets, URLs when a hostname is expected, malformed IP/CIDR values, and unsupported input characters.
4. Apply scope bounds and a timeout appropriate to the tool. Keep process invocation shell-free and output bounded.
5. Add tests for known-good input, malformed input, option injection, adapter registration, and the exact argument template.
6. Update the supported-adapter table in `README.md` and describe any impact or privilege requirements.
7. Verify `npm run check`, `cargo fmt --manifest-path src-tauri/Cargo.toml --all`, and `cargo test --manifest-path src-tauri/Cargo.toml`. Then build and smoke-test on Kali Linux.

## AI integration

The planner may recommend only a registered adapter ID. Rust filters the recommendation against the registry. The model never supplies an executable path or arguments. A recommendation only preselects a GUI adapter; it does not run anything. A target extracted from the user's mission is validated independently before execution.

## Safety policy

Prefer inventory, troubleshooting, DNS, HTTP metadata, TLS configuration, and defensive audit workflows. Do not add unrestricted shell execution or expose credential attacks, stealth, persistence, evasion, or destructive actions through a natural-language wrapper.
