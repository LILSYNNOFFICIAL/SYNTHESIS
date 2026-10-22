# Roadmap

## Implemented foundation

- [x] Rust + Tauri 2 desktop shell and React/TypeScript UI
- [x] Professional dashboard, mission planner, tool catalog, activity, settings
- [x] Local Ollama mission planning with deterministic fallback
- [x] Local Ollama model discovery, selection, and allowlisted GUI downloads
- [x] Structured AI plans with validated adapter recommendations and target extraction
- [x] Eleven fixed adapters: Nmap, ping, traceroute, dig, MX/TXT/NS records, host, WHOIS, HTTP headers, HTTP status
- [x] Target validation, authorization acknowledgement, direct argument arrays, bounded CIDR scan size
- [x] Managed child-process timeout and output cap
- [x] Locally persisted recent activity and text report export
- [x] Frontend and Rust CI workflow

## Product completion work

- [ ] Verify CI on the latest main commit and repair any failures
- [ ] Build and smoke-test .deb/AppImage on a real Kali Linux desktop
- [ ] Add live stdout/stderr streaming and explicit cancellation
- [ ] Add persistent backend job store and structured report format
- [ ] Add adapter manifest/schema system with per-adapter parameter forms and validation
- [ ] Add parsers for Nmap XML and common tool result formats
- [ ] Add adapter-level integration tests using stub executables
- [ ] Add model hardware/RAM guidance and model pull instructions
- [ ] Add accessibility and keyboard-navigation audit
- [ ] Add signed release artifacts and checksums

## Adapter policy

Prioritize low-impact inventory, DNS, HTTP metadata, local diagnostics, and defensive audit tools. Each adapter needs a fixed argument builder, scope limits, timeout, output bounds, tests, and a plain-language description. Do not add unrestricted shell execution or allow model output to become executable commands.
