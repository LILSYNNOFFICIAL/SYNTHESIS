# SYNTHESIS

Professional AI-assisted graphical workspace for Kali Linux. Describe a goal, get a reviewable mission plan, and run supported tools through a polished desktop GUI.

**Status:** early development preview, not yet a production-hardened replacement for every terminal workflow.

## Features
- Rust + Tauri 2 desktop shell; React + TypeScript UI.
- Local Ollama planning with deterministic offline fallback.
- Initial allowlisted adapters: Nmap, ping, dig, WHOIS.
- No arbitrary shell execution; argument arrays are passed directly.
- Target validation, authorization acknowledgement, captured output, report export.
- CI for frontend build and Rust tests.

## Requirements
Linux desktop, Node.js 20+, npm, Rust stable, Cargo, and Tauri Linux prerequisites: https://v2.tauri.app/start/prerequisites/#linux. Optional Ollama: https://ollama.com/. Optional tools: nmap, iputils-ping, dnsutils, whois.

## Run
    npm install
    npm run tauri dev

Frontend preview: npm run dev
Checks: npm run check; cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check; cargo test --manifest-path src-tauri/Cargo.toml
Build: npm run tauri build

## Safety
SYNTHESIS is intended for systems and networks you own or are explicitly authorized to assess. AI plans are advisory and cannot execute commands. Only registered adapters can launch tools; user text is never evaluated by a shell. The authorization acknowledgement is a guardrail, not proof of permission. The process manager needs stronger cancellation and timeout termination before production. See docs/ARCHITECTURE.md and docs/ROADMAP.md.

MIT license. See LICENSE.
