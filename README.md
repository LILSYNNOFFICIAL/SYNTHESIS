# SYNTHESIS

**Plain-language security workflows for Kali Linux.**

SYNTHESIS is a local-first desktop workspace for people who want to use security and network tools without memorizing terminal syntax. Describe the goal, review a proposed plan, choose a registered adapter, confirm authorization, and inspect the results in a professional GUI.

> **Project status:** active development. The desktop foundation and 11 bounded adapters are implemented. A passing CI run and a real Kali Linux release install are still required before calling a build production-ready. SYNTHESIS does not claim to wrap every Kali package.

## What it does

- **Plain-language mission planning:** asks local Ollama for a reviewable workflow, with an offline fallback.
- **No dedicated GPU required:** Ollama can run small quantized models on CPU. Inference may be slower and needs enough RAM.
- **Registered tool adapters:** the app builds argument arrays itself. Model output is never executed as a command.
- **Target and scope checks:** rejects shell syntax, malformed hostnames, URLs in the target field, and overly broad CIDR scans.
- **Execution boundaries:** no arbitrary shell, no implicit root privileges, explicit authorization acknowledgement, per-run timeout, output cap.
- **Useful results:** captured stdout/stderr, recent activity stored locally in the app webview, and plain-text report export.
- **Local AI model selection:** discovers models installed in the local Ollama instance.

## Supported adapters

| Category | Adapter | Purpose | Executable |
|---|---|---|---|
| Network | Nmap | Version-light discovery of the 100 most common TCP ports | `nmap` |
| Network | Ping | Four bounded reachability probes | `ping` |
| Network | Traceroute | Route discovery, maximum 12 hops | `traceroute` |
| Web & DNS | DNS lookup | Standard DNS query | `dig` |
| Web & DNS | Mail records | MX record lookup | `dig` |
| Web & DNS | TXT records | TXT record lookup | `dig` |
| Web & DNS | Name servers | NS record lookup | `dig` |
| Web & DNS | Host lookup | Resolver lookup | `host` |
| Web & DNS | WHOIS | Public registration data | `whois` |
| Web | HTTP headers | Bounded HTTP/S response-header request | `curl` |
| Web | HTTP status | Status code, remote IP, request duration | `curl` |

The catalog detects whether each executable is available on the current machine. Install optional tools with your distribution's trusted package manager.

## Stack

- Rust backend and Tauri 2 desktop shell
- React + TypeScript + Vite frontend
- Ollama HTTP API at `127.0.0.1:11434` only
- GitHub Actions for frontend and Rust checks
- Linux `.deb` and AppImage bundle targets

## Build on Kali Linux

Install Node.js 20+, npm, Rust stable/Cargo, and the Tauri Linux prerequisites documented at [Tauri's Linux setup guide](https://v2.tauri.app/start/prerequisites/#linux). Then:

```bash
git clone https://github.com/LILSYNNOFFICIAL/SYNTHESIS.git
cd SYNTHESIS
npm install
npm run check
cargo fmt --manifest-path src-tauri/Cargo.toml --all
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri dev
```

Build Linux packages:

```bash
bash scripts/build-kali.sh
```

The build helper runs the frontend check, Rust tests, and Tauri package build in one command after system prerequisites are installed. To run each step manually, use the commands above.

Tauri writes package artifacts beneath `src-tauri/target/release/bundle/` (the exact output depends on the selected bundle target and installed build dependencies).

## Local AI without a powerful GPU

1. Install Ollama from [ollama.com](https://ollama.com/) and ensure its local service is running.
2. Open SYNTHESIS Settings and choose a small model such as `qwen2.5:0.5b`, `qwen2.5:1.5b`, or `llama3.2:1b`.
3. Click **Download selected model**. The app downloads only from its fixed model allowlist and refreshes the installed model list.
4. Test the connection. Small models can run on CPU, but generation may be slower and still needs enough RAM.

SYNTHESIS does not send mission text to a cloud AI provider. If Ollama is missing or unavailable, the app falls back to a deterministic checklist. The fallback is not generative AI.

## Security model

- Only adapter IDs compiled into the Rust registry can run.
- Targets are validated and arguments are passed directly to child processes, never through a shell.
- Mission text and model output are treated as untrusted data.
- Planning is separate from execution. The user must select a tool and confirm authorization.
- Tool runs have a timeout and bounded captured output.
- The app does not ask for root access. Some tools may offer reduced functionality without elevated privileges.

Only test assets you own or are explicitly authorized to assess. A confirmation checkbox is a guardrail, not proof of authorization. Review tool parameters and results before relying on them.

## Current limitations

- This is not a universal wrapper for every Kali package. Adapters must be added and tested intentionally.
- Tool output is currently captured when a process exits; live streaming and cancellation controls are not yet implemented.
- Activity history is stored in local webview storage, not an encrypted database.
- Report export is plain text. Structured findings, richer report formats, and adapter-specific parsers remain future work.
- The GitHub Actions workflow must pass, and the resulting package must be smoke-tested on a real Kali desktop before release readiness can be claimed.

## Contributing

See [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), [Adapter Authoring](docs/ADDING_ADAPTERS.md), and [Security Policy](SECURITY.md). Add adapters with fixed argument construction, narrow scope, bounded execution, tests, and clear documentation. Do not pass model-generated shell commands to the operating system.

## License

MIT. See [LICENSE](LICENSE).
