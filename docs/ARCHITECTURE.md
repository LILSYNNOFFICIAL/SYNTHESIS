# Architecture

## Components

- **React + TypeScript:** mission entry, plan review, tool catalog, execution confirmation, result inspection, local activity, settings.
- **Tauri 2:** desktop shell and a narrow invoke-command bridge.
- **Rust:** adapter registry, target validation, command argument construction, timeout management, output bounding, and local AI HTTP calls.
- **Ollama:** optional local model endpoint at `127.0.0.1:11434`; model discovery uses `/api/tags`, mission planning uses `/api/chat`, and GUI model downloads use `/api/pull` with a fixed model allowlist.
- **Local webview storage:** recent jobs, latest output, and model preference. This is convenience persistence, not encrypted storage.

## Execution flow

1. The user describes an objective.
2. Ollama produces a text-only plan, or the deterministic fallback is used.
3. SYNTHESIS extracts an explicit hostname, IP, or CIDR from the mission when possible, then independently validates it. The user can correct the target and selects a registered adapter recommended by the planner.
4. Rust validates authorization acknowledgement and target syntax.
5. Rust maps the adapter ID to a fixed executable and a fixed argument template.
6. The child process is started without a shell, dropped on timeout, and output is capped before it is returned to the UI.

AI output is never parsed into executable arguments. A tool cannot be launched solely because the model suggested it.

## Trust boundaries

- Mission text and model output are untrusted.
- The target field rejects URLs, shell metacharacters, leading option syntax, malformed hostnames, and malformed CIDRs.
- CIDR scanning is limited to /24 or narrower for IPv4 and /120 or narrower for IPv6.
- Only compiled adapter IDs can execute. The UI cannot submit an arbitrary executable.
- The process is not run with root privileges by SYNTHESIS.
- The local AI endpoint is fixed to loopback. There is no cloud provider integration in this build.

These controls reduce risk; they do not prove authorization or guarantee that every underlying tool is harmless. Review scope before running any assessment.

## Known limitations

- Output is returned after process completion; streaming and user-triggered cancellation are future work.
- Tool output is text-based and not normalized into common finding objects.
- Activity history uses local webview storage and is not encrypted.
- Adapter parameters are fixed per adapter rather than generated from a generic schema.
- A real Kali Linux build and smoke test remain release gates.
