# Architecture

- React and TypeScript render the mission workspace, tool catalog, activity, and settings.
- Tauri 2 exposes a narrow command bridge.
- Rust owns the adapter registry, validation, AI connection, and process execution.
- Ollama is accessed only at 127.0.0.1:11434. AI output is displayed as a plan and never parsed into executable commands.
- Tool output is rendered as text, not HTML. The backend builds argument arrays and never invokes a shell.

## Trust boundaries
Mission text and model output are untrusted. Only hard-coded adapters can execute. Targets must pass validation and execution requires an authorization acknowledgement. The app does not request root privileges or store provider credentials.

## Known limitation
The current 45-second wrapper does not reliably kill a child process that hangs because execution uses a blocking output call. Before production, use managed child processes with kill-on-timeout, cancellation, streaming output, and OS resource limits. Job history is in-memory for the active UI session.
