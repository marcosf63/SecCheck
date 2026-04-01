# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development
uv sync

# Run tests
uv run pytest

# Run a single test file
uv run pytest tests/test_scanners.py

# Run a single test by name
uv run pytest tests/test_scanners.py::test_process_scanner

# Run the CLI (development)
uv run sec-check --help
uv run sec-check doctor --host <ip> --user <user> --identity ~/.ssh/id_ed25519
uv run sec-check quick  --host <ip> --user <user> --identity ~/.ssh/id_ed25519
uv run sec-check deep   --host <ip> --user <user> --identity ~/.ssh/id_ed25519

# Install as a tool globally
uv tool install .
```

## Architecture

**Flow:** CLI → `_build_connection` (merges CLI args + `~/.ssh/config`) → `SSHClient` (paramiko) → `RemoteExecutor` → scanners → reporters → output.

### Key layers

- **`app/cli.py`** — Typer commands (`quick`, `deep`, `doctor`). All three share `_build_connection` and `_run_scan` helpers. SSH config resolution lives here via `load_ssh_config`.
- **`app/ssh/`** — `SSHClient` (context manager wrapping paramiko), `RemoteExecutor` (executes remote shell commands, returns `CommandResult`). Use `executor.run_safe()` when command failure is non-fatal.
- **`app/scanners/`** — Each scanner extends `BaseScanner` and implements `_run(executor) -> ScanResult`. `BaseScanner.run()` wraps `_run` with error handling. `QUICK_SCANNERS` and `DEEP_SCANNERS` lists in `__init__.py` control what each scan type collects.
- **`app/models/`** — Pydantic models: `SSHConnection` (connection params), `ScanResult` (raw + parsed output per scanner), `Report` (aggregated sections dict + metadata).
- **`app/reporters/`** — Three reporters: `text_reporter` (Rich console), `json_reporter` (raw JSON), `llm_reporter` (structured JSON optimized for LLM consumption).
- **`app/utils/ssh_config.py`** — Parses `~/.ssh/config` to fill in omitted CLI options.

### Adding a new scanner

1. Create `app/scanners/my_scanner.py` extending `BaseScanner` with `name` and `_run`.
2. Import and add the instance to `QUICK_SCANNERS` or `DEEP_SCANNERS` in `app/scanners/__init__.py`.
3. Add to `__all__` in the same file.

`parsed_data` in `ScanResult` is untyped (`Any`) — scanners return whatever structure makes sense for their domain (lists of dicts are the convention).
