# Repository Guidelines

## Project Structure & Module Organization
`zagora/` contains the runtime package:
- `cli.py`: command parsing and user-facing commands.
- `server.py`: lightweight HTTP registry server.
- `registry.py`, `config.py`, `exec.py`: registry API calls, config resolution, and local/SSH command helpers.
- `__main__.py` and `__init__.py`: package entry points.

`tests/` contains unit tests (`test_commands.py`, `test_server.py`, `test_config.py`) built with `unittest`.  
`install.sh` is the end-user installer script.  
`pyproject.toml` defines packaging metadata and the `zagora` console script.
`mobile/android/` is an Android MVP controller app (Compose + Retrofit).

## Build, Test, and Development Commands
- `python -m venv .venv && source .venv/bin/activate`: create and activate a local dev environment.
- `pip install -e .`: editable install for local development.
- `python -m unittest discover -s tests -v`: run the full test suite.
- `python -m unittest tests.test_server -v`: run one test module during iteration.
- `python -m zagora --help`: verify CLI entrypoint and available commands.
- `cd mobile/android && bash scripts/verify_android_env.sh`: verify Android local build prerequisites.
- `cd mobile/android && gradle :app:assembleDebug`: build Android debug APK (JDK 17 + SDK required).

## Coding Style & Naming Conventions
- Follow PEP 8 with 4-space indentation and clear, small functions.
- Prefer type hints (`str | None`, `list[str]`) for new/updated Python code.
- Use `snake_case` for functions/variables, `UPPER_CASE` for constants, `CamelCase` for test classes.
- Keep CLI errors actionable and explicit (match existing `ZagoraError` usage).
- Keep shell snippets in code and scripts POSIX-friendly where possible.

## Testing Guidelines
- Use `unittest` and `unittest.mock` (current project standard).
- Add tests with every behavior change, especially for CLI parsing and server/registry edge cases.
- Name files `test_*.py`, classes `Test*`, and methods `test_*`.
- Prefer focused unit tests over broad integration tests; mock network/SSH boundaries.

## Commit & Pull Request Guidelines
- Keep commit subjects short, imperative, and lower-case, consistent with history (for example: `fix sync definitive-empty pruning`, `support connect-first shorthand in REPL`).
- One logical change per commit; avoid mixing refactors with behavior changes.
- PRs should include a concise problem/solution summary, test evidence (exact command and result), linked issue/context when relevant, and CLI output snippets for user-visible command behavior changes.

## Security & Configuration Tips
- Do not commit real hostnames, tokens, or SSH secrets.
- Prefer environment variables (`ZAGORA_HOST`, `ZAGORA_TOKEN`) for local secrets.
- When touching config behavior, preserve precedence: CLI > environment > config file.
