# Bootstrapping OpenSpec and pytest-bdd

Run this preflight before the first BDD task when OpenSpec is unavailable, the repository is not
initialized, or the project interpreter cannot import `pytest_bdd`. Do not create scenarios or tests
during bootstrap.

OpenSpec requires a supported Node.js runtime; `pytest-bdd` requires Python 3.9 or newer. Runtime
installation is outside this bootstrap: report an unmet runtime as a blocker.

## Audit first

Inspect and report:

- `node --version`, `npm --version`, and `openspec --version`;
- the selected Python interpreter and resolved `pytest`/`pytest-bdd` versions;
- whether `openspec/` and the five local Codex workflows exist;
- the dependency manager, lockfiles, and virtual-environment convention; and
- `git status --short`.

A healthy setup makes no changes. If work is needed, show one summary and obtain one approval for
the declared global OpenSpec, generated repository, and project-local dependency changes.

## Initialize or refresh

For a repository without OpenSpec:

```powershell
openspec init --tools codex --profile core
```

For an initialized repository:

```powershell
openspec update
```

Do not rerun init over an initialized repository. Preserve existing `AGENTS.md` instructions and
inspect the generated diff. Verify with:

```powershell
openspec --version
openspec list --json
```

If the CLI cannot update global Codex prompts because of local permissions but creates the
repository-local `.codex/skills`, report that distinction; do not claim the global integration was
updated.

## Install local BDD dependencies

If no dependency manager is authoritative, use the tracked requirements file:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-bdd.txt
.\.venv\Scripts\python.exe -c "from importlib.metadata import version; import pytest, pytest_bdd; print(version('pytest')); print(version('pytest-bdd'))"
```

Use explicit interpreter paths in later commands. Keep `.venv/` and local evidence out of Git.

## Handoff

Report versions, selected interpreter, every generated path, final Git status, and the next exact
command (`/opsx:explore` or `/opsx:propose <change>`). Network, permissions, dependency resolution,
or import failures are blockers; show the failed command and error.

