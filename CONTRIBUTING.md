# Contributing

Thanks for your interest in improving `ksu-profile-analyzer`! This is a short
guide to get you started.

## Development setup

1. Clone the repo.
2. (Optional) Create a Python venv:
   ```sh
   python3 -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   # or: .venv\Scripts\activate  # Windows
   ```
3. The skill uses only Python stdlib — no `pip install` needed for the core
   scripts.
4. External tools required for each pipeline:
   - **APK pipeline**: `apktool` (≥2.9), `jadx-cli` (≥1.5), `aapt2`, `unzip`
   - **Binary pipeline**: `binutils` (`readelf`, `objdump`, `nm`), `file`, `strings`
   - **Repo pipeline**: `ripgrep` (`rg`)
   - **Strace pipeline**: `strace` on the target Android device

## Repo layout

```
.
├── SKILL.md                      # skill entry point — the LLM reads this first
├── reference/                    # canonical docs the LLM consults as needed
│   ├── ksu_profile_schema.md
│   ├── capabilities.md
│   ├── groups.md
│   ├── selinux.md
│   ├── syscall_to_cap.md
│   ├── troubleshoot_selinux.md
│   ├── _refresh_log.md          # auto-appended by refresh_references.py
│   ├── _cache/                  # auto-populated (gitignored)
│   └── forks/                   # per-fork deltas (currently identical)
├── pipelines/                   # per-target-type analysis playbooks
│   ├── apk.md
│   ├── binary.md
│   ├── repo.md
│   ├── strace.md
│   └── refresh.md
├── templates/                   # Jinja2 templates + JSON skeletons
│   ├── profile_minimal.json
│   ├── profile_recommended.json
│   ├── analysis_report.md.j2
│   ├── apply.sh.j2
│   └── strace_capture.sh
├── scripts/                     # Python orchestration (stdlib only)
│   ├── apk_analyze.py
│   ├── binary_analyze.py
│   ├── repo_analyze.py
│   ├── strace_analyze.py
│   └── refresh_references.py
├── examples/                    # sample inputs + expected outputs
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE                       # GPL-3.0-or-later
└── .gitignore
```

## Making changes

1. Fork the repo, create a feature branch.
2. Make your changes. Run the smoke tests in `examples/`:
   ```sh
   python3 scripts/repo_analyze.py examples/demo-repo/
   python3 scripts/strace_analyze.py examples/strace-sample/
   ```
3. Verify the output matches `examples/expected-output/findings.json`.
4. If you change the reference docs (capabilities, groups, profile schema),
   regenerate them via:
   ```sh
   python3 scripts/refresh_references.py --force
   ```
5. Open a PR with a clear description. Reference the issue number if applicable.

## Adding a new capability mapping

1. Add the syscall/symbol to `reference/syscall_to_cap.md` (the canonical
   table the LLM consults).
2. Add the corresponding entry in `scripts/strace_analyze.py` `SYMBOL_MAP`
   (for binary pipeline) or `SYSCALL_NAME_MAP` (for strace pipeline).
3. If the mapping is path-based (e.g. `write` to `/sys/kernel/config/...`),
   add to `PATH_MAP` instead — the same map serves both the `openat` handler
   and the `write/read` fd-path handler.
4. Add a smoke-test case in `examples/` covering the new mapping.

## Adding a new fork

1. Add `reference/forks/<fork-name>.md` documenting the fork's schema deltas
   (if any) and source URLs.
2. Update `reference/forks/_diff_table.md`.
3. Add the fork's source URLs to `scripts/refresh_references.py` `SOURCES` list.
4. Update the fork detection hint in `SKILL.md` and the apply script template
   (`templates/apply.sh.j2`) to recognize the new fork's daemon name.
5. Add a fork-specific `profile.<fork>.json` to the output bundle (the skill
   already emits 3 JSONs — one per fork — and the `_meta.target_fork` field
   distinguishes them).

## Adding a new analysis pipeline

1. Create `pipelines/<name>.md` describing the tool chain, the parsing rules,
   and the signal-to-capability mapping for the new target type.
2. Add `scripts/<name>_analyze.py` (stdlib only, returns findings.json with
   the standard shape documented in `pipelines/<name>.md`).
3. Add a section to `SKILL.md` describing when to dispatch to the new pipeline.
4. Add a smoke-test case in `examples/`.

## Releasing a new version

1. Update `CHANGELOG.md` with the new version and changes (follow Keep a
   Changelog format).
2. Tag the release: `git tag vMAJOR.MINOR.PATCH`.
3. Push tags: `git push --tags`.
4. Build the `.skill` package (uses the skill-creator's `package_skill.py`):
   ```sh
   cd <skill-creator-path>
   python3 -m scripts.package_skill <this-repo-path>
   ```
5. Attach the resulting `.skill` file to the GitHub release so users can
   install via direct download OR via `npx skills add <your-user>/<repo>`.

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: incompatible schema changes (e.g. a `Profile` field renamed or
  removed, breaking change to the `findings.json` shape, breaking change to
  the analysis.md template that consumers depend on).
- **MINOR**: new features (new pipeline, new capability mapping, new fork
  support) — backwards-compatible.
- **PATCH**: bug fixes — backwards-compatible.

## License

By contributing, you agree that your contributions will be licensed under the
project's LICENSE (GPL-3.0-or-later). The reference docs in `reference/` are
derived from KernelSU source (GPL-3.0-or-later), so the whole project is
distributed under GPL-3.0-or-later for license consistency.
