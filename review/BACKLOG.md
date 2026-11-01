# Review backlog

Only work promoted from whole-codebase reviews belongs here. Every entry is ready for separate work and carries a `Findings:` line naming the raw review findings it covers; each finding maps to at most one entry. Claiming and resolving follow [docket/TODO_GUIDE.md](../docket/TODO_GUIDE.md); promotion follows [docket/CODE_REVIEW_GUIDE.md](../docket/CODE_REVIEW_GUIDE.md).

## P0 Critical

## P1 High

## P2 Normal

## P3 Low

## Unprioritized

- [NATIVE] `parse-pkgbuild-literal-boundaries` — **Respect Bash comments and strings when editing literal package fields.** Valid helper input must remain editable without corrupting its source.
  - Source: [full review](2026-10-31-2121-full.md), 2026-10-31.
  - Findings: `dependency-comment-closes-array`, `quoted-description-counts-as-assignment`
  - Starting point: `mpkg` functions `literal_dependencies` and `update`.
  - Cover parentheses in array comments and assignment-shaped lines in multiline descriptions. Preserve all dependencies and unrelated source, validate output syntax, and reject unsupported input before writing without executing dependency expressions.

- [NATIVE] `refresh-active-architecture-dependencies` — **Refresh the complete dependency set for the active architecture.** Matching package versions must not hide missing architecture-specific dependencies.
  - Source: [full review](2026-10-31-2121-full.md), 2026-10-31.
  - Findings: `refresh-omits-architecture-dependencies`
  - Starting point: `mpkg` functions `dependencies`, `install`, and `refresh`.
  - Exercise architecture-only and mixed dependency lists with a matching installed package version; assert checking, installation and marking, while excluding other architectures.

- [TOOLING] `isolate-refresh-test-call-evidence` — **Assert each refresh invocation against its own command log.** Earlier builds must not satisfy later rebuild assertions.
  - Source: [full review](2026-10-31-2121-full.md), 2026-10-31.
  - Findings: `refresh-test-reuses-command-log`
  - Starting point: `tests/test_mpkg.py:test_refresh_no_rewrite_or_commit_and_provider_resolution`.
  - Clear or slice the log per invocation. Removing the missing-dependency rebuild predicate must fail the test, while the unchanged helper must pass.
