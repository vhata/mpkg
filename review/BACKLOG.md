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
