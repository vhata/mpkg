# Review index

Historical codebase reviews are immutable snapshots; the newest snapshot is the current finding inventory. Fix PRs supply evidence; the next incremental review verifies and records closure. Process: [docket/CODE_REVIEW_GUIDE.md](../docket/CODE_REVIEW_GUIDE.md). Promoted work: [BACKLOG.md](BACKLOG.md). Newest first; the top row is the baseline for the next incremental review. An empty index means no review has been recorded, not that there are no defects.

| Review (UTC) | Type | Reviewed commit | Open findings at close |
| --- | --- | --- | --- |
| [2026-10-31 21:21](2026-10-31-2121-full.md) | Full | `49d12c4d3a4bcf6f6c7b42b9518af8ab5323faac` | 6 |

<!-- This section must stay below the index table: review-due.sh reads the first table row with a backticked commit as the latest review. -->
## Pending reconciliation

Findings whose fix has landed with independent verification but whose closure the next review has not yet recorded. The next incremental review verifies each and clears the list.

| Finding | Fix PR and commit | Reviewer | Evidence |
| --- | --- | --- | --- |
| `update-marks-raw-requirements` | [#2](https://github.com/vhata/mpkg/pull/2), `db235dd` | `/root/dependency_target_review` | Original versioned/virtual update failures reproduced; strict installed-name regressions and 202-test suite passed. |
| `refresh-selects-unsatisfying-providers` | [#2](https://github.com/vhata/mpkg/pull/2), `db235dd` | `/root/dependency_target_review` | Incompatible-provider reproduction, 18 native-vercmp cases and mutation checks passed; [review](https://github.com/vhata/mpkg/pull/2#issuecomment-6563651617). |
