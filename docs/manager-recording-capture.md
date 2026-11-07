# Explicit input capture while recording

`record` and `adopt` accept `--capture-inputs` to establish private
baselines for every declared nonsecret file. The installed helper reads
those files under its verified host policy and records the bytes with
the decision. The unprivileged client transfers only the exact TOML
source; input bytes never enter the request or ordinary response.

```sh
.venv/bin/python -m mpkg_manager record environment.toml \
  --source-is-nonsecret --expected-revision 0 --capture-inputs
.venv/bin/python -m mpkg_manager adopt environment.toml \
  --source-is-nonsecret --expected-revision 1 --capture-inputs \
  --resource config
```

Use the actual reviewed revision from `current` or `history`.
The [recording client](manager-recording-cli.md) defines source
classification, authorization, selection and transport behavior.

## Scope and retained baselines

Each nonsecret input file must be explicitly classified `nonsecret` in the
declaration. Protected entries require the separate
[preparation flow](manager-protected-recording.md). Classification is the operator's responsibility, not secret
detection. Bytes remain in the private store even for this classification.
The source acknowledgement separately classifies the entire TOML text.

Capture includes every declared file, including bundles unrelated to an
adoption's selected resources. Resource authority remains limited to the
selected adoption. Each explicit capture records a fresh baseline;
later intent does not replace an older adopted resource's baseline.
Re-adoption can explicitly establish a new accepted baseline. Status
reports current and retained inputs separately.

Without the flag, recording preserves its declaration-only behavior and
does not read inputs. Such records remain valid with unavailable input
freshness. Status never silently fills in a missing capture. The flag is
not accepted by status, initialization, relinquishment or export.

The helper uses the existing
[authenticated complete-recording API](manager-recorded-input-evidence.md).
Its allowed roots, descriptor identity checks, 64-file and 64 MiB aggregate
capture limits, and 16 MiB per-file limit remain in force. Capturing files
does not prove complete effective Compose input closure or target-file
agreement, and does not inspect or apply resource properties.

## Failures and protected inputs

Reads occur outside the SQLite transaction while the helper owns its
mutation lock. Missing files, denied paths, symlinks, policy changes or
capture limits return the fixed `input_capture_rejected` error and exit 6.
No decision, snapshot or partial capture is published on those failures.
Revision conflicts remain explicit and stale requests do not read inputs.
Concurrent file reads are bounded observations, not writer exclusion or
an atomic filesystem snapshot.

The existing commit and transport uncertainty rules remain unchanged.
An uncertain response exits 7; the helper may have committed or may still
be running. Inspect current/history before deciding whether to retry.
There is no automatic retry or rollback claim. Filesystem reads and store
validation have no enforced wall-clock deadline; the client transport
deadline does not prove the helper stopped.

Protected recording declarations require `--prepared-inputs UUID` from
[`prepare-inputs`](manager-protected-recording.md), even with
`--capture-inputs`. The preparation authenticates the protected subset;
this flag additionally captures the nonsecret subset. Caller-supplied
references alone never authenticate protected bytes.

Private integration tests exercise real capture/store/status flows,
retained adoption baselines, no implicit reads, selection/revision races,
path refusals, partial capture failure, policy revocation, limits and
post-commit uncertainty. They substitute the helper transport and perform
no sudo, installed-helper, package, service or Docker operations.
