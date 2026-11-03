# Deployment Lifecycle

This doc explains exactly when and how a change in the repo lands in CrowdStrike. Read this before your first apply so you know what to expect.

## The short version

Merging an MR to `main` does NOT deploy. Deployment is a separate, manually-triggered CI stage. You must click ▶ on the `apply` job in the post-merge pipeline.

```
author → MR → validate → plan → merge → apply (MANUAL) → CrowdStrike
                                                             |
                                            auto-backfill Falcon-assigned ids to main
```

## Pipeline stages

| Stage | When it runs | Credentials | What it does |
|---|---|---|---|
| `validate` | Every push to any branch | none (no network) | Schema + format linting |
| `plan` | Every MR pipeline | `FALCON_*_RO` | Reads Falcon, diffs against the MR's repo state, posts `plan.txt` artifact |
| `apply` | `main` branch post-merge, **manual trigger** | `FALCON_*_RW` + `FALCON_CID` | Creates / updates / deletes rules in Falcon; backfills assigned IDs back to main if `SSH_DEPLOY_KEY` is set |
| `drift` | Scheduled pipeline with `DRIFT_CHECK=true` (e.g. daily) | `FALCON_*_RO` | Detects divergence between Falcon and main; if `SSH_DEPLOY_KEY` is set, absorbs the diff with a direct commit to `main` (no MR, no human gate) |

## What `apply` actually does

Operations run in this order, continuing past individual failures:

- **Create** — rule with `id: null` AND no name match in Falcon → `create_rule` API call. Falcon assigns a new ID. The script writes the new ID to the local YAML on the runner.
- **Update** — rule with matching ID OR name-fallback match, where content hash differs → `update_rule` API call. The write-whitelist is sent: `name`, `description`, `severity`, `tactic`, `technique`, `search.{outcome, filter, lookback, trigger_mode}`, `status`, `schedule.definition`. Repo-only fields (`notes`, `runbook_url`, `owner`, `log_source`, `lifecycle.*`) are never sent.
- **Repair ID** — local `id` is stale (null or doesn't exist in Falcon) but remote has a name match with identical content. No API call; just rewrites the local YAML id so future plans match on id directly.
- **Delete** — rule ID exists in Falcon but the YAML file was removed in this commit AND the rule's name appears in the `deleted_rule_names` whitelist computed by `scripts/deleted_rule_names.sh` from git history. Requires the prior `lifecycle.deletion_requested: true` merge by convention.

The plan also populates two informational buckets that apply takes no action on — they surface state for human awareness:

- **Remote-only** (`REMOTE-ONLY` in `plan.txt`) — a rule exists in Falcon with no matching local YAML. Almost always a UI-authored rule; absorbed automatically by the next drift run. Apply ignores this bucket.
- **Remote-missing** (`REMOTE-MISSING` in `plan.txt`) — a local YAML has a non-null `id` but its remote has vanished. Almost always a UI deletion; apply deliberately does **not** recreate the rule (that was the old behavior and it resurrected rules the user meant to delete). To confirm the deletion, remove the YAML in a follow-up PR — that routes through the normal `Delete` path above.

Apply's content-hash comparison only considers the write-whitelist. So: metadata-only edits never produce a plan diff or an API call. You can polish `notes` across 100 rules in one MR and `plan` will say 0 changes.

### Continue-on-error behavior

If any individual operation fails (e.g. a 404 on an UI-authored rule we don't own), the script records the failure but continues to the next operation. At the end, it prints a summary:

```
--- APPLY SUMMARY: N succeeded, M failed ---
  [update] some_rule.yml: status=404 body={...}
```

The job exits non-zero if any operation failed, so CI surfaces the issue. The backfill push runs regardless — successful creates get their IDs committed even when other rules fail.

### Automatic ID backfill (requires `SSH_DEPLOY_KEY`)

If the CI variable `SSH_DEPLOY_KEY` is set (File type, Protected) to an SSH private key whose public half is a project Deploy Key with write access, the `apply` job will:

1. Configure SSH with the key
2. After running the plan, if any rule YAMLs changed locally (from create-backfills or repair-id), commit them with `[skip ci]` and push to `main`

Result: authoring a new rule in an MR → merge → click apply → rule is created in Falcon AND its ID lands in main, zero manual follow-up.

Without `SSH_DEPLOY_KEY`, the apply job logs the created rule IDs in `plan.txt` and you reconcile locally via `make import-overwrite` + a backfill MR.

## What the post-apply round-trip check catches

After all creates/updates/deletes complete successfully, apply re-fetches Falcon state and re-plans. If the plan is non-empty, the script logs a warning and writes the residual diff to `plan.txt`. This indicates a field was sent but Falcon stored something different. Very rare; worth investigating if seen.

## Why `apply` is `when: manual`

For the first 60 days of operation, the `apply` stage requires a human to click play in GitLab's pipeline UI. Reasoning:

- A merge storm (several MRs merged close together) produces only one deploy click, not N separate deploy attempts
- Delete blast radius — if a `rm` accidentally makes it through review, manual apply is the last chance to notice
- Apply probes the write scope before writes, but a manual click is another layer

After 60 days of clean operation, flip it to `on_success` automatic. Edit `.gitlab/ci/apply.yml`:

```yaml
- if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && $CI_PIPELINE_SOURCE != "schedule"
  when: on_success   # was: manual
```

## The drift job

Runs on a scheduled pipeline that sets `DRIFT_CHECK=true` (daily is a good default). It runs `sync_detections.py --drift`, which is identical to `--plan` except it exits 5 if any diff exists.

**With `SSH_DEPLOY_KEY` configured** (normal mode): on drift, the job:

1. Prints the plan (`CREATE` / `UPDATE` / `REPAIR ID` / `REMOTE-ONLY` / `REMOTE-MISSING` sections) and writes `plan.txt` as a pipeline artifact
2. Runs `import_from_falcon.py --overwrite` to pull Falcon's current state into local YAML — this absorbs UI edits and creates new files for UI-authored rules
3. Commits the diff with message `reconcile: absorb Falcon UI changes detected by drift pipeline <id> [skip ci]`
4. Pushes the commit **directly to `main`** via the SSH deploy key — same mechanism apply uses for id-backfill
5. Exits 0 on success — no notification, no human action required

Many orgs disable project access tokens, and `CI_JOB_TOKEN` can't merge MRs on its own. Direct push to `main` is the only reliable auto-reconcile path. `plan.txt` (retained 3 months as an artifact) plus the reconcile commit in git history are the audit trail.

**Without `SSH_DEPLOY_KEY` configured** (fallback mode): the job exits non-zero on drift, GitLab's built-in pipeline-failure notifications fire (Slack / email via Settings → Integrations), and you reconcile manually via `make import-overwrite` + a normal MR flow.

**What drift means, concretely:**

- Someone edited a rule in the Falcon UI since the last apply (most common — absorbed as UPDATE)
- A rule was created in the UI outside this repo (absorbed as a new YAML via REMOTE-ONLY)
- A rule was deleted in the UI — surfaces as REMOTE-MISSING in `plan.txt`. Drift does **not** remove the local YAML automatically (too risky against transient API blips); open a PR that `git rm`s the file to confirm
- An `apply` succeeded but the backfill push failed, leaving `id: null` in the local YAML (less common with auto-backfill working)

### When the auto-reconcile push fails

The most common cause is branch protection on `main` rejecting the SSH deploy key. Fix at Settings → Repository → Protected branches: either add the deploy key to "Allowed to push" for `main`, or allow the key to bypass protection. Apply's id-backfill push uses the same key, so if it has been working there, drift should work too.

### Manually reconciling when the auto-path isn't available

1. **Absorb UI changes** (legitimate tune should be persisted):
   ```bash
   make import-overwrite
   git checkout -b drift/absorb-ui-changes
   git add rules/
   git commit -m "drift: absorb Falcon UI edits"
   git push -u origin drift/absorb-ui-changes
   ```
   MR, merge. Apply is a no-op since Falcon state already matches.

2. **Revert UI changes** (accidental or unauthorized): run `apply` on main unchanged. It overwrites Falcon's divergent values with what the repo says.

## Your first apply checklist

Before clicking ▶ on apply for the first time:

1. **Confirm the plan** — read `plan.txt` from the MR. Zero surprises.
2. **Test against staging if possible** — not all teams have a staging Falcon tenant, but if yours does, apply there first.
3. **Schedule during working hours** — if the apply breaks, you want teammates around. Don't deploy Friday at 5pm.
4. **Watch the apply job output** — the script logs each operation as it runs. Failures appear in a summary block at the end.
5. **Verify in the Falcon UI** — spot-check at least one rule post-apply.

## Rollback

Fastest rollback: revert the merge commit on main, re-run apply.

```bash
git checkout main && git pull
git revert -m 1 <merge-commit-sha>
# Push revert through standard MR flow
```

After the revert merges, click apply. Falcon returns to the pre-change state.

Slower but sometimes necessary: the rule that needs reverting was a delete. Rollback requires recreating it from git history (see [`deleting-rules.md`](./deleting-rules.md) → Undo). You lose the old Falcon ID; the recreated rule gets a new one.
