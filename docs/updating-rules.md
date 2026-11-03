# Updating an Existing Rule

Use this when you're modifying a rule that's already in the repo and deployed to Falcon — tuning the CQL, bumping severity, changing the schedule, pausing via `status: inactive`, etc. For net-new rules see [`authoring-new-rules.md`](./authoring-new-rules.md).

## What triggers an actual Falcon API call

Only changes to these fields result in a `update_rule` call during `apply`:

- `name`
- `description`
- `severity`
- `tactic`
- `technique`
- `search.filter`
- `search.outcome`
- `search.lookback`
- `search.trigger_mode`
- `status`
- `schedule.definition`

Everything else is **repo-only metadata** and does NOT deploy: `log_source`, `runbook_url`, `owner`, `notes`, `lifecycle.*`. You can freely tune these without queueing a deploy.

Practical implication: a cleanup MR that just fills in `runbook_url` across 50 rules produces a `plan` with 0 updates. Safe and free.

## Standard update flow

### 1. Branch

```bash
git checkout main && git pull
git checkout -b tune/<rule-slug>-<reason>
```

Examples:
- `tune/okta-impossible-travel-severity-down`
- `tune/aws-root-login-add-exclusion`

### 2. Edit the YAML

Open `rules/<file>.yml`. Make your change.

If you're editing CQL, use a `|` block literal — YAML handles newlines cleanly.

Bump `lifecycle.last_reviewed` to today if the change is meaningful:

```yaml
lifecycle:
  created: "2025-06-01"
  last_reviewed: "2026-01-15"      # <-- bumped
  deletion_requested: false
```

### 3. Validate

```bash
make validate
```

If the rule is `standardization_pending: true` and your change is in CQL, you have two choices:

- **Keep pending, quick tune**: don't flip the flag. Format checks stay deferred. Change ships as-is.
- **Standardize while you're in there**: bring the CQL fully to the CQL format standard (ipLocation, asn, groupBy/collect, format, confidenceThreshold="high"), then flip `standardization_pending: false`. See [`standardization-sweep.md`](./standardization-sweep.md).

### 4. Plan against Falcon

```bash
make plan
```

You should see exactly one update in the `UPDATE:` section, matching the rule you edited. If you see extra updates or creates, stop and investigate — likely drift between Falcon and your local main (pull again, re-plan).

### 5. MR + merge

```bash
git add rules/<file>.yml
git commit -m "tune: <rule name> — <what changed and why>"
git push -u origin tune/<rule-slug>-<reason>
```

In the MR description, note the WHY. Example:

> Lowered `severity` from 90 to 70. False-positive rate was 8/week — not
> a pageable cadence. Runbook updated with the new triage guidance.

### 6. Deploy

Merge → pipeline runs → click ▶ on `apply` → change lands in Falcon.

Confirm in the Falcon UI that the rule reflects your change. If it doesn't, check the apply job's logs and see [`troubleshooting.md`](./troubleshooting.md).

## Common update patterns

### Pausing a rule temporarily

Flip `status` to `inactive`. The rule stays deployed but won't fire. Cheap to toggle back.

```yaml
status: inactive
```

### Tuning alert volume

Most common lever is `severity`. Second most common is adding exclusions inline in the `search.filter`. Avoid tuning via `schedule` — reducing run frequency delays detection.

### Changing the MITRE mapping

Straightforward field edit — `tactic` and `technique`. If a newer technique isn't recognized, run `make refresh-mitre` and commit the updated cache.

### Rename

Change `name`. Because `id` matches, this is a pure update to Falcon — no create-then-delete churn. But **don't rename a rule that still has `id: null`** — the name-match fallback breaks and you get a create + orphan.

### When the rule has a stale local id

If the local `id` doesn't exist in Falcon but the rule's `name` still matches a remote rule, the plan will show one of:
- `REPAIR ID (metadata-only)` — content already matches remote; apply just rewrites the local id, no API call
- Normal `UPDATE` — content differs; apply sends an update keyed on the remote's id and also rewrites the local id

Either way the backfill push (if `SSH_DEPLOY_KEY` is configured) carries the corrected id to main. Happens most often when someone deletes and recreates a rule in the UI; Falcon assigns a new id but the name stays the same.

### When the rule is owned by someone else (UI-authored)

Falcon returns 404 on `update_rule` for rules created by another user in the UI. The api_client isn't permitted to modify them. Apply logs the failure but continues past it. Two ways forward:

1. **Absorb the UI-authored rule into the repo as externally-owned** — run `make import-overwrite` locally, accept Falcon's values, merge. Future UI edits get absorbed automatically by the daily drift job (direct commit to `main`).
2. **Take over via repo** — delete the UI version in Falcon, then author a new rule from the repo. Cleanest when there's disagreement about content.

### Metadata-only change (no deploy)

Edit `notes`, `runbook_url`, `owner`, `log_source`, or `lifecycle.*`. `make plan` will show zero changes. MR lands in the repo without touching Falcon.

## Checklist

```markdown
- [ ] Validator passes
- [ ] Plan shows exactly one expected update (or zero, if metadata-only)
- [ ] lifecycle.last_reviewed bumped if the change is meaningful
- [ ] MR description explains WHY
- [ ] If this changed alert volume, added a note so future-me knows the baseline
```
