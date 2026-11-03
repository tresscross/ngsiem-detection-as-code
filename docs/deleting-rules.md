# Deleting a Rule

Deleting a rule is a **two-step MR process**, by design. A single accidental `rm` cannot take a rule out of production.

If you just want to stop a rule from firing without removing it, set `status: inactive` instead — that's a one-MR update and fully reversible.

## The two-step workflow

### MR 1 — mark intent

Edit the rule's YAML:

```yaml
lifecycle:
  created: "2025-06-01"
  last_reviewed: "2026-01-15"
  deletion_requested: true          # <-- set this
```

Commit, open MR. CI runs, `plan` shows zero changes (metadata-only). Merge.

After the MR merges, **no API call happens**. The apply job sees the flag change but takes no action — the rule is still in Falcon, still firing, still deployed. You've only recorded intent.

Why this matters: a second reviewer has to consciously merge MR 2 before anything is destroyed. A misfire on MR 1 is a 10-second revert.

### MR 2 — actually delete

```bash
git checkout -b delete/<rule-slug>
git rm rules/<file>.yml
git commit -m "delete: <rule name> — superseded by <other rule> (!MR1-link)"
git push -u origin delete/<rule-slug>
```

Link MR 1 in the MR 2 description. Reviewers should confirm MR 1 was merged and the `deletion_requested` flag was set before approving MR 2.

CI's `plan` on MR 2 shows a DELETE for the rule. Merge. Click ▶ on `apply`. The `delete_rules` API call fires, and the rule is gone from Falcon.

### How the deletion whitelist works

The `apply` job runs `scripts/deleted_rule_names.sh` against the last applied commit (the `dac-last-applied` tag, falling back to `HEAD~1` on first run) to build the set of rule names removed since then. The helper reads the deleted YAML files from git history, extracts their `name:` fields, and passes them as a comma-separated list to `sync_detections.py --deleted-rule-names`. The plan builder refuses to delete any remote rule whose name isn't in that list — so a stale local id that coincidentally matches a remote rule cannot cause an accidental delete.

If you're curious: `sync_detections.py` defaults to **fail-safe** — when no deletion whitelist is provided at all, no deletes happen. This prevents the whole class of "I ran plan and everything got deleted" accidents.

## Rule of thumb for MR 1 → MR 2 timing

At least **24 hours** between MR 1 merge and MR 2 open. Reason: if someone objects, they have time to comment before the second MR commits to the removal. A same-day two-step is legal but defeats the purpose.

## When to delete

Good reasons:

- Rule produces false positives at a rate that tuning can't fix
- Detection is now covered by a better rule (link to the superseding rule)
- Log source is deprecated and the rule can't fire
- Rule was a test / experiment / import artifact
- Duplicate of another rule

Bad reasons:

- "It's noisy" — try `status: inactive` first, decide after a week
- "I don't understand it" — ask the original owner before deleting
- "It hasn't fired in a year" — could be intentional (rare-event detection); check the runbook first

## Deleting vs. deactivating

| Scenario | Action |
|---|---|
| Permanently retire a detection | Two-step delete |
| Pause while investigating a noisy rule | `status: inactive` |
| Rule is being replaced; want overlap period | New rule goes `status: active`, old rule goes `status: inactive`. After 2 weeks of parallel running with the new one performing well, two-step delete the old. |
| Rule belongs to a deprecated log source | Decide whether the log source really is dead. If yes, delete. If it might come back, `status: inactive`. |

## UI-authored rules: API delete returns 404

If the rule was created by a human user in the Falcon UI (not via api_client), `delete_rules` returns 404 even when the rule visibly exists. Falcon gates rule modification by creator. Options:

1. Delete the rule in the Falcon UI, then `make import-overwrite` locally to sync. Normal two-step delete MR flow for the YAML.
2. Leave the rule in Falcon, but `git rm` the YAML from the repo — the next drift run will surface it as `REMOTE-ONLY` and, if `SSH_DEPLOY_KEY` is configured, automatically re-absorb it by generating a fresh YAML on `main`. So this option only works if you actively want the rule re-absorbed; if you want it *gone*, delete in Falcon first (option 1).

## Undo

Between MR 1 and MR 2: open a third MR that flips `deletion_requested` back to `false`. No deployment impact — metadata-only change.

After MR 2 has merged AND the apply job has run: the rule is gone from Falcon. Recovery means:

1. Retrieve the YAML from git history: `git show <commit-before-delete>:rules/<file>.yml > rules/<file>.yml`
2. Set `id: null` (the old ID is invalidated)
3. Treat as a new rule — MR, merge, apply, backfill ID.

You'll keep the rule's logic but lose its Falcon state (disabled-state toggles, any UI-side notes, alert history attribution).

## Bulk deletes

If you're cleaning out 20 junk rules at once, still do it as two steps — one MR setting `deletion_requested: true` on all 20, a second MR `rm`-ing all 20. The rationale scales: you want a second reviewer eyeballing the list before anything is destroyed.
