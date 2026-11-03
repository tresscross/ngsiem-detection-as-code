# Troubleshooting

Common failures, what they mean, how to fix them. Ordered roughly by pipeline stage.

## `make validate` fails

### `[schema] name: 'TODO' ...` or other placeholder values

A bootstrap-imported rule has placeholder text (the importer falls back to `TODO` when a remote rule has no name). Fill in a real value, or delete the rule if it's junk.

### `[schema] search.trigger_mode: 'X' is not one of [...]`

The schema allows `summary`, `smart`, `all`, `verbose`. If Falcon has something else, either add it to the schema enum or investigate the rule in the UI. Note: **`smart` is not valid on create for standard correlation rules** — Falcon returns `search.trigger_mode 'smart' is not valid for rule type`. Use `summary` for new rules.

### `[schema] severity: X is not one of [10, 30, 50, 70, 90]`

Falcon's create API enforces exactly those five values. Pick the closest tier. See [`rule-quality-standards.md`](./rule-quality-standards.md) → Severity scale.

### `[schema] technique: 'X' does not match pattern`

Pattern is `^(T[0-9]{4}(\.[0-9]{3})?|CST[0-9]{4})?$`. If you're seeing a MITRE ID that isn't in `T####` / `T####.###` / `CST####` form, inspect the field. Common mistake: tactic ID in the technique field or vice versa.

### `[cql_format] search.filter missing required format elements: ...`

You're editing a rule with `standardization_pending: false` whose CQL doesn't match the CQL format standard. Two options:
1. Add the missing elements (`ipLocation(`, `asn(`, `groupBy(`, `collect(`) — see [`rule-quality-standards.md`](./rule-quality-standards.md)
2. If this is a legacy rule you're editing without standardizing, flip `standardization_pending: true` and revisit in a sweep MR

### `[lookback_zero] search.lookback='0h0m' means the rule queries a zero-duration window`

The rule never actually fires. Fix `lookback` to a real duration ≥ the schedule interval, or delete if intentionally broken.

### `[uniqueness_name] Duplicate rule name 'X'`

Two YAML files share the same `name` field. Common cause: earlier `make import-overwrite` runs with a buggy import script created duplicates under different slugified filenames. Fix: remove the duplicate you don't want, keep the canonical one. The current import script prefers existing files by id and by name, so it won't recreate the duplicate on next run.

If both are `standardization_pending: true`, the check silences — but the moment one flips to `false`, the collision surfaces.

### `[mitre_tactic] tactic 'TAxxxx' not in schema/mitre_enterprise.json`

MITRE cache stale. `make refresh-mitre` pulls the current ATT&CK STIX bundle and writes both name and ID forms.

---

## `make plan` issues

### `error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set`

Load creds first. From the README quickstart or:
```bash
export FALCON_CLIENT_ID=<RO_client_id>
export FALCON_CLIENT_SECRET=<RO_client_secret>
export FALCON_BASE_URL=https://api.crowdstrike.com   # your tenant's API base URL
```

### `get_rules_combined failed: status=401`

Expired or wrong credentials. Verify with a raw OAuth curl:
```bash
curl -sX POST -u "$FALCON_CLIENT_ID:$FALCON_CLIENT_SECRET" "$FALCON_BASE_URL/oauth2/token"
```
Should return a token. If 401, the RO credential is revoked or the base URL is wrong.

### `get_rules_combined failed: status=403`

Credential is valid but lacks `Correlation Rules: Read` scope. Add that scope on the Falcon API client.

### Plan shows unexpected updates on every rule

Content hash seeing drift on some field. If 500+ rules show updates, it's a serialization issue — re-run `make import-overwrite` to canonicalize local YAML to match what the script sees from Falcon. If only a few, inspect individual diffs (usually UI edits).

### Plan shows "REPAIR ID (metadata-only)"

Normal — happens when local YAML has `id: null` or an id that doesn't exist in Falcon but the rule's name matches a remote rule. Apply will silently fix the local id; no API call is made. Most common cause: an apply created a rule but the backfill push failed (check `SSH_DEPLOY_KEY` setup).

---

## `apply` job fails in CI

### `create_rule failed: 401 not authorized to create rule in requested CID: <empty>`

`FALCON_CID` CI variable is empty or not reaching the job. Check:
- Settings → CI/CD → Variables → `FALCON_CID` exists, Protected, Value is the 32-char tenant CID (not the Client ID; they're different fields)
- `.gitlab/ci/apply.yml` doesn't contain a `FALCON_CID: $FALCON_CID` self-reference (known GitLab gotcha — self-references emit the literal `$FALCON_CID` string)

### `create_rule failed: 401 not authorized to create rule in requested CID: $FALCON_CID`

Same symptom as above, literal `$FALCON_CID` string in the payload. The variable wasn't expanded. Don't self-reference in the job's `variables:` block — project-level CI variables flow through automatically.

### `create_rule failed: 400 expected RuleCreateRequestV1.Severity to be one of: 10 30 50 70 90`

Rule YAML has a severity outside the enum. Schema now enforces this at validate time; if it slipped through, check the schema file.

### `create_rule failed: 400 RuleCreateRequestV1.Tactic is not a valid tactic`

Rule YAML uses the ATT&CK tactic NAME (`"Command and Control"`) — Falcon's create API requires the ID form (`TA0011`). See [`rule-quality-standards.md`](./rule-quality-standards.md) → MITRE mapping.

### `create_rule failed: 400 Technique T#### is not a technique of tactic TA####`

Tactic and technique are mismatched. Verify the technique's parent tactic at https://attack.mitre.org and align.

### `create_rule failed: 400 search.trigger_mode 'smart' is not valid for rule type`

`smart` is only accepted for certain rule types (IDP, etc.). Change to `summary`.

### `update_rule failed: 404 Rule not found, id=<hex>`

Either:
- Local YAML has a stale id that doesn't exist in Falcon (old import, deleted in UI). The updated plan logic should fall back to name match and UPDATE via the new id — if the error still appears, the rule genuinely has no name match either.
- Rule is owned by another user (created via UI). The api_client can't modify rules it doesn't own. Falcon returns 404 rather than 403 for this case.

Apply now continues past these failures, so the error surfaces but doesn't block other rules. Decide whether to match the UI version locally (`make import-overwrite`) or to stop tracking the rule in the repo.

### `delete_rules failed: 404 rule not found`

Same root cause as above — UI-authored rule, api_client can't delete. Delete via Falcon UI if needed, then `make import-overwrite` to sync local state.

### `WARNING: backfill push failed` / `error in libcrypto / Permission denied (publickey)`

SSH key configured but OpenSSH can't parse it. Cause is almost always one of:
- CRLF line endings instead of LF (happens when key is pasted from a Windows editor)
- Missing trailing newline
- Key was truncated on paste (missing `-----END OPENSSH PRIVATE KEY-----` line)

Regenerate with `ssh-keygen -t ed25519 -f ~/.ssh/dac_deploy_key -N "" -C "ci-backfill"` and re-paste the WHOLE file contents (including BEGIN/END lines, with trailing newline) into the `SSH_DEPLOY_KEY` CI variable, type File.

Apply's create/update path runs regardless — the push failure only means the ID backfill didn't reach main. Reconcile locally with `make import-overwrite`.

### `WARNING: post-apply plan shows residual diff`

A write-whitelist field was sent but Falcon stored something different (or dropped it). Inspect the `plan.txt` artifact — it shows exactly which rule and which field diverged. Typically a Falcon-side behavior change worth filing a script update for.

---

## Drift alerts

### Daily drift pipeline failed — what do I do?

With `SSH_DEPLOY_KEY` configured and branch protection set up correctly, a drift run with differences exits 0 and commits the reconcile to `main` automatically — no notification, nothing to do. If the pipeline **failed**, one of these is the cause:

- **`Failed to push reconcile commit to main`** — branch protection on `main` is rejecting the SSH deploy key. Fix at Settings → Repository → Protected branches: add the deploy key to "Allowed to push" for `main`, or allow it to bypass protection. Apply's id-backfill uses the same key, so if backfill commits have been landing, drift should too.
- **`Drift plan said changes existed, but import produced no local diff`** — drift is in a field `import_from_falcon.py` doesn't overwrite (`lifecycle.*`, `log_source`, etc., or an edge case in the whitelist logic). Inspect `plan.txt` from the pipeline artifacts and either hand-edit the local YAML or extend the import script's write-through set.
- **`No SSH_DEPLOY_KEY — cannot auto-reconcile`** — the CI variable is unset or missing the File type flag. See the README "ID backfill" section for setup.

### Scheduled drift pipeline never runs

Check Build → Pipeline schedules. Ensure the schedule is "Active", cron expression valid, `DRIFT_CHECK=true` in Variables, target branch `main`.

### I see `REMOTE-ONLY` in `plan.txt`

A rule exists in Falcon that has no local YAML. Usually UI-authored. With `SSH_DEPLOY_KEY` configured, the next drift run will absorb it automatically by generating a YAML from the tenant state and committing to `main`. No action needed unless drift is broken — then see above.

### I see `REMOTE-MISSING` in `plan.txt`

A local YAML has an `id` set, but that rule is gone from the Falcon tenant. Almost always means someone deleted it in the UI. Apply deliberately does **not** recreate it (the old behavior resurrected rules the user meant to delete). To confirm the deletion, open a PR that `git rm`s the file — the existing delete path (via `scripts/deleted_rule_names.sh`) will remove any remaining trace cleanly. If you instead want the rule back, recreate the YAML with `id: null` and let apply create fresh.

---

## Import issues

### Re-import creates duplicate YAML files

Previously a bug: the old import picked filenames by slugifying the rule name, ignoring that an existing file might already track the rule. Fixed — import now checks existing files by id, then by name, before falling back to a slug-based filename. If you see duplicates persisting, you may be running an older `scripts/import_from_falcon.py`; pull the latest main.

### Import reverts my local-only fields (log_source, owner, notes, standardization_pending)

Fixed. The import now preserves these fields when writing to an existing file — only Falcon-authoritative fields (name, description, severity, status, tactic, technique, search.*, schedule.*) are overwritten. If you still see this, ensure you have the latest main checked out.

---

## GitLab pipeline issues

### Pipeline doesn't trigger on push

Check `.gitlab-ci.yml` `rules:` blocks for each stage. The `plan` stage requires `CI_PIPELINE_SOURCE == "merge_request_event"` — branch pushes without an open MR don't trigger plan.

### `apply` button isn't visible

On the post-merge pipeline, find the `apply` job — it has a play button. If no `apply` stage appears at all, check if the pipeline was created on a scheduled run (apply is excluded from those by design).

---

## CLI / env issues

### Falcon credentials not set

Credentials aren't in your environment. Set them directly:
```bash
export FALCON_CLIENT_ID=<RO_client_id>
export FALCON_CLIENT_SECRET=<RO_client_secret>
export FALCON_BASE_URL=https://api.crowdstrike.com   # your tenant's API base URL
```

### `make validate` works but `make plan` says `crowdstrike-falconpy not installed`

Your shell's `PATH` is finding a different Python than the venv. Activate: `source .venv/bin/activate`. Verify: `which python` should point inside `.venv/bin/`.

---

## When to escalate

- Repeated `WARNING: post-apply plan shows residual diff` — file a script fix.
- Falcon API returns 5xx that doesn't resolve with a retry — open a CrowdStrike support ticket.
- Drift alerts fire daily with the same rule diverging — someone is repeatedly editing in the UI. Find the analyst and redirect to the repo workflow, or accept the rule as UI-owned and adjust docs accordingly.
- SSH push fails after the libcrypto fix — key is genuinely malformed or not registered as a deploy key; regenerate from scratch.

---

## Useful one-liners

```bash
# Count standardized vs pending
echo "Standardized: $(grep -lE 'standardization_pending: false' rules/*.yml | wc -l)"
echo "Pending:      $(grep -lE 'standardization_pending: true' rules/*.yml | wc -l)"

# Find rules with zero lookback
grep -lE 'lookback: .?0[hms]' rules/*.yml

# Find rules using @every format
grep -l "definition: '@every" rules/*.yml | wc -l

# Find rules by log source
grep -l "log_source: Okta" rules/*.yml

# Oldest last_reviewed dates
grep -h 'last_reviewed:' rules/*.yml | sort | head
```
