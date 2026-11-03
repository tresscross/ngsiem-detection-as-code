# Contributing

This file covers two things: contributing to this project, and the rule-authoring workflow for teams that adopt it.

## Contributing to the framework

1. Fork the repo and create a branch.
2. `make install`, then `make validate && make test`.
3. Open a PR that describes the change and what you tested. Never include tenant data such as rule IDs, CIDs, hostnames, IPs, or usernames in issues, PRs, or test fixtures.

## Authoring a new rule

1. Branch off `main`: `git checkout -b rule/<slug>`.
2. Copy `examples/rule_template.yml` to `rules/<slug>.yml`.
3. Fill in every required field and leave `id: null`.
4. Write the CQL inside `search.filter` as a `|` block literal.
5. Run `make validate` locally until it passes.
6. Optional: run `make plan` with RO creds to preview the change against the tenant.
7. Push and open an MR.

**Required fields:** `id`, `name`, `severity`, `status`, `coverage_category`, `search`, `schedule`, `lifecycle`.

**Optional fields:** `description`, `tactic`, `technique`, `log_source`, `runbook_url`, `owner`, `notes`. The validator checks them only when they're set. `log_source` must be a key in `schema/log_sources.json`, which you edit to match the sources in your tenant. If `DAC_RUNBOOK_URL_PREFIX` is set, `runbook_url` must start with it.

## CQL format (hard requirements)

Every rule's `search.filter` must contain:

- **Enrichment**: `ipLocation(<ip>)` and `asn(<ip>)` on any IP field used for correlation. Falcon sensor telemetry is exempt.
- **Consolidation**: `groupBy([key], function=[collect([...])])`. Collect every field you want in the alert payload, not just the pivot field.
- **Description**: `format(format="...", field=[...], as=detection.description)`. Analysts read this first.
- **TI confidence**: any `ioc:lookup(` or `threatFeed` call must include `confidenceThreshold="high"`.

The validator enforces these unless `lifecycle.standardization_pending: true`, which is meant only for bootstrap-imported rules.

## MITRE mapping

- `tactic`: use the ATT&CK ID (`"TA0001"`, not `"Initial Access"`). Falcon's create API rejects the name form.
- `technique`: use `T####` or `T####.###`, and it must belong to the tactic you set.

Run `make refresh-mitre` if your tactic or technique isn't in the cached bundle.

## Severity scale

Falcon's create API accepts only five values: `10` Informational, `30` Low, `50` Medium, `70` High, `90` Critical. See [`docs/rule-quality-standards.md`](./docs/rule-quality-standards.md).

## Review checklist for MRs

- [ ] The `plan.txt` artifact shows only the intended diff
- [ ] `runbook_url` points to a real page, not a placeholder
- [ ] `owner` is a real team alias or person
- [ ] Any TI lookup includes `confidenceThreshold="high"`
- [ ] `lifecycle.last_reviewed` is updated if the rule changed meaningfully
- [ ] The name doesn't duplicate another rule's

## Deleting a rule (two steps)

**MR 1** records intent and makes no API call:

```yaml
lifecycle:
  deletion_requested: true
```

**MR 2** removes the file:

```bash
git rm rules/<file>.yml
```

After MR 2 merges, the apply job deletes the remote rule. To pause a rule instead, set `status: inactive`.

## Updating a rule

Edit the file and open an MR. The sync script detects changes with a content hash over the fields it writes: name, description, severity, tactic, technique, search.{outcome, filter, lookback, trigger_mode}, status, and schedule.definition. Changes to `notes`, `runbook_url`, `owner`, and `lifecycle.*` are tracked in git only and trigger no API update.

## Local testing tips

- `python scripts/validate_rules.py --json` prints machine-readable violations, which is handy for a pre-commit hook.
- If `make plan` shows diffs you didn't expect, someone probably edited the rule in the Falcon UI. Either pull the drift job's reconcile commit or run apply to overwrite the UI change.
- To test `--apply` end to end, use a staging tenant.
