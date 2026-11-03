# The Standardization Sweep

On bootstrap, every existing Falcon rule landed in the repo with `lifecycle.standardization_pending: true`. The sweep is the ongoing effort of bringing each of those rules up to the CQL format standard. Treat it as background work, not a project with a deadline.

## Why it exists

Rules that predate the repo usually weren't written to a shared standard. Their CQL often lacks the ipLocation/asn enrichment, the groupBy/collect consolidation, or TI confidenceThreshold gates. Some may have zero-duration lookbacks or placeholder names. The format linter would reject most of them on day one, so the `standardization_pending` flag was introduced to let them coexist in the repo while they get cleaned up rule-by-rule.

## How to know if a rule is pending

```yaml
lifecycle:
  standardization_pending: true
```

While this flag is true, the validator SKIPS:

- Format checks (ipLocation, asn, groupBy, collect, format)
- TI confidenceThreshold check
- CQL parenthesis balance check
- MITRE tactic/technique existence in the cache
- Zero-duration lookback check
- Name-uniqueness check (if BOTH sides of a name collision are pending)

Schema-level checks still run — types, required fields, enums.

## A single sweep MR

### 1. Pick one rule

Start with ones where you have context — you authored it, you've responded to alerts from it, you understand the signal.

```bash
ls rules/ | head -50          # or grep for something specific
```

### 2. Branch

```bash
git checkout -b sweep/<rule-slug>
```

### 3. Read the current CQL

```yaml
search:
  filter: |
    <current legacy CQL>
```

Figure out what it's trying to detect. If it's unclear, that's a rule that should probably be deleted during sweep, not standardized.

### 4. Rewrite to the CQL format standard

See [`rule-quality-standards.md`](./rule-quality-standards.md) for the full template. Required elements in the new CQL:

- `ipLocation(<ip-field>)` and `asn(<ip-field>)` enrichment
- `groupBy([key], function=[collect([...])])` with every field you want in the alert payload
- `format(format="...", field=[...], as=detection.description)` for human-readable alert summary
- `confidenceThreshold="high"` on any TI lookup

### 5. Fill in metadata

Optional but encouraged on sweep:

- `log_source`: pick a key from `schema/log_sources.json`
- `runbook_url`: runbook URL (or file a ticket if no runbook exists)
- `owner`: team alias or email
- `description`: write a real one if it's blank/TODO

### 6. Fix zero lookback if present

If `search.lookback` is `0h0m` or similar, the rule was never actually firing. Decide:

- **Delete the rule** (two-step, see [`deleting-rules.md`](./deleting-rules.md))
- **Set a real lookback**, normally equal to the schedule interval (see "Schedule and lookback pairing" in [`rule-quality-standards.md`](./rule-quality-standards.md))

### 7. Bump lifecycle

```yaml
lifecycle:
  created: "<keep original>"
  last_reviewed: "2026-01-15"     # today
  deletion_requested: false
  standardization_pending: false  # FLIP IT — this is the whole point
```

### 8. Validate

```bash
make validate
```

All format checks now engage for this rule. If any fail, fix the CQL until they pass. This is where the sweep feels like real work — the validator is unforgiving because the rule is no longer pending.

### 9. Plan

```bash
make plan
```

Should show exactly one update for the rule you just rewrote. The new CQL replaces the old in Falcon.

### 10. MR + merge + apply

Standard flow. In the MR description, note what changed. Suggested template:

```markdown
## What this sweep MR does

Brings `<rule name>` up to the CQL format standard. Flips `standardization_pending` to false.

## Before → After

- `search.filter`: [describe the key changes — added ipLocation/asn, consolidated via groupBy, etc.]
- `search.lookback`: [was `0h0m`, now `1h` — rule was never firing] *(if applicable)*
- `log_source`: was empty, now `Okta_Workforce_Identity` *(if applicable)*
- Severity: unchanged *(or note any change)*

## Validation

- [ ] Legacy CQL semantics preserved (still detects the same behavior)
- [ ] `make plan` shows exactly one update
- [ ] Alert volume re-baselined (attach a hunt query result link)
```

## Cadence suggestions

- **1 sweep/day minimum** — steady small MRs beat a big-bang rewrite.
- **Batch similar rules** — rules from the same log source usually share a structure. Standardize one, copy the enrichment pattern to the rest.
- **Delete aggressively** — if a rule has `name: TODO`, `description: None`, or was clearly a test or experiment, sweep = delete. Don't standardize junk.

## What the metric looks like

```bash
echo "Standardized: $(grep -l 'standardization_pending: false' rules/*.yml | wc -l)"
echo "Pending:      $(grep -l 'standardization_pending: true' rules/*.yml | wc -l)"
```

This is a healthy OKR for the team: percentage of `standardization_pending: false`, trending up each month.

## When to stop

There is no "done" — the repo will always have some pending if new imports happen. But the target state: zero rules with `name: TODO`, `description: None`, or `lookback: 0h0m`. Everything active and pending has defensible content even if its CQL hasn't been modernized yet.
