# Authoring a New Rule

Use this when you have a detection idea that isn't in Falcon yet. For changes to an existing rule, see [`updating-rules.md`](./updating-rules.md). For bringing a bootstrap-imported rule up to standard, see [`standardization-sweep.md`](./standardization-sweep.md).

## Before you write anything

Answer these four questions first. If you can't, the rule isn't ready to write.

1. **What specifically is the behavior you're detecting?** One sentence, concrete.
2. **What log source carries the evidence?** Pick from `schema/log_sources.json`. If the source isn't there, the rule is premature — you need the log source onboarded first.
3. **What's your MITRE tactic + technique?** Look up at [attack.mitre.org](https://attack.mitre.org). Use the technique ID (`T####` or `T####.###`), plus the tactic name.
4. **What's the expected volume?** Sanity-check against recent hunt queries. If you expect >5 alerts/day on a severity ≥70 rule, tune first.

## Step-by-step

### 1. Branch

```bash
cd ngsiem-detection-as-code
git checkout main && git pull
git checkout -b rule/<short-slug>
```

Slug convention: `rule/okta-impossible-travel`, `rule/aws-root-console-login`. Keep it short.

### 2. Create the file

Copy the canonical example as a starting point:

```bash
cp examples/rule_template.yml rules/<your_slug>.yml
```

File naming: `<logsource>_<short_description>.yml` — e.g. `aws_cloudtrail_root_console_login.yml`. Lowercase, underscores.

### 3. Fill in the fields

```yaml
id: null                              # leave null — Falcon assigns on first apply
name: "AWS - Root Console Login"      # human-readable; must be unique repo-wide
description: >
  Detects a successful console login by the AWS root account, which should
  never be used for day-to-day operations.
severity: 70                          # 10/30/50/70/90 only — see rule-quality-standards.md
status: active                        # or 'inactive' to deploy disabled
coverage_category: cloud              # endpoint | cloud | identity (required)
tactic: "TA0001"                      # TA#### form — Falcon create API rejects name form
technique: "T1078.004"                # T#### or T####.### — must map to the tactic above
log_source: "AWS_CloudTrail_Logs"     # must match schema/log_sources.json key
runbook_url: "https://wiki.example.com/runbooks/..."   # optional but encouraged
owner: "detection-eng@example.com"  # optional
notes: |
  Expected volume: 0-1/month.
  Reference: CIS AWS 1.1.
search:
  filter: |
    <your CQL here>
  outcome: "detection"
  lookback: "1h"
  trigger_mode: "summary"              # "smart" is rejected on create
schedule:
  definition: "@every 10m"            # Falcon-native format; cron may be rejected by create API
lifecycle:
  created: "2026-01-15"
  last_reviewed: "2026-01-15"
  deletion_requested: false
```

Do NOT set `lifecycle.standardization_pending: true` on a new rule — that flag is only for imports. New rules must meet the CQL format standard on day one.

### 4. Write the CQL

Every new rule's `search.filter` MUST include:

- `ipLocation(<ip-field>)` and `asn(<ip-field>)` enrichment on whatever IP you're pivoting on
- `groupBy([key], function=[collect([...])])` for alert payload consolidation
- `format(format="...", field=[...], as=detection.description)` so analysts see a human-readable summary
- `confidenceThreshold="high"` on any `ioc:lookup(` or `threatFeed` call

See [`rule-quality-standards.md`](./rule-quality-standards.md) for the full template and example patterns.

### 5. Validate locally

```bash
make validate
```

Fix any violations. `python scripts/validate_rules.py --json` emits structured output if you want to consume the results programmatically.

### 6. Preview against Falcon

```bash
# Load RO creds (one-time per shell)
export FALCON_CLIENT_ID=<RO_client_id>
export FALCON_CLIENT_SECRET=<RO_client_secret>
export FALCON_BASE_URL=https://api.crowdstrike.com   # your tenant's API base URL

make plan
```

Should show your new rule in the `CREATE:` section, zero updates, zero deletes.

### 7. Open the MR

```bash
git add rules/<your_slug>.yml
git commit -m "add: <rule name>"
git push -u origin rule/<short-slug>
```

GitLab prints an MR URL in the push output. Open it.

### 8. Review + merge

- CI's `plan` job posts the diff as an artifact — confirm it matches what you expect
- Have a peer review
- Merge

### 9. Deploy

The `apply` stage on main is `when: manual`. In the GitLab pipeline UI for the post-merge pipeline, find the `apply` job and click the ▶ play button. The job creates the rule in Falcon and prints the assigned ID.

### 10. ID backfill (automatic if deploy key is set up)

After apply creates the rule, Falcon assigns a hex ID. If the `SSH_DEPLOY_KEY` CI variable is configured (see README "ID backfill"), the apply job commits and pushes the new ID directly to `main` with `[skip ci]`. **No action required.** You'll see a commit on main like `backfill: Falcon-assigned rule ids from apply <pipeline_id>`.

**Manual fallback** (if deploy key isn't configured):

```bash
make import-overwrite     # pulls all rules from Falcon, including your new one with its ID
git checkout -b backfill/<your_slug>-id
git add rules/<your_slug>.yml
git commit -m "backfill: Falcon id for <rule name>"
git push -u origin backfill/<your_slug>-id
```

Open a trivial MR, merge. Apply is a no-op. Your YAML now has the real ID; renames are safe.

## Checklist (copy into your MR description)

```markdown
- [ ] Validator passes locally (`make validate`)
- [ ] Plan shows only my intended change (`make plan`)
- [ ] Log source is onboarded (exists in `schema/log_sources.json`)
- [ ] CQL includes ipLocation+asn, groupBy/collect, format(detection.description)
- [ ] Any TI lookups use confidenceThreshold="high"
- [ ] Tactic + technique verified against ATT&CK
- [ ] Severity is defensible (see rule-quality-standards.md)
- [ ] Expected alert volume matches severity level
- [ ] Runbook linked (or TODO filed to create one)
```
