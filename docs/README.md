# Detection Engineering Workflow: Documentation

This directory is the operational handbook for authoring, updating, and deploying CrowdStrike NG-SIEM correlation rules through this repository.

For how the pipeline is implemented (schema, scripts, CI), start with the repo root `README.md` and `CONTRIBUTING.md`. For day-to-day detection-engineering work, start here.

## Where to go

| I want to... | Read |
|---|---|
| Set up a local clone | [`getting-started.md`](./getting-started.md) |
| Write a brand-new detection rule | [`authoring-new-rules.md`](./authoring-new-rules.md) |
| Change an existing rule's CQL / severity / schedule | [`updating-rules.md`](./updating-rules.md) |
| Bring a bootstrap-imported rule up to the format standard | [`standardization-sweep.md`](./standardization-sweep.md) |
| Delete / retire a rule | [`deleting-rules.md`](./deleting-rules.md) |
| Understand when changes actually reach CrowdStrike | [`deployment-lifecycle.md`](./deployment-lifecycle.md) |
| Know the CQL and metadata standards | [`rule-quality-standards.md`](./rule-quality-standards.md) |
| Diagnose a broken pipeline, drift alert, or apply failure | [`troubleshooting.md`](./troubleshooting.md) |

## Core principles

1. **The repo is the source of truth.** A rule that isn't in a merged MR isn't a deployed detection. The scheduled drift job catches edits made only in the UI, then absorbs them into `main` or flags them for review.
2. **Merging is safe; deploying is deliberate.** Merging a rule MR to `main` doesn't deploy it. The `apply` stage is `when: manual`, so a person has to start it. That prevents an accidental mass deploy after many merges.
3. **Deletes take two steps.** MR 1 sets `lifecycle.deletion_requested: true` and MR 2 removes the file, because a delete is permanent.
4. **Standardization is an ongoing sweep, not a deadline.** Imported rules stay `standardization_pending: true` until someone touches them. Each sweep is a small MR.
5. **Local tooling is read-only.** All deploy credentials live in CI. People and any AI assistants author and validate; CI runners execute.

## Common daily actions

```bash
source .venv/bin/activate
git checkout main && git pull

# Read-only Falcon creds for plan/import
export FALCON_CLIENT_ID=<RO_client_id>
export FALCON_CLIENT_SECRET=<RO_client_secret>
export FALCON_BASE_URL=https://api.crowdstrike.com   # your tenant's API base URL

make validate       # lint all rules
make plan           # diff the local repo against Falcon
```

## Out of scope

- **How to write good CQL for detecting a given TTP.** That's detection design, not workflow. See CrowdStrike's CQL / LogScale query documentation.
- **How alerts route to analysts.** That's downstream of this repo, in your case-management or SOAR integration.
