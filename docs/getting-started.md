# Getting Started

This guide takes you from nothing to a working local clone that validates rules and plans against your Falcon tenant.

## Prerequisites

- Python 3.11+
- Git
- A Falcon API client with **Correlation Rules: Read** scope. That scope is all you need locally; the write credential lives only in CI.

## Setup

```bash
git clone <your fork or copy of this repo>
cd ngsiem-detection-as-code
python3 -m venv .venv
source .venv/bin/activate
make install
```

Set read-only credentials. A secrets manager or `direnv` with an untracked `.envrc` both work; `.envrc` is already in `.gitignore`.

```bash
export FALCON_CLIENT_ID=<RO_client_id>
export FALCON_CLIENT_SECRET=<RO_client_secret>
export FALCON_BASE_URL=https://api.crowdstrike.com   # your tenant's API base URL
```

## Bootstrap your rules

To track the rules already in your tenant:

```bash
make import       # writes one YAML per remote rule into rules/
make validate
make plan         # should report 0 to create / update / delete
```

Imported rules are tagged `lifecycle.standardization_pending: true`, so the CQL format linter skips them until they're swept. See [standardization-sweep.md](./standardization-sweep.md).

To start fresh instead, copy `examples/rule_template.yml` into `rules/` and follow [authoring-new-rules.md](./authoring-new-rules.md).

## Customize for your tenant

- **`schema/log_sources.json`**: list the log sources you've onboarded. A rule's `log_source` must be one of these keys.
- **`DAC_RUNBOOK_URL_PREFIX`** (optional env / CI var): require `runbook_url` to point at your wiki.
- **`DAC_BOT_EMAIL`** (optional CI var): the commit author for backfill and reconcile commits.
- **CQL format standard**: if your house style differs, edit `_check_cql_format` in `scripts/validate_rules.py`.

## Wire up CI

See the credential table in the root [README](../README.md#credential-model) and [deployment-lifecycle.md](./deployment-lifecycle.md). The minimum setup:

1. Add the RO and RW Falcon credentials, `FALCON_CID`, and `FALCON_BASE_URL` as CI/CD variables.
2. Optionally add an SSH deploy key as `SSH_DEPLOY_KEY` so IDs backfill automatically.
3. Optionally create a scheduled pipeline with `DRIFT_CHECK=true` for daily drift detection.

## Troubleshooting

- **`make validate` fails with a missing-module error**: your venv isn't active. Run `source .venv/bin/activate`.
- **`make plan` fails with 401**: the credential is wrong, or `FALCON_BASE_URL` points at the wrong cloud region.
- For pipeline, drift, and apply problems, see [troubleshooting.md](./troubleshooting.md).
