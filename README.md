# ngsiem-detection-as-code

Detection-as-code for **CrowdStrike Falcon Next-Gen SIEM** correlation rules. Every rule is a reviewable YAML file; CI validates it, shows a plan against your Falcon tenant, and applies the change after merge.

The pipeline ships for GitLab CI. The scripts are plain Python, so porting to GitHub Actions or another CI system means rewriting only the job definitions.

**Handbook:** [`docs/`](./docs/README.md) covers authoring, updating, standardizing, deleting, and deploying rules.

## What you get

- **Rule schema** ([`schema/rule.schema.json`](./schema/rule.schema.json)) covering name, severity, MITRE mapping, CQL, lookback, schedule, and lifecycle flags.
- **Validator** ([`scripts/validate_rules.py`](./scripts/validate_rules.py)) with no network calls. It checks the schema, MITRE IDs against a cached ATT&CK bundle, CQL sanity (balanced parens, non-zero lookback), an opinionated CQL format standard, and name/id uniqueness.
- **Sync engine** ([`scripts/sync_detections.py`](./scripts/sync_detections.py)) with `--plan`, `--apply`, and `--drift` modes against the Falcon correlation-rules API. It uses fail-safe deletes and continues past failures on individual rules.
- **Bootstrap importer** ([`scripts/import_from_falcon.py`](./scripts/import_from_falcon.py)) that pulls your existing tenant rules into YAML so you can start from what you already have.
- **Drift reconcile**: a scheduled job detects edits made in the Falcon UI and optionally commits them back to `main`.
- **Coverage summary** ([`scripts/coverage_summary.py`](./scripts/coverage_summary.py)), a JSON artifact with active-rule counts and ATT&CK techniques per coverage category.

## Quickstart

```bash
git clone <this repo> && cd ngsiem-detection-as-code
python -m venv .venv && source .venv/bin/activate
make install

export FALCON_CLIENT_ID=<RO_client_id> FALCON_CLIENT_SECRET=<RO_client_secret>
export FALCON_BASE_URL=https://api.crowdstrike.com   # your tenant's API base URL
make import            # one-time: pull existing tenant rules into rules/
make validate          # static checks, no network
make plan              # read-only diff against the tenant
```

To start from an empty repo, copy [`examples/rule_template.yml`](./examples/rule_template.yml) into `rules/` instead of importing.

## Credential model

| Credential | Type | Used by |
|---|---|---|
| `FALCON_CLIENT_ID_RO` / `FALCON_CLIENT_SECRET_RO` | Falcon API, `Correlation Rules: Read` | local dev and the `validate`, `plan`, and `drift` jobs (CI var: masked, **unprotected**, because MR pipelines need it) |
| `FALCON_CLIENT_ID_RW` / `FALCON_CLIENT_SECRET_RW` | Falcon API, `Correlation Rules: Read + Write` | only the `apply` job (CI var: masked, **protected**, default branch only) |
| `FALCON_CID` | Falcon tenant Customer ID (32 hex) | `apply` job only (CI var: protected). The `create_rule` API requires it. |
| `FALCON_BASE_URL` | tenant API base URL | all jobs |
| `SSH_DEPLOY_KEY` | SSH private key with repo write access | `apply` and `drift` (CI var: **File type**, protected). Enables automatic ID backfill and drift auto-reconcile. |
| `DAC_BOT_EMAIL` | optional | author email for bot commits |
| `DAC_RUNBOOK_URL_PREFIX` | optional | if set, `runbook_url` must start with this prefix (e.g. your wiki) |

**Never** put the RW credential or `SSH_DEPLOY_KEY` on a workstation or give them to an AI coding assistant. Keep both only in CI/CD variables. Local work uses the RO credential. Full write round-trips go through CI, or through a dedicated terminal pointed at a non-production tenant.

Repo-write automation uses an SSH deploy key, so no personal or project access tokens are needed. That also works in orgs that disable project access tokens.

## Pipeline lifecycle

```
author rule YAML  -->  open MR  -->  validate + plan  -->  review  -->  merge  -->  apply (manual)
                                                                                         |
                                                                Falcon create/update/delete,
                                                                then auto-backfill ids to main
```

- **validate** runs on every push. It's fast, makes no network calls, and hard-fails on schema or format violations.
- **plan** runs on every MR with RO creds. It writes a `plan.txt` artifact. `CREATE`, `UPDATE`, `DELETE`, and `REPAIR ID` sections list the actions apply will take. Two sections are informational: `REMOTE-ONLY` (a rule in the tenant with no local YAML) and `REMOTE-MISSING` (a local YAML whose id no longer exists remotely).
- **apply** runs on the default branch after merge. It ships as `when: manual`; flip it to automatic once you trust it. It uses the RW creds and continues past failures on individual rules. If `SSH_DEPLOY_KEY` is configured, it commits the Falcon-assigned IDs back to `main` with `[skip ci]`.
- **drift** runs on a schedule with RO creds, when `DRIFT_CHECK=true` is set on the schedule. If the Falcon state differs from `main` and a deploy key is configured, it runs `import_from_falcon.py --overwrite` and pushes a reconcile commit. Without a deploy key, it only fails the pipeline so notifications fire.

## Rule lifecycle

1. **Draft**: a new file on a branch, with `id: null`.
2. **Active**: merged and applied. The apply job backfills `id`, and `status` is `active`.
3. **Deleted**, in two steps:
   - **MR 1** sets `lifecycle.deletion_requested: true`. This records intent and makes no API call.
   - **MR 2** runs `git rm rules/<file>.yml`. The apply job deletes only the rules whose files were removed.

`status: inactive` means deployed but disabled. Use it to pause a rule.

## Format standard (opinionated)

The validator enforces a house style that keeps alerts readable for triage. Every rule's CQL must include:

- `ipLocation(<ip>)` and `asn(<ip>)` enrichment (Falcon sensor telemetry is exempt)
- `groupBy([key], function=[collect([...])])` consolidation
- `detection.description` via `format(...)`
- `confidenceThreshold="high"` on any TI lookup (`ioc:lookup(`, `threatFeed`)

Rules from the bootstrap importer are tagged `lifecycle.standardization_pending: true` and skip these checks until someone brings them up to standard. If your team wants a different standard, edit `_check_cql_format` in `scripts/validate_rules.py`.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`docs/rule-quality-standards.md`](./docs/rule-quality-standards.md).

## ID backfill

When `apply` creates a rule, Falcon assigns it a hex ID. The ID has to end up in the local YAML so later plans match the rule by ID and renames are safe.

**Automatic (recommended):** add an SSH deploy key with write access as the `SSH_DEPLOY_KEY` CI variable.

1. Generate an ed25519 keypair.
2. Add the public key as a Deploy Key in the project with write permission.
3. Allow the deploy key to push to the protected `main` branch.
4. Store the private key as CI variable `SSH_DEPLOY_KEY` (Type: File, Protected).

**Manual fallback:** without the key, apply logs the new IDs to `plan.txt`. Then run `make import-overwrite` locally and commit the diff. Until then, sync matches `id: null` rules by `name`, so it creates no duplicates.

## Known limitations

- **`trigger_mode: "smart"` is rejected on create** for standard correlation rules, even though some legacy rules return it on GET. Use `summary`.
- **The tactic must be the ATT&CK ID** (`TA0001`, not `Initial Access`), and the technique must belong to that tactic. Falcon validates both.
- **Severity accepts only** `10 / 30 / 50 / 70 / 90`.

## Contributing

Issues and PRs are welcome. Run `make validate && make test` before opening one.

## License

[Apache-2.0](./LICENSE)
