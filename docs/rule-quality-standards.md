# Rule Quality Standards

The canonical reference for what an NG-SIEM correlation rule must look like. The validator enforces these on any rule with `lifecycle.standardization_pending: false`. Bootstrap-imported rules (`standardization_pending: true`) are exempt until they're swept.

## The CQL format standard

Every rule's `search.filter` must include four elements:

### 1. Enrichment

```cql
| ipLocation(<ip-field>)
| asn(<ip-field>)
```

Applied to whatever IP you're correlating on (client.ipAddress, src_ip, etc.). This gives analysts geolocation and ASN context at detection time — no separate enrichment step needed.

### 2. Consolidation

```cql
| groupBy([<pivot-key>],
    function=[
      collect([<field>, <field>, <field>, ...])
    ])
```

Collapse the event stream into one row per pivot key. The `collect([...])` list must include every field you want visible in the alert payload. Analysts read the output of `groupBy` — if it's not collected, it's invisible.

### 3. Human-readable description

```cql
| format(format="<rule-specific narrative>",
         field=[<field1>, <field2>, ...],
         as=detection.description)
```

Example:

```cql
| format(format="Okta impossible travel for %s between %s and %s",
         field=[actor.alternateId, last_country, curr.client.ipAddress.country],
         as=detection.description)
```

This populates `detection.description` in the alert — first thing an analyst reads in the alert or case.

### 4. TI confidence gate

If the rule calls `ioc:lookup(` or `threatFeed`:

```cql
| ioc:lookup(field=..., type=..., confidenceThreshold="high")
```

`high` only. Medium produces too many false positives — the TI feed's own confidence is already calibrated generously.

## Full canonical example

From [`examples/rule_template.yml`](../examples/rule_template.yml):

```cql
#Vendor="okta" #event.module="okta" #event.dataset="okta.system"
| eventType=/user\.session\.start/
| outcome.result="SUCCESS"
| ipLocation(client.ipAddress)
| asn(client.ipAddress)
| groupBy([actor.alternateId],
    function=[
      collect([client.ipAddress, client.ipAddress.city, client.ipAddress.state,
               client.ipAddress.country, client.ipAddress.org, eventType]),
      selectLast([client.ipAddress.country], as=last_country),
      selectFromMax(field=@timestamp, include=[client.ipAddress.country], as=curr)
    ])
| last_country != curr.client.ipAddress.country
| format(format="Okta impossible travel for %s between %s and %s",
         field=[actor.alternateId, last_country, curr.client.ipAddress.country],
         as=detection.description)
```

Note:
- Starts with data-source tag filters (`#Vendor`, `#event.module`, `#event.dataset`) — fast index-hit
- Event-type filter as a regex for flexibility
- Enrichment and consolidation
- Narrative format line at the end

## Metadata standards

### Required fields

- `id` — `null` for new rules, hex32 for existing
- `name` — unique across repo, human-readable, short
- `severity` — one of 10/30/50/70/90, see scale below
- `status` — `active` or `inactive`
- `coverage_category` — `endpoint`, `cloud`, or `identity`
- `search` object
- `schedule` object
- `lifecycle` object

### Optional but strongly encouraged

- `description` — one sentence, answer "what triggers this?"
- `tactic` — MITRE ATT&CK tactic ID ("TA0001"); the create API rejects the name form
- `technique` — ATT&CK technique ID (`T####` or `T####.###`); CrowdStrike custom (`CST####`) also accepted
- `log_source` — key from `schema/log_sources.json`
- `runbook_url` — link to the runbook (prefix enforced only if `DAC_RUNBOOK_URL_PREFIX` is set)
- `owner` — team alias or email
- `notes` — tuning history, volume expectations, exception rationale

### Severity scale

Falcon's create API accepts only five discrete severity values. Anything else returns `400 expected RuleCreateRequestV1.Severity to be one of: 10 30 50 70 90`.

| Value | Tier | Response expectation |
|---|---|---|
| `10` | Informational | Monitored; no response unless correlating signal |
| `30` | Low | Monitored; tuning expected during cycles |
| `50` | Medium | Triage within 1 business day |
| `70` | High | Triage within 4 business hours; analyst response |
| `90` | Critical | Page on-call; immediate triage; runbook must exist |

Severity is calibrated against expected alert volume. A severity-90 rule producing 10 alerts/day is misconfigured — either tune down the volume or drop the severity.

### MITRE mapping

- **Tactic** — use the **ID form**: `TA0001`, `TA0011`, etc. The Falcon create API rejects the Title Case name (`"Initial Access"`) with `RuleCreateRequestV1.Tactic is not a valid tactic`. Some bootstrap-imported rules still carry name-form tactics — those are exempt via `standardization_pending`, but all new rules must use TA####.
- **Technique** — specific pattern. Format `T####` or `T####.###`. Example: `T1078.004` (Valid Accounts — Cloud Accounts). **Technique must be a valid sub-category of the specified tactic** — Falcon validates the mapping. E.g. `T1078.004` (Cloud Accounts) is not a child of TA0011 (Command and Control); pairing them fails with `Technique T1078.004 is not a technique of tactic Command and Control`.
- **CrowdStrike custom IDs** — `CST####` is accepted on imported legacy rules for tradecraft without a MITRE equivalent. New rules should use real ATT&CK IDs.

Cache refresh: `make refresh-mitre` pulls the latest ATT&CK Enterprise STIX bundle. Run it periodically (or add a scheduled CI job) and commit the result.

### `search.trigger_mode`

Valid values: `summary`, `smart`, `all`, `verbose`. For new standard correlation rules, **use `summary`**. `smart` is only valid for certain rule types (IDP detections and similar) — Falcon's create API rejects it with `search.trigger_mode 'smart' is not valid for rule type` when used on a standard correlation rule. `verbose` and `all` are returned on GET for some legacy rules; the schema accepts them but `summary` is the default.

### `search.outcome`

`detection` (most rules) or `incident` (rolls up to a case). The schema also permits `case` and `null` because some imported legacy rules have those values, but **only `detection` and `incident` work on create** per the Falcon API docs.

## Schedule and lookback pairing

Rules chain scheduled runs — each run queries the last `lookback` window. The correct default is:

**`lookback` == `schedule` interval.** Each run covers exactly one non-overlapping window. No duplicates.

| Schedule | Correct lookback |
|---|---|
| `@every 5m` | `5m` |
| `@every 10m` | `10m` |
| `@every 1h` | `1h` |
| `@every 24h` | `24h` |

### Why overlap is usually wrong

An earlier version of this doc suggested a 15-minute lookback on a 10-minute schedule for "safety". That's wrong for most rules — it means each event inside the overlap is seen by multiple runs and fires duplicate detections. For a 10-min schedule with 15-min lookback, every event fires the rule ~1.5 times on average; for an hourly schedule with 75-min lookback (the old example), every event fires ~1.25 times.

**The detection engine handles run-boundary stitching internally** — you don't need to pad for ingest lag.

### When lookback > schedule IS appropriate

**The test**: does the rule **count and then filter by count**? If yes, a slightly longer lookback is usually fine. Examples:

- `| groupBy([user], function=count()) | _count >= 5` — "5 failed logins by the same user". Each user only crosses the threshold once per window; overlapping runs re-emit the same user+count pair, which Falcon dedupes inherently.
- `| groupBy([user, bin(@timestamp, span=1h)]) | ...` — explicit time-bucket key means the same `(user, bucket)` can only emit once.
- **Correlation across event types** using `selfJoinFilter`, which dedupes by construction.

In these cases, a typical pairing is `schedule: @every 1h0m` + `lookback: 1h20m` (a 33% buffer gives a count-based rule enough headroom to catch slow-arriving events at the window edge).

If a rule is **not** counting-and-filtering — e.g., just `groupBy([key], function=collect([...]))` emitting one alert per matched event — then overlap DOES produce duplicates. Pair lookback to schedule exactly.

Document the overlap rationale in `notes` when you use it.

### When lookback < schedule

Never. That leaves gaps between runs where events are missed entirely.

### Zero lookback

`0h0m` / `0h` means the rule fires but queries nothing — a known hazard in bootstrap rules. The validator hard-fails this on any `standardization_pending: false` rule.

## Accepted duration formats

Falcon stores durations in Go-style multi-unit format. All of these are valid:

- `30s`
- `75m`
- `1h`, `2h`, `24h`
- `1h30m`, `2h0m`, `24h0m`
- `@every 10m`, `@every 1h0m`, `@every 0h15m`

All of these are also valid for `schedule.definition`:

- 5-field cron: `*/10 * * * *`, `0 6 * * *`, `0 */4 * * *`
- Falcon interval: `@every 10m`, `@every 1h`, `@every 24h0m`

**Do not translate between cron and @every.** They're not semantically equivalent — cron fires on wall-clock boundaries, @every fires at a fixed offset from rule creation. Preserve whatever Falcon stores.

## Anti-patterns the linter catches

| Anti-pattern | Check |
|---|---|
| Missing `ipLocation(` in CQL | `cql_format` |
| Missing `asn(` in CQL | `cql_format` |
| Missing `groupBy(` in CQL | `cql_format` |
| Missing `collect(` in CQL | `cql_format` |
| TI lookup without `confidenceThreshold="high"` | `ti_confidence` |
| Unbalanced parens/brackets in CQL | `cql_sanity` |
| Zero-duration `search.lookback` | `lookback_zero` |
| Empty `search.lookback` | `lookback_missing` |
| `log_source` not in allowlist | `log_source` |
| Bad MITRE tactic/technique | `mitre_tactic`, `mitre_technique` |
| `runbook_url` doesn't start with `DAC_RUNBOOK_URL_PREFIX` (default `https://`) | `runbook_url` |
| Duplicate rule name | `uniqueness_name` |
| Duplicate rule id | `uniqueness_id` |

All of the CQL / MITRE / lookback checks are skipped while `standardization_pending: true`. Schema-level checks and uniqueness checks run always.

## One principle above all

The validator exists to protect analysts from noisy, ambiguous, or undeployable detections at review time rather than at 3am on-call. When a check fails, it's correcting the rule before it fires — not after.
