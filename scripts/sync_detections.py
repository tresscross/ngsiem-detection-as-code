#!/usr/bin/env python3
"""Plan or apply the local rules/ directory against a CrowdStrike Falcon tenant.

Two modes:
    --plan   read-only diff. CI runs this on every MR with RO credentials. Never calls write APIs.
    --apply  creates/updates/deletes rules to match the local repo. Only runs in the GitLab
             runner on default-branch merges with RW credentials.

Exit codes:
    0  clean (no changes applied or needed)
    2  diff present (--plan mode found changes — CI signal that MR has intent)
    3  local validation failure
    4  Falcon API failure
    5  drift detected (scheduled drift job)

Auth via env: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL.
Same var names locally and in CI. Apply mode probes the credential's scope and refuses to run
if write access is not available.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

try:
    from falconpy import CorrelationRules
except ImportError:
    print("error: crowdstrike-falconpy not installed. Run `pip install -e .` first.",
          file=sys.stderr)
    sys.exit(1)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = REPO_ROOT / "rules"
PLAN_ARTIFACT = REPO_ROOT / "plan.txt"

# Fields sent on update. Preserves search.outcome as its OWN comma-separated entry —
# the reference falconpy sample had a bug where the list was missing a comma and drift
# in search.outcome was silently undetectable. Do not port that bug.
UPDATE_WHITELIST = (
    "name",
    "description",
    "severity",
    "tactic",
    "technique",
    "search.outcome",
    "search.filter",
    "search.lookback",
    "search.trigger_mode",
    "status",
    "schedule.definition",
)

# Local YAML uses `schedule.definition` (nice flat shape for authors);
# Falcon's API nests schedule under `operation`. This mapping translates the
# local path to the API path when building update/create payloads AND when
# normalizing remote rules back to local shape for hash comparison.
LOCAL_TO_API_PATH = {
    "schedule.definition": "operation.schedule.definition",
}


def _set_nested(d: dict, dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def _normalize_remote(remote_rule: dict) -> dict:
    """Reshape a Falcon API rule to match the local YAML layout so hash
    comparison lines up. Specifically: lift operation.schedule up to a
    top-level schedule key."""
    result = dict(remote_rule)
    operation = remote_rule.get("operation") or {}
    sched = operation.get("schedule")
    if isinstance(sched, dict):
        result["schedule"] = sched
    return result


def _canonical(v: Any) -> Any:
    """Treat None and '' as the same empty value so hash comparisons don't
    flap between Falcon's '' and our null representations. Coerce ruamel
    scalar subclasses to plain str for JSON serialization."""
    if v is None or v == "":
        return ""
    if isinstance(v, (int, float, bool, str)):
        # str covers LiteralScalarString etc. via subclass relation.
        return v if type(v) in (int, float, bool, str) else str(v)
    return str(v)


# --------- YAML / local state ---------

_yaml = YAML()
_yaml.preserve_quotes = True
_yaml.width = 10_000
_yaml.indent(mapping=2, sequence=4, offset=2)


def load_local_rules(rules_dir: Path) -> dict[Path, dict]:
    """Load rules/*.yml into a dict keyed by path."""
    result: dict[Path, dict] = {}
    for rule_path in sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml")):
        with rule_path.open() as f:
            result[rule_path] = _yaml.load(f)
    return result


def write_local_rule(rule_path: Path, rule: dict) -> None:
    """Write a rule back to disk, preserving comments/ordering via ruamel."""
    with rule_path.open("w") as f:
        _yaml.dump(rule, f)


# --------- Content hashing ---------

def _get_nested(d: dict, dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def content_hash(rule: dict) -> str:
    """Deterministic hash over UPDATE_WHITELIST fields only. Remote rules must
    be passed through _normalize_remote() first so their schedule field is at
    the local path. Values are run through _canonical() so None and '' hash
    identically — Falcon emits '' for unset string fields, we import as null."""
    payload = {field: _canonical(_get_nested(rule, field)) for field in UPDATE_WHITELIST}
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


# --------- Falcon API ---------

def build_client() -> CorrelationRules:
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")
    base_url = os.environ.get("FALCON_BASE_URL", "auto")
    if not client_id or not client_secret:
        print("error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set in environment.",
              file=sys.stderr)
        sys.exit(4)
    return CorrelationRules(client_id=client_id, client_secret=client_secret, base_url=base_url)


def _ok(status_code: int | None) -> bool:
    """Tolerate any 2xx — reference sample's exact == 200 check missed 207 partial-success."""
    return status_code is not None and 200 <= status_code < 300


def fetch_all_remote(client: CorrelationRules) -> dict[str, dict]:
    """Paginate get_rules_combined and return a dict keyed by rule id."""
    result: dict[str, dict] = {}
    offset = 0
    page_size = 100
    while True:
        resp = client.get_rules_combined(limit=page_size, offset=offset,
                                         sort="last_updated_on|asc")
        status = resp.get("status_code")
        if not _ok(status):
            raise RuntimeError(f"get_rules_combined failed: status={status} body={resp.get('body')}")
        body = resp.get("body", {})
        resources = body.get("resources") or []
        for r in resources:
            if r.get("id"):
                result[r["id"]] = r
        meta_pagination = body.get("meta", {}).get("pagination", {})
        total = meta_pagination.get("total")
        if not resources:
            break
        offset += len(resources)
        if total is not None and offset >= total:
            break
    return result


def probe_write_scope(client: CorrelationRules) -> bool:
    """Attempt a write with a deliberately invalid payload and check the error type.
    A read-only token returns 403; a write token returns 400/422 for bad payload.
    Ugly but effective — Falcon has no scope-introspection endpoint."""
    resp = client.create_rule(name="")  # empty name should 400 on write, 403 on read-only
    status = resp.get("status_code")
    if status == 403:
        return False
    if status in (400, 422, 500):
        return True
    if _ok(status):
        # Unexpected success with empty name — delete immediately.
        rid = (resp.get("body", {}).get("resources") or [{}])[0].get("id")
        if rid:
            client.delete_rules(ids=rid)
        return True
    return True  # conservative: assume write available if we can't tell


# --------- Diff planning ---------

@dataclass
class Plan:
    to_create: list[tuple[Path, dict]] = field(default_factory=list)
    to_update: list[tuple[Path, dict, dict]] = field(default_factory=list)  # path, local, remote
    to_delete: list[dict] = field(default_factory=list)  # remote-only rules flagged for delete
    # Remote rules with no local YAML match. Surfaced by drift mode so UI-authored
    # rules don't go silent. Apply mode ignores this bucket — importing is
    # import_from_falcon.py's job, not sync_detections.py's.
    to_import: list[dict] = field(default_factory=list)
    # Local rules with a non-null id whose remote has vanished. Almost always
    # means "deleted in the UI" (new rules have null id). Apply mode MUST NOT
    # treat these as to_create — that silently resurrected rules the user meant
    # to delete. Surface for human review; confirm the deletion by removing
    # the YAML in a PR, which then flows through the existing to_delete path.
    remote_missing: list[tuple[Path, dict]] = field(default_factory=list)
    # Metadata-only repair: local id is stale but content matches the remote
    # rule matched via name. No API call; apply_plan just writes the new id
    # to the local YAML so subsequent plans match on id directly.
    to_repair_id: list[tuple[Path, dict, dict]] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.to_create or self.to_update or self.to_delete
                    or self.to_import or self.remote_missing or self.to_repair_id)

    @property
    def has_apply_work(self) -> bool:
        """Buckets that apply_plan actually acts on. Excludes to_import
        (import_from_falcon.py's job) and remote_missing (needs human
        confirmation via YAML deletion) so apply mode doesn't spuriously
        early-exit-block or warn on state that's informational only."""
        return bool(self.to_create or self.to_update or self.to_delete
                    or self.to_repair_id)

    def summary(self) -> str:
        parts = [f"Plan: {len(self.to_create)} to create, "
                 f"{len(self.to_update)} to update, "
                 f"{len(self.to_delete)} to delete, "
                 f"{self.unchanged} unchanged."]
        if self.to_import:
            parts.append(f"({len(self.to_import)} remote-only rule(s) not tracked locally.)")
        if self.remote_missing:
            parts.append(f"({len(self.remote_missing)} local rule(s) whose remote has vanished — "
                         f"confirm by deleting the YAML.)")
        if self.to_repair_id:
            parts.append(f"({len(self.to_repair_id)} stale local id(s) to repair — no API call.)")
        return " ".join(parts)

    def detail(self) -> str:
        lines = [self.summary(), ""]
        if self.to_create:
            lines.append("CREATE:")
            for path, rule in self.to_create:
                lines.append(f"  + {rule.get('name')}  ({path.name})")
            lines.append("")
        if self.to_update:
            lines.append("UPDATE:")
            for path, local, remote in self.to_update:
                lines.append(f"  ~ {local.get('name')}  ({path.name})  id={remote.get('id')}")
            lines.append("")
        if self.to_delete:
            lines.append("DELETE:")
            for r in self.to_delete:
                lines.append(f"  - {r.get('name')}  id={r.get('id')}")
            lines.append("")
        if self.to_import:
            lines.append("REMOTE-ONLY (untracked in repo — likely UI-authored):")
            for r in self.to_import:
                lines.append(f"  ? {r.get('name')}  id={r.get('id')}")
            lines.append("")
        if self.remote_missing:
            lines.append("REMOTE-MISSING (local has id, remote is gone — likely UI-deleted; "
                         "remove the YAML to confirm):")
            for path, rule in self.remote_missing:
                lines.append(f"  ! {rule.get('name')}  ({path.name})  id={rule.get('id')}")
            lines.append("")
        if self.to_repair_id:
            lines.append("REPAIR ID (metadata-only, no API call):")
            for path, local, remote in self.to_repair_id:
                lines.append(f"  * {local.get('name')}  ({path.name})  "
                             f"{local.get('id')} -> {remote.get('id')}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"


def build_plan(local: dict[Path, dict], remote: dict[str, dict],
               deleted_files_in_commit: set[str] | None = None) -> Plan:
    # Normalize remote rules to local YAML shape before any comparison.
    # Without this, `schedule.definition` reads None on every remote rule
    # (Falcon puts it under operation.schedule) and every rule appears as
    # a false-positive update.
    remote = {rid: _normalize_remote(r) for rid, r in remote.items()}
    plan = Plan()
    local_by_id: dict[str, tuple[Path, dict]] = {}
    local_no_id: list[tuple[Path, dict]] = []
    for path, rule in local.items():
        rid = rule.get("id")
        if isinstance(rid, str) and rid:
            local_by_id[rid] = (path, rule)
        else:
            local_no_id.append((path, rule))

    remote_by_name: dict[str, dict] = {}
    for r in remote.values():
        n = r.get("name")
        if n:
            # If multiple remote rules share a name, keep the most-recently
            # updated one as the match target for ambiguous local lookups.
            existing = remote_by_name.get(n)
            if existing is None or (r.get("last_updated_on", "") > existing.get("last_updated_on", "")):
                remote_by_name[n] = r

    # Track which remote ids have been "claimed" by a local rule — either via
    # exact id match or via name fallback for stale-id scenarios. Unclaimed
    # remote rules are the only candidates for deletion.
    consumed_remote_ids: set[str] = set()

    # Rules with no id (new rules or post-bootstrap un-backfilled) — match by name.
    for path, rule in local_no_id:
        name = rule.get("name")
        if name in remote_by_name:
            matched = remote_by_name[name]
            consumed_remote_ids.add(matched["id"])
            if content_hash(rule) != content_hash(matched):
                plan.to_update.append((path, rule, matched))
            else:
                # Content matches remote; local id is null. Queue a repair
                # so the next apply writes the remote id back into the local
                # YAML (carried by the SSH-backfill commit). Without this,
                # local would stay id:null forever and rely on name-fallback
                # on every future plan.
                plan.to_repair_id.append((path, rule, matched))
        else:
            plan.to_create.append((path, rule))

    # Rules with an id — try id match first, fall back to name match (handles
    # stale ids, UI-recreated rules, and cross-tenant migrations).
    for rid, (path, rule) in local_by_id.items():
        remote_rule = remote.get(rid)
        if remote_rule is not None:
            consumed_remote_ids.add(rid)
            if content_hash(rule) != content_hash(remote_rule):
                plan.to_update.append((path, rule, remote_rule))
            else:
                plan.unchanged += 1
            continue
        # Id not in remote — try to recover via name match. This prevents
        # the "stale id → accidental create of a duplicate" hazard. The
        # apply_plan step writes back the correct id to the local YAML
        # regardless of whether an API update was actually needed.
        name = rule.get("name")
        matched = remote_by_name.get(name)
        if matched is not None and matched["id"] not in consumed_remote_ids:
            consumed_remote_ids.add(matched["id"])
            if content_hash(rule) != content_hash(matched):
                plan.to_update.append((path, rule, matched))
            else:
                # Content is fine; only the local id is stale. Queue a
                # metadata-only repair that's apply_plan's job to handle.
                plan.to_repair_id.append((path, rule, matched))
            continue
        # Neither id nor name matches any remote rule. A non-null id means
        # the rule was successfully applied at some point and subsequently
        # disappeared from the tenant — almost certainly a UI deletion.
        # The old code re-created it, resurrecting rules the user meant
        # to delete. Surface for human review instead; removing the YAML
        # in a follow-up PR routes through the existing to_delete path.
        plan.remote_missing.append((path, rule))

    # Deletes first — a rule going into to_delete must NOT also appear in
    # to_import. Without this ordering, the same remote rule would be listed
    # as "remote-only (import me)" and "pending delete" simultaneously.
    to_delete_rids: set[str] = set()
    if deleted_files_in_commit is not None:
        all_local_names = {r.get("name") for r in local.values() if r.get("name")}
        for rid, remote_rule in remote.items():
            if rid in consumed_remote_ids:
                continue
            name = remote_rule.get("name")
            # Never delete a remote rule whose name is claimed by any local rule
            # (with or without id). That's a stale-id scenario, not an orphan.
            if name in all_local_names:
                continue
            if name not in deleted_files_in_commit:
                continue
            plan.to_delete.append(remote_rule)
            to_delete_rids.add(rid)

    # Remaining orphan remotes — surface as to_import so drift mode catches
    # UI-authored rules. Distinct from to_delete: import-needed is not the same
    # as delete-needed, and coupling them silenced UI-authored drift entirely
    # in --drift mode.
    for rid, remote_rule in remote.items():
        if rid in consumed_remote_ids or rid in to_delete_rids:
            continue
        plan.to_import.append(remote_rule)

    return plan


# --------- Apply ---------

# Falcon refuses to update schedule/start_on/stop_on on a rule that is in the
# 'inactive' state ("can't be transitioned in state 'inactive' and also update
# attributes 'schedule', 'start_on' or 'stop_on'"). The schedule is immutable
# while a rule is inactive, so any update that carries it — even an unchanged
# value sent for a name- or filter-only edit — 400s. Omit these fields from the
# payload for inactive rules; changing a schedule requires activating the rule
# first, which is an explicit status change, not a content edit.
_INACTIVE_IMMUTABLE_KEYS = frozenset({"schedule.definition"})


def _build_update_payload(rule: dict, rule_id: str) -> dict:
    payload: dict[str, Any] = {"id": rule_id}
    is_inactive = rule.get("status") == "inactive"
    for key in UPDATE_WHITELIST:
        if is_inactive and key in _INACTIVE_IMMUTABLE_KEYS:
            continue
        val = _get_nested(rule, key)
        if val is None:
            continue
        # Route local YAML paths to Falcon's API paths (e.g. schedule.definition
        # goes to operation.schedule.definition — see LOCAL_TO_API_PATH).
        api_path = LOCAL_TO_API_PATH.get(key, key)
        _set_nested(payload, api_path, val)
    return payload


def _build_create_payload(rule: dict) -> dict:
    payload: dict[str, Any] = {}
    for key in UPDATE_WHITELIST:
        val = _get_nested(rule, key)
        if val is None:
            continue
        api_path = LOCAL_TO_API_PATH.get(key, key)
        _set_nested(payload, api_path, val)
    # Only include customer_id if the tenant CID is explicitly set. Sending an
    # empty string makes Falcon reject with 401 "not authorized to create rule
    # in requested CID: <empty>" rather than falling back to the token's CID.
    cid = os.environ.get("FALCON_CID", "").strip()
    if cid:
        payload["customer_id"] = cid
    return payload


@dataclass
class ApplyResult:
    created: list[tuple[str, str, str]] = field(default_factory=list)  # (path_name, rule_name, new_id)
    failures: list[tuple[str, str, str]] = field(default_factory=list)  # (op, path_name, error)
    success_count: int = 0

    @property
    def has_failures(self) -> bool:
        return bool(self.failures)


def apply_plan(client: CorrelationRules, plan: Plan) -> ApplyResult:
    """Execute every operation in the plan, continuing past individual failures.
    Returns an ApplyResult with both successes and failures. The caller decides
    what to do with failures (typically: print a summary and exit non-zero).

    Rationale for continue-on-error: a 404 on one rule (e.g. a UI-authored rule
    that this api_client can't modify) shouldn't prevent other rules from being
    applied, or prevent the backfill push that carries successful creates' IDs
    back to the repo. Fail-fast let one rule's failure
    leave newly-created rule IDs stranded on the ephemeral runner."""
    result = ApplyResult()

    for path, rule in plan.to_create:
        try:
            payload = _build_create_payload(rule)
            resp = client.create_rule(body=payload)
            if not _ok(resp.get("status_code")):
                raise RuntimeError(f"status={resp.get('status_code')} body={resp.get('body')}")
            new_id = (resp.get("body", {}).get("resources") or [{}])[0].get("id")
            if not new_id:
                raise RuntimeError(f"no id returned: {resp.get('body')}")
        except Exception as e:
            result.failures.append(("create", path.name, str(e)))
            print(f"  FAIL create: {rule.get('name')}  ({path.name})  — {e}")
            continue
        rule["id"] = new_id
        try:
            write_local_rule(path, rule)
        except OSError:
            pass
        result.created.append((path.name, rule.get("name", ""), new_id))
        result.success_count += 1
        print(f"  created: {rule.get('name')}  id={new_id}  ({path.name})")

    for path, local_rule, remote_rule in plan.to_update:
        # Use rule_id (the API key), not id (the display field). For most
        # rules these are equal, but bootstrap-imported rules have them
        # diverged — sending the display id makes Falcon's PATCH endpoint
        # 404 with `Rule not found, id: <display_id>`.
        rid = remote_rule.get("rule_id") or remote_rule.get("id")
        try:
            payload = _build_update_payload(local_rule, rid)
            resp = client.update_rule(body=payload)
            if not _ok(resp.get("status_code")):
                raise RuntimeError(f"status={resp.get('status_code')} body={resp.get('body')}")
        except Exception as e:
            result.failures.append(("update", path.name, str(e)))
            print(f"  FAIL update: {local_rule.get('name')}  id={rid}  ({path.name})  — {e}")
            continue
        if local_rule.get("id") != rid:
            local_rule["id"] = rid
            try:
                write_local_rule(path, local_rule)
            except OSError:
                pass
        result.success_count += 1
        print(f"  updated: {local_rule.get('name')}  id={rid}  ({path.name})")

    for path, local_rule, remote_rule in plan.to_repair_id:
        new_id = remote_rule.get("id")
        old_id = local_rule.get("id")
        local_rule["id"] = new_id
        try:
            write_local_rule(path, local_rule)
        except OSError:
            pass
        result.success_count += 1
        print(f"  repaired local id: {local_rule.get('name')}  {old_id} -> {new_id}  ({path.name})")

    for remote_rule in plan.to_delete:
        # Delete keys off rule_id same as update — display id 404s on
        # bootstrap-imported rules.
        rid = remote_rule.get("rule_id") or remote_rule.get("id")
        try:
            resp = client.delete_rules(ids=rid)
            if not _ok(resp.get("status_code")):
                raise RuntimeError(f"status={resp.get('status_code')} body={resp.get('body')}")
        except Exception as e:
            result.failures.append(("delete", rid or "<no-id>", str(e)))
            print(f"  FAIL delete: {remote_rule.get('name')}  id={rid}  — {e}")
            continue
        result.success_count += 1
        print(f"  deleted: {remote_rule.get('name')}  id={rid}")

    if result.failures:
        print()
        print(f"--- APPLY SUMMARY: {result.success_count} succeeded, {len(result.failures)} failed ---")
        for op, target, err in result.failures:
            print(f"  [{op}] {target}: {err[:200]}")

    return result


# --------- Entry point ---------

def _parse_deleted_names(deleted_names_arg: str | None) -> set[str] | None:
    if not deleted_names_arg:
        return None
    return {name.strip() for name in deleted_names_arg.split(",") if name.strip()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true", help="read-only diff against remote")
    mode.add_argument("--apply", action="store_true", help="create/update/delete to match local")
    mode.add_argument("--drift", action="store_true",
                      help="plan mode, but exits 5 on any diff (scheduled CI)")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--deleted-rule-names",
                        help="Comma-separated rule names that were deleted in this commit. "
                             "Only rules in this list can be deleted remotely. In CI, "
                             "compute this from `git diff --name-status`.")
    parser.add_argument("--plan-artifact", type=Path, default=PLAN_ARTIFACT)
    args = parser.parse_args(argv)

    client = build_client()

    try:
        remote = fetch_all_remote(client)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4

    local = load_local_rules(args.rules_dir)
    deleted_names = _parse_deleted_names(args.deleted_rule_names)
    plan = build_plan(local, remote, deleted_files_in_commit=deleted_names)

    # Write plan artifact in all modes.
    with args.plan_artifact.open("w") as f:
        f.write(plan.detail())

    print(plan.detail())

    if args.plan:
        return 2 if plan.has_changes else 0

    if args.drift:
        return 5 if plan.has_changes else 0

    # --apply: verify scope before doing anything.
    if not probe_write_scope(client):
        print("error: FALCON_CLIENT_ID does not have Correlation Rules: Write scope. "
              "Apply mode refused.", file=sys.stderr)
        return 4

    if not plan.has_apply_work:
        print("apply: no changes.")
        return 0

    result = apply_plan(client, plan)

    # Append created-rule IDs to the plan artifact so the CI job carries them out of the
    # ephemeral runner filesystem even if SSH push isn't configured.
    if result.created:
        with args.plan_artifact.open("a") as f:
            f.write("\n\nCREATED (backfill IDs locally via `make import-overwrite` if auto-backfill didn't run):\n")
            for path_name, name, new_id in result.created:
                f.write(f"  {path_name}  id={new_id}  name={name}\n")

    if result.failures:
        with args.plan_artifact.open("a") as f:
            f.write(f"\n\nFAILURES ({len(result.failures)}):\n")
            for op, target, err in result.failures:
                f.write(f"  [{op}] {target}: {err[:300]}\n")
        # Exit non-zero so CI surfaces the partial failure, but after having
        # completed every operation we could.
        return 4

    # Post-apply round-trip check: re-fetch and ensure no spurious drift remains.
    remote_after = fetch_all_remote(client)
    local_after = load_local_rules(args.rules_dir)
    followup = build_plan(local_after, remote_after)
    if followup.has_apply_work:
        print("WARNING: post-apply plan shows residual diff — likely a field was dropped "
              "by the update whitelist. Inspect plan.txt.", file=sys.stderr)
        with args.plan_artifact.open("a") as f:
            f.write("\n\n# POST-APPLY DRIFT\n" + followup.detail())

    return 0


if __name__ == "__main__":
    sys.exit(main())
