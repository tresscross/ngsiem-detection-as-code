#!/usr/bin/env python3
"""One-time bootstrap: pull every existing correlation rule from Falcon and write one YAML per rule.

Fields Falcon doesn't track (log_source, runbook_url, owner, notes) are left unset; fill them
in during the standardization sweep.

Every imported rule gets `lifecycle.standardization_pending: true` so the CQL format linter
skips its CQL; sweep MRs flip the flag to false as rules are brought to standard.

Requires read-only Falcon creds.

Usage:
    python scripts/import_from_falcon.py
    python scripts/import_from_falcon.py --rules-dir path/to/rules
"""
from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import LiteralScalarString, PreservedScalarString

try:
    from falconpy import CorrelationRules
except ImportError:
    print("error: crowdstrike-falconpy not installed. Run `pip install -e .` first.",
          file=sys.stderr)
    sys.exit(1)

# Reuse the fetch pagination logic from sync_detections.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sync_detections import build_client, fetch_all_remote  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = REPO_ROOT / "rules"

TODO = "TODO"
_yaml = YAML()
_yaml.preserve_quotes = True
_yaml.width = 10_000
_yaml.indent(mapping=2, sequence=4, offset=2)


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", name or "unnamed").strip("_").lower()
    return slug or "unnamed"


def _lookback(val: Any) -> str | None:
    """Preserve Falcon's lookback verbatim. No transformation.
    The user standardizes during the sweep if the format is non-obvious."""
    if isinstance(val, str) and val:
        return val
    if isinstance(val, (int, float)):
        return f"{int(val)}s"
    return None


def _schedule_def(schedule: dict | None) -> str | None:
    """Preserve Falcon's schedule definition verbatim. Do NOT translate
    `@every Xs/m/h/d` to cron — they're not equivalent (different phase,
    different semantics). The schema accepts both forms."""
    if not isinstance(schedule, dict):
        return None
    definition = schedule.get("definition")
    if isinstance(definition, str) and definition:
        return definition
    return None


def remote_to_rule(remote: dict, existing: dict | None = None) -> dict:
    """Build the local YAML rule dict from a Falcon remote rule.

    If `existing` is given (re-import of a rule already tracked in the repo),
    preserve local-only fields: log_source, runbook_url, owner, notes, and
    lifecycle.* (including standardization_pending). Only Falcon-authoritative
    fields are overwritten. This prevents re-imports from wiping metadata an
    analyst added, or reverting standardization_pending from false to true."""
    search = remote.get("search") or {}
    filter_cql = search.get("filter") or ""
    existing = existing if isinstance(existing, dict) else {}
    existing_lifecycle = existing.get("lifecycle") if isinstance(existing.get("lifecycle"), dict) else {}

    # Build fields in a stable order matching the convention used by earlier
    # bootstrap imports, so re-imports don't churn field order in every diff.
    rule: dict[str, Any] = {}
    # Falcon-authoritative scalars first
    rule["id"] = remote.get("id") or None
    rule["name"] = remote.get("name") or TODO
    rule["description"] = remote.get("description") or None
    rule["severity"] = remote.get("severity") or 50
    rule["status"] = remote.get("status") or "inactive"
    rule["tactic"] = remote.get("tactic") or None
    rule["technique"] = remote.get("technique") or None

    # Local-only metadata — preserve from existing, omit if absent.
    # coverage_category is repo-only (not represented in Falcon) and is required
    # by the schema, so it MUST be preserved across re-imports or every drift
    # reconcile will strip it from all rules and break the next validate job.
    for local_only in ("log_source", "runbook_url", "owner", "coverage_category"):
        if local_only in existing:
            rule[local_only] = existing[local_only]

    # notes: preserve existing, else seed with bootstrap reminder
    if "notes" in existing:
        rule["notes"] = existing["notes"]
    else:
        rule["notes"] = ("Imported from Falcon on bootstrap. Standardize CQL and clear "
                         "lifecycle.standardization_pending before the next sweep MR.")

    # Falcon-authoritative nested objects
    rule["search"] = {
        "filter": LiteralScalarString(filter_cql) if "\n" in filter_cql else filter_cql,
        "outcome": search.get("outcome") or None,
        "lookback": _lookback(search.get("lookback")),
        "trigger_mode": search.get("trigger_mode") or None,
    }
    rule["schedule"] = {
        "definition": _schedule_def(remote.get("operation", {}).get("schedule")),
    }

    # lifecycle always last
    rule["lifecycle"] = {
        "created": existing_lifecycle.get("created", str(dt.date.today())),
        "last_reviewed": existing_lifecycle.get("last_reviewed", str(dt.date.today())),
        "deletion_requested": existing_lifecycle.get("deletion_requested", False),
        # standardization_pending defaults to True for new imports, but preserve
        # whatever the user set (commonly False once swept).
        "standardization_pending": existing_lifecycle.get(
            "standardization_pending", True if not existing else False
        ),
    }
    # Carry legacy_ids through if set
    if "legacy_ids" in existing_lifecycle:
        rule["lifecycle"]["legacy_ids"] = existing_lifecycle["legacy_ids"]

    return rule


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing YAML files (dangerous).")
    args = parser.parse_args(argv)

    args.rules_dir.mkdir(parents=True, exist_ok=True)
    # Note: we do NOT purge disambiguation-suffix files (pattern _<hex8>.yml)
    # anymore. The id-based existing-file matching below handles all cases —
    # disambig files get updated in place by the remote rule whose id matches
    # theirs, so they never become "stale." A blanket purge was destructive
    # when combined with the name-fallback logic (two same-named Falcon rules
    # would collapse into one file with only the last-processed content).

    client = build_client()
    remote = fetch_all_remote(client)
    if not remote:
        print("No remote rules found.")
        return 0

    # Index existing YAML files by id and by name so we can update in place
    # instead of creating a new slug-based filename. Without this, a rule
    # authored with a different slug convention (e.g. "my_custom_slug"
    # instead of the slugified name "okta_activity_by_user_...")
    # gets a SECOND file on import, producing uniqueness_name violations.
    # Also keeps existing content cached so remote_to_rule can preserve
    # local-only fields (log_source, notes, lifecycle.standardization_pending).
    existing_by_id: dict[str, Path] = {}
    existing_by_name: dict[str, Path] = {}
    existing_by_path: dict[Path, dict] = {}
    for path in sorted(args.rules_dir.glob("*.yml")) + sorted(args.rules_dir.glob("*.yaml")):
        try:
            with path.open() as f:
                existing = _yaml.load(f)
        except Exception:
            continue
        if not isinstance(existing, dict):
            continue
        existing_by_path[path] = existing
        eid = existing.get("id")
        if isinstance(eid, str) and eid:
            existing_by_id[eid] = path
        ename = existing.get("name")
        if isinstance(ename, str) and ename and ename not in existing_by_name:
            existing_by_name[ename] = path

    written = 0
    skipped = 0
    written_paths: set[Path] = set()
    for rid, r in remote.items():
        # Figure out which existing file (if any) this remote rule maps to.
        # We use this both to pick the output path AND to preserve local-only
        # fields (log_source, owner, notes, lifecycle.*) when writing.
        existing_path: Path | None = None
        if rid in existing_by_id:
            existing_path = existing_by_id[rid]
        elif (r_name := r.get("name")) and r_name in existing_by_name:
            existing_path = existing_by_name[r_name]

        existing_rule = existing_by_path.get(existing_path) if existing_path else None
        rule = remote_to_rule(r, existing=existing_rule)
        name = rule.get("name")

        # Target selection priority:
        #   1. Existing file tracking this exact id — overwrite in place
        #   2. Existing file with matching name, provided we haven't already
        #      written to that file in this run — overwrite in place
        #   3. Slug-based filename, with disambig suffix if the base path
        #      is already claimed in this run or exists on disk
        out_path: Path | None = None
        if rid in existing_by_id:
            out_path = existing_by_id[rid]
        elif name and name in existing_by_name:
            candidate = existing_by_name[name]
            # If another remote rule already claimed this file in this run
            # (two Falcon rules with the same name), fall through to the
            # disambig-suffix path to preserve both.
            if candidate not in written_paths:
                out_path = candidate

        if out_path is None:
            slug = slugify(name)
            out_path = args.rules_dir / f"{slug}.yml"
            if out_path in written_paths or (out_path.exists() and not args.overwrite):
                out_path = args.rules_dir / f"{slug}_{rid[:8]}.yml"

        if out_path.exists() and not args.overwrite and out_path not in written_paths:
            skipped += 1
            continue
        with out_path.open("w") as f:
            _yaml.dump(rule, f)
        written_paths.add(out_path)
        written += 1
        print(f"  wrote: {out_path.name}")

    print(f"\nImport complete: {written} rules written, {skipped} skipped (already exist).")
    print("Next steps (in sweep MRs):")
    print("  1. Optionally fill in log_source, runbook_url, owner on rules you own.")
    print("  2. Standardize the CQL per docs/rule-quality-standards.md")
    print("     (add ipLocation+asn, groupBy/collect, format(detection.description), TI confidenceThreshold='high').")
    print("  3. Fix zero-duration lookbacks (search for 'lookback: 0h' or '0h0m').")
    print("  4. Flip lifecycle.standardization_pending to false when the rule meets the CQL format standard.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
