#!/usr/bin/env python3
"""Aggregate coverage_category + MITRE technique data across all rule YAMLs.

Walks rules/ and emits a single JSON document tabulating:
  - total rules (all statuses) + active subset
  - per-category active rule counts + distinct technique IDs covered
  - rules missing coverage_category (should be 0; the schema requires it)

The output is published as a CI artifact so a dashboard or SOAR workflow can
fetch the latest snapshot from the main pipeline.

Exit codes:
    0  artifact written successfully
    1  CLI usage error
    2  rules directory missing or unreadable

Usage:
    python scripts/coverage_summary.py                    # stdout
    python scripts/coverage_summary.py --out FILE         # write to FILE
    python scripts/coverage_summary.py --rules-dir DIR    # override
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = REPO_ROOT / "rules"

CATEGORIES = ("endpoint", "cloud", "identity")


def monday_iso() -> str:
    """Monday 00:00 UTC of the current week — composite-key anchor for the snapshot row."""
    now = datetime.now(timezone.utc)
    monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    return monday.isoformat().replace("+00:00", "Z")


def techniques_of(rule: dict) -> list[str]:
    """Pull MITRE technique IDs from a rule, normalizing across the two shapes
    Falcon's correlation-rules API returns:
      - v1 / older: top-level `technique: T1059.001`
      - v2 / templates: `mitre_attack: [{tactic_id, technique_id}]`
    A single rule may carry either or both; collect everything.
    """
    out: list[str] = []
    ma = rule.get("mitre_attack")
    if isinstance(ma, list):
        for m in ma:
            if isinstance(m, dict):
                tid = m.get("technique_id")
                if tid:
                    out.append(tid)
    top = rule.get("technique")
    if top:
        out.append(top)
    return out


def build_summary(rules_dir: Path) -> dict:
    per_category_techniques: dict[str, set[str]] = {c: set() for c in CATEGORIES}
    rules_in_category: dict[str, int] = {c: 0 for c in CATEGORIES}
    rule_count_total = 0
    rule_count_active = 0
    missing_category: list[str] = []

    for yml in sorted(rules_dir.rglob("*.yml")):
        try:
            rule = yaml.safe_load(yml.read_text()) or {}
        except yaml.YAMLError as e:
            print(f"WARN: YAML parse failed for {yml.name}: {e}", file=sys.stderr)
            continue

        rule_count_total += 1
        is_active = (rule.get("status") or "active") == "active"
        if is_active:
            rule_count_active += 1

        cat = rule.get("coverage_category")
        if cat not in CATEGORIES:
            missing_category.append(rule.get("id") or yml.name)
            continue
        if not is_active:
            # Inactive rules count toward inventory totals but not toward coverage.
            continue

        rules_in_category[cat] += 1
        for t in techniques_of(rule):
            per_category_techniques[cat].add(t)

    return {
        "snapshot_date": monday_iso(),
        "source": "custom_correlation",
        "rule_count_total": rule_count_total,
        "rule_count_active": rule_count_active,
        "missing_category_count": len(missing_category),
        # Cap the list so a sudden drift event doesn't blow up the artifact.
        "missing_category_rule_ids": missing_category[:100],
        "categories": [
            {
                "category": c,
                "rules_in_category": rules_in_category[c],
                "techniques_covered": sorted(per_category_techniques[c]),
            }
            for c in CATEGORIES
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Tabulate coverage_category across rules/ and emit a snapshot JSON.")
    ap.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR, help="rules directory to walk")
    ap.add_argument("--out", type=Path, default=None, help="write JSON to this path (default: stdout)")
    ap.add_argument("--indent", type=int, default=2, help="JSON indent (default 2; pass 0 for compact)")
    args = ap.parse_args()

    if not args.rules_dir.is_dir():
        print(f"ERROR: rules directory not found: {args.rules_dir}", file=sys.stderr)
        return 2

    summary = build_summary(args.rules_dir)
    indent = args.indent if args.indent > 0 else None
    payload = json.dumps(summary, indent=indent, sort_keys=False)

    if args.out:
        args.out.write_text(payload + "\n")
        # Echo a compact human-readable summary to stderr so CI logs show
        # the snapshot at a glance without a second tool invocation. JSON
        # goes only to --out, so this doesn't pollute the artifact.
        print(f"coverage_summary written: {args.out}", file=sys.stderr)
        print(f"  snapshot_date:           {summary['snapshot_date']}", file=sys.stderr)
        print(f"  rule_count_total:        {summary['rule_count_total']}", file=sys.stderr)
        print(f"  rule_count_active:       {summary['rule_count_active']}", file=sys.stderr)
        print(f"  missing_category_count:  {summary['missing_category_count']}", file=sys.stderr)
        for c in summary["categories"]:
            print(
                f"  {c['category']:9s} active_rules={c['rules_in_category']:4d}  distinct_techniques={len(c['techniques_covered']):4d}",
                file=sys.stderr,
            )
    else:
        sys.stdout.write(payload + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
