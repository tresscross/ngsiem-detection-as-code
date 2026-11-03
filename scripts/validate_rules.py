#!/usr/bin/env python3
"""Validate every rule YAML under rules/ against the detection-as-code schema and format standards.

Runs eight categories of checks (see docs/rule-quality-standards.md). Checks 2-4 are skipped when
`lifecycle.standardization_pending` is true — this lets bootstrap-imported
rules pass the baseline commit while still being caught by all structural checks.

Exit codes:
    0  all rules valid
    1  CLI usage error
    3  one or more rules failed validation

Usage:
    python scripts/validate_rules.py                 # human-readable output
    python scripts/validate_rules.py --json          # machine-readable
    python scripts/validate_rules.py --rules-dir X   # override rules directory
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = REPO_ROOT / "rules"
SCHEMA_DIR = REPO_ROOT / "schema"
RULE_SCHEMA_PATH = SCHEMA_DIR / "rule.schema.json"
LOG_SOURCES_PATH = SCHEMA_DIR / "log_sources.json"
MITRE_PATH = SCHEMA_DIR / "mitre_enterprise.json"

# Optional: require runbook_url to live under your wiki, e.g. "https://example.atlassian.net/wiki/".
# Unset (the default) accepts any https:// URL.
RUNBOOK_URL_PREFIX = os.environ.get("DAC_RUNBOOK_URL_PREFIX") or "https://"
CQL_FORMAT_DOC = "docs/rule-quality-standards.md"

FORMAT_SKIPPABLE_CHECKS = {"cql_format", "ti_confidence", "cql_sanity"}


@dataclass
class Violation:
    rule_file: str
    check: str
    message: str
    hint: str | None = None


@dataclass
class ValidationReport:
    rules_checked: int = 0
    rules_skipped_format: int = 0
    violations: list[Violation] = field(default_factory=list)

    def add(self, v: Violation) -> None:
        self.violations.append(v)

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules_checked": self.rules_checked,
            "rules_skipped_format": self.rules_skipped_format,
            "passed": self.passed,
            "violations": [asdict(v) for v in self.violations],
        }


def _load_json(path: Path) -> dict:
    with path.open() as f:
        return json.load(f)


def _load_yaml(path: Path) -> dict | None:
    try:
        with path.open() as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        return {"__yaml_error__": str(e)}


def _check_schema(rule_path: Path, rule: dict, validator: Draft202012Validator,
                  report: ValidationReport) -> bool:
    errors = sorted(validator.iter_errors(rule), key=lambda e: e.path)
    if not errors:
        return True
    for err in errors:
        loc = ".".join(str(p) for p in err.absolute_path) or "<root>"
        report.add(Violation(
            rule_file=str(rule_path),
            check="schema",
            message=f"{loc}: {err.message}",
        ))
    return False


def _is_edr_telemetry(cql: str) -> bool:
    """CrowdStrike endpoint sensor telemetry (ProcessRollup2 and friends) carries no
    network source IP to geolocate, so the ipLocation()/asn() format requirement does
    not apply. Identify it by the sensor-event markers."""
    markers = (
        "#event_simpleName",
        "#repo=base_sensor",
        "#repo = base_sensor",
        "ProcessRollup2",
        "SyntheticProcessRollup2",
    )
    return any(m in cql for m in markers)


def _check_cql_format(rule_path: Path, rule: dict, report: ValidationReport) -> None:
    cql = rule.get("search", {}).get("filter", "")
    edr = _is_edr_telemetry(cql)
    missing = []
    # ipLocation/asn only make sense for IP-bearing sources; exempt EDR sensor telemetry.
    if not edr:
        if "ipLocation(" not in cql:
            missing.append("ipLocation(<ip>)")
        if "asn(" not in cql:
            missing.append("asn(<ip>)")
    if "groupBy(" not in cql:
        missing.append("groupBy([key], ...)")
    if "collect(" not in cql:
        missing.append("collect([...])")
    if missing:
        report.add(Violation(
            rule_file=str(rule_path),
            check="cql_format",
            message=f"search.filter missing required format elements: {', '.join(missing)}",
            hint=f"See {CQL_FORMAT_DOC} for the full template.",
        ))


def _check_ti_confidence(rule_path: Path, rule: dict, report: ValidationReport) -> None:
    cql = rule.get("search", {}).get("filter", "")
    uses_ti = ("ioc:lookup(" in cql) or ("threatFeed" in cql)
    if uses_ti and 'confidenceThreshold="high"' not in cql and "confidenceThreshold='high'" not in cql:
        report.add(Violation(
            rule_file=str(rule_path),
            check="ti_confidence",
            message='TI lookup present but confidenceThreshold="high" not found',
            hint="All threat-intel lookups must use confidenceThreshold=\"high\" to avoid low-confidence noise.",
        ))


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_duration_seconds(s: str) -> int | None:
    """Parse Go-style multi-unit duration ('1h', '2h30m', '0h5m', '90s') to seconds.
    Returns None if not parseable."""
    if not isinstance(s, str) or not s:
        return None
    total = 0
    last_end = 0
    for m in re.finditer(r"([0-9]+)([smhd])", s):
        if m.start() != last_end:
            return None
        total += int(m.group(1)) * _DURATION_UNITS[m.group(2)]
        last_end = m.end()
    if last_end != len(s):
        return None
    return total


def _check_lookback_nonzero(rule_path: Path, rule: dict, report: ValidationReport) -> None:
    lb = rule.get("search", {}).get("lookback", "")
    if not isinstance(lb, str) or not lb:
        report.add(Violation(
            rule_file=str(rule_path),
            check="lookback_missing",
            message="search.lookback is empty — rule will never match any data",
        ))
        return
    seconds = _parse_duration_seconds(lb)
    if seconds is None:
        return  # unparseable — schema regex already handles shape
    if seconds == 0:
        report.add(Violation(
            rule_file=str(rule_path),
            check="lookback_zero",
            message=f"search.lookback='{lb}' means the rule queries a zero-duration window. "
                    "This is either a Falcon-side misconfiguration or a template default that "
                    "was never set. Standardize before flipping standardization_pending to false.",
        ))


def _check_cql_sanity(rule_path: Path, rule: dict, report: ValidationReport) -> None:
    cql = rule.get("search", {}).get("filter", "")
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    in_string: str | None = None
    prev = ""
    for ch in cql:
        if in_string:
            if ch == in_string and prev != "\\":
                in_string = None
        elif ch in ('"', "'"):
            in_string = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif ch in pairs.values():
            if not stack or stack.pop() != ch:
                report.add(Violation(
                    rule_file=str(rule_path),
                    check="cql_sanity",
                    message=f"Unbalanced '{ch}' in CQL filter",
                ))
                return
        prev = ch
    if stack:
        report.add(Violation(
            rule_file=str(rule_path),
            check="cql_sanity",
            message=f"Unclosed brackets in CQL filter: expected {stack}",
        ))
        return
    if cql.rstrip().endswith("\\"):
        report.add(Violation(
            rule_file=str(rule_path),
            check="cql_sanity",
            message="CQL filter ends with a trailing backslash",
        ))
    pipe_line_starts = sum(1 for line in cql.splitlines() if line.lstrip().startswith("|"))
    if pipe_line_starts < 2:
        report.add(Violation(
            rule_file=str(rule_path),
            check="cql_sanity",
            message=f"Expected at least 2 line-starting pipes in CQL; found {pipe_line_starts}. "
                    "A correlation rule should chain multiple stages.",
        ))


def _check_log_source(rule_path: Path, rule: dict, log_sources: dict,
                     report: ValidationReport) -> None:
    ls = rule.get("log_source")
    if ls and ls not in log_sources.get("sources", {}):
        valid = sorted(log_sources.get("sources", {}).keys())
        report.add(Violation(
            rule_file=str(rule_path),
            check="log_source",
            message=f"log_source '{ls}' not in schema/log_sources.json",
            hint=f"Valid sources: {', '.join(valid)}",
        ))


# CrowdStrike-assigned custom MITRE codes. Falcon emits these for behaviors that
# have no public ATT&CK mapping (CST#### techniques, CSTA#### tactics) and the
# importer preserves them verbatim. The rule schema already sanctions CST####
# techniques, so the ATT&CK-cache membership check must accept the custom
# taxonomy too — otherwise these rules can never clear standardization_pending
# without rewriting Falcon's own mapping. See _check_mitre.
_CST_TECHNIQUE_RE = re.compile(r"^CST[0-9]{4}$")
_CST_TACTIC_RE = re.compile(r"^CSTA[0-9]{4}$")


def _check_mitre(rule_path: Path, rule: dict, mitre: dict, report: ValidationReport) -> None:
    tactic = rule.get("tactic")
    technique = rule.get("technique")
    if tactic and tactic not in mitre.get("tactics", []) and not _CST_TACTIC_RE.match(str(tactic)):
        report.add(Violation(
            rule_file=str(rule_path),
            check="mitre_tactic",
            message=f"tactic '{tactic}' not in schema/mitre_enterprise.json "
                    "(and not a CrowdStrike custom CSTA#### tactic)",
            hint="Run `make refresh-mitre` to refresh the ATT&CK cache.",
        ))
    if technique and technique not in mitre.get("techniques", []) and not _CST_TECHNIQUE_RE.match(str(technique)):
        report.add(Violation(
            rule_file=str(rule_path),
            check="mitre_technique",
            message=f"technique '{technique}' not in schema/mitre_enterprise.json "
                    "(and not a CrowdStrike custom CST#### technique)",
            hint="Run `make refresh-mitre` to refresh the ATT&CK cache.",
        ))


def _check_runbook_url(rule_path: Path, rule: dict, report: ValidationReport) -> None:
    url = rule.get("runbook_url", "")
    if url and not url.startswith(RUNBOOK_URL_PREFIX):
        report.add(Violation(
            rule_file=str(rule_path),
            check="runbook_url",
            message=f"runbook_url must start with {RUNBOOK_URL_PREFIX}",
        ))


def _check_uniqueness(rules_by_file: dict[Path, dict], report: ValidationReport) -> None:
    names: dict[str, list[Path]] = defaultdict(list)
    ids: dict[str, list[Path]] = defaultdict(list)
    pending_by_path: dict[Path, bool] = {}
    for path, rule in rules_by_file.items():
        pending_by_path[path] = bool(rule.get("lifecycle", {}).get("standardization_pending"))
        if isinstance(rule.get("name"), str):
            names[rule["name"]].append(path)
        rid = rule.get("id")
        if isinstance(rid, str) and rid:
            ids[rid].append(path)
    for name, paths in names.items():
        if len(paths) <= 1:
            continue
        # Skip the name-uniqueness failure if every member of the collision
        # is standardization_pending (bootstrap duplicates). Once any one of
        # them is standardized, the check re-engages and forces a resolution.
        if all(pending_by_path.get(p, False) for p in paths):
            continue
        for p in paths:
            report.add(Violation(
                rule_file=str(p),
                check="uniqueness_name",
                message=f"Duplicate rule name '{name}' across {len(paths)} files: "
                        f"{', '.join(str(x) for x in paths)}",
            ))
    # ID uniqueness is always a hard fail — two files with the same id would
    # fight each other in the apply loop. Cannot be deferred.
    for rid, paths in ids.items():
        if len(paths) > 1:
            for p in paths:
                report.add(Violation(
                    rule_file=str(p),
                    check="uniqueness_id",
                    message=f"Duplicate rule id '{rid}' across {len(paths)} files: "
                            f"{', '.join(str(x) for x in paths)}",
                ))


def validate(rules_dir: Path) -> ValidationReport:
    report = ValidationReport()
    schema = _load_json(RULE_SCHEMA_PATH)
    validator = Draft202012Validator(schema)
    log_sources = _load_json(LOG_SOURCES_PATH)
    mitre = _load_json(MITRE_PATH)

    rules_by_file: dict[Path, dict] = {}
    rule_files = sorted(rules_dir.glob("*.yml")) + sorted(rules_dir.glob("*.yaml"))

    for rule_path in rule_files:
        report.rules_checked += 1
        rule = _load_yaml(rule_path)
        if rule is None:
            report.add(Violation(rule_file=str(rule_path), check="yaml_parse",
                                 message="Empty YAML file"))
            continue
        if "__yaml_error__" in rule:
            report.add(Violation(rule_file=str(rule_path), check="yaml_parse",
                                 message=rule["__yaml_error__"]))
            continue

        schema_ok = _check_schema(rule_path, rule, validator, report)
        if not schema_ok:
            continue

        rules_by_file[rule_path] = rule

        pending = rule.get("lifecycle", {}).get("standardization_pending", False)

        if not pending:
            _check_cql_format(rule_path, rule, report)
            _check_ti_confidence(rule_path, rule, report)
            _check_cql_sanity(rule_path, rule, report)
            _check_mitre(rule_path, rule, mitre, report)
            _check_lookback_nonzero(rule_path, rule, report)
        else:
            report.rules_skipped_format += 1

        _check_log_source(rule_path, rule, log_sources, report)
        _check_runbook_url(rule_path, rule, report)

    _check_uniqueness(rules_by_file, report)
    return report


def _print_human(report: ValidationReport) -> None:
    if report.passed:
        print(f"OK - {report.rules_checked} rules validated "
              f"({report.rules_skipped_format} skipped format checks via standardization_pending).")
        return
    print(f"FAIL - {len(report.violations)} violations across {report.rules_checked} rules.\n")
    by_file: dict[str, list[Violation]] = defaultdict(list)
    for v in report.violations:
        by_file[v.rule_file].append(v)
    for rule_file, vs in sorted(by_file.items()):
        print(f"  {rule_file}")
        for v in vs:
            print(f"    [{v.check}] {v.message}")
            if v.hint:
                print(f"      hint: {v.hint}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON output")
    args = parser.parse_args(argv)

    if not args.rules_dir.is_dir():
        print(f"error: rules directory not found: {args.rules_dir}", file=sys.stderr)
        return 1

    report = validate(args.rules_dir)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_human(report)

    return 0 if report.passed else 3


if __name__ == "__main__":
    sys.exit(main())
