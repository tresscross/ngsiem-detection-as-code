.PHONY: help install validate plan import import-overwrite refresh-mitre test clean

help:
	@echo "Targets:"
	@echo "  install            pip install this project in editable mode (use a venv)"
	@echo "  validate           run the rule validator against rules/"
	@echo "  plan               read-only diff against remote Falcon (requires FALCON_*_RO env)"
	@echo "  import             bootstrap rules/ from existing Falcon rules (one-time)"
	@echo "  import-overwrite   re-import and overwrite existing YAML files (use to backfill"
	@echo "                     Falcon-assigned IDs after an apply job creates new rules)"
	@echo "  refresh-mitre      refresh schema/mitre_enterprise.json from the MITRE ATT&CK STIX bundle"
	@echo "  test               run pytest"

install:
	pip install -e .[dev]

validate:
	python scripts/validate_rules.py

plan:
	python scripts/sync_detections.py --plan

import:
	python scripts/import_from_falcon.py

import-overwrite:
	python scripts/import_from_falcon.py --overwrite

refresh-mitre:
	python scripts/refresh_mitre.py

test:
	pytest -q

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache plan.txt
	find . -type d -name __pycache__ -prune -exec rm -rf {} \;
