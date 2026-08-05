#!/usr/bin/env python3
"""Validate a real evidence container against the published JSON Schemas.

The schemas are a contract with the Arachnid Recover module and with any
downstream consumer. Drift between what the tool emits and what the schema
promises is a breaking change that must not merge silently, so CI produces a
real container and checks it rather than validating a hand-written fixture.

Usage: validate-schemas.py <container-dir>
"""

import json
import sys
from pathlib import Path

import jsonschema

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"


def main(container: Path) -> int:
    report_schema = json.loads((SCHEMA_DIR / "report.schema.json").read_text())
    custody_schema = json.loads((SCHEMA_DIR / "custody.schema.json").read_text())

    jsonschema.Draft202012Validator.check_schema(report_schema)
    jsonschema.Draft202012Validator.check_schema(custody_schema)
    print("schemas are valid draft 2020-12")

    report = json.loads((container / "artifacts" / "report.json").read_text())
    jsonschema.Draft202012Validator(report_schema).validate(report)
    counts = {k: len(v) for k, v in report.get("collection", {}).items()}
    print(f"report.json validates: {counts}")

    validator = jsonschema.Draft202012Validator(custody_schema)
    n = 0
    for lineno, line in enumerate((container / "custody.log").read_text().splitlines(), 1):
        sig, _, body = line.partition(" ")
        if len(sig) != 128:
            print(f"custody.log:{lineno}: signature is not 128 hex chars", file=sys.stderr)
            return 1
        validator.validate(json.loads(body))
        n += 1
    print(f"all {n} custody records validate")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1])))
