from __future__ import annotations

import argparse
import json
import sys

from . import findings, model


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="oci-blast-radius",
                                 description="Offline OCI network blast-radius review (synthetic/exported data).")
    ap.add_argument("input", help="simplified network model JSON")
    ap.add_argument("--output", help="write JSON report here")
    ap.add_argument("--fail-on-high", action="store_true", help="exit 2 if any high finding")
    a = ap.parse_args(argv)
    try:
        m = model.load_file(a.input)
    except (OSError, json.JSONDecodeError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    fs = findings.analyze(m)
    report = {"summary": findings.summary(m), "findings": [f.to_dict() for f in fs],
              "disclaimer": "Rule-level review priorities from a simplified model; not confirmed exploitability."}
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.subject}: {f.message}")
    print(f"{len(fs)} finding(s); {report['summary']['edges']} permitted instance pairs.")
    return 2 if a.fail_on_high and any(f.severity == "high" for f in fs) else 0


if __name__ == "__main__":
    sys.exit(main())
