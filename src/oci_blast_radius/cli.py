from __future__ import annotations

import argparse
import json
import sys

from . import findings, model


def _convert(argv) -> int:
    ap = argparse.ArgumentParser(prog="oci-blast-radius convert",
                                 description="Convert a local OCI-style network export to the simplified model JSON (offline).")
    ap.add_argument("export", help="OCI-style export JSON (offline file)")
    ap.add_argument("--output", help="write simplified model JSON here (default stdout)")
    a = ap.parse_args(argv)
    from . import adapter
    try:
        model_dict = adapter.convert_file(a.export)
        m = model.load(model_dict)  # validation pass: references must resolve
    except (OSError, json.JSONDecodeError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    text = json.dumps(model_dict, indent=2)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print(f"converted {len(m.instances)} instance(s), {len(m.subnets)} subnet(s) -> {a.output}")
    else:
        print(text)
    return 0


def main(argv=None) -> int:
    import sys as _sys
    args = list(_sys.argv[1:] if argv is None else argv)
    if args and args[0] == "convert":
        return _convert(args[1:])
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
