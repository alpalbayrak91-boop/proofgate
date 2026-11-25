"""Generate metadata from a local wheel collection; never install or import a wheel."""
import argparse
import json
from pathlib import Path
from collections import Counter
from zipfile import BadZipFile
from wheelcap import scan, receipt


def compact(path):
    report = scan(path)
    return {"filename": path.name, "name": report["name"], "version": report.get("version"),
            "sha256": report["sha256"], "python_files_parsed": report["python_files_parsed"],
            "evidence": dict(sorted(Counter(f["rule"] for f in report["findings"]).items())),
            "warnings": report["warnings"], "receipt_root": receipt(report)["root"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    files = sorted(args.directory.glob("*.whl"))
    if not files:
        parser.error("no .whl files in the specified directory")
    for path in files:
        try:
            record = compact(path)
        except (OSError, ValueError, RuntimeError, BadZipFile) as exc:
            record = {"filename": path.name, "error": str(exc)}
        print(json.dumps(record, sort_keys=True))
