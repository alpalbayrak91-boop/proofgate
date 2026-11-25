"""WheelCap: offline static evidence for Python release artifacts. Python 3.10+."""
import argparse
import ast
import hashlib
import json
import os
import sys
import tokenize
import zipfile
from collections import Counter
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from urllib.parse import quote

MAX_MEMBER = 8 * 1024**2
MAX_TOTAL = 300 * 1024**2
MAX_FILES = 40_000
RULES = {
    "net": "Network API reference", "exec": "Process API reference",
    "fs": "Filesystem API reference", "dynamic_eval": "Dynamic code evaluation",
    "dunder_escape": "Selected introspection attribute", "native_ext": "Opaque native binary",
    "install_hook": "Executable .pth startup line",
}
MODULES = {"socket": "net", "urllib": "net", "http": "net", "requests": "net",
           "httpx": "net", "subprocess": "exec", "pathlib": "fs", "shutil": "fs"}
CALLS = {"open": "fs", "builtins.open": "fs", "io.open": "fs", "os.open": "fs",
         "os.remove": "fs", "os.unlink": "fs", "os.system": "exec", "os.popen": "exec",
         "eval": "dynamic_eval", "exec": "dynamic_eval", "compile": "dynamic_eval",
         "builtins.eval": "dynamic_eval", "builtins.exec": "dynamic_eval",
         "builtins.compile": "dynamic_eval"}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def dotted(node, aliases):
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return dotted(node.value, aliases) + "." + node.attr
    return ""


def analyze_python(data, note):
    tree = ast.parse(data)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for part in node.names:
                root = part.name.split(".")[0]
                aliases[part.asname or root] = part.name if part.asname else root
                if root in MODULES:
                    note(MODULES[root], node.lineno, "import", part.name)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            root = node.module.split(".")[0]
            for part in node.names:
                target = node.module + "." + part.name
                aliases[part.asname or part.name] = target
                category = CALLS.get(target) or MODULES.get(root)
                if category:
                    note(category, node.lineno, "import", target)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = dotted(node.func, aliases)
            category = CALLS.get(target) or MODULES.get(target.split(".")[0])
            if category:
                note(category, node.lineno, "call", target)
        if isinstance(node, ast.Attribute) and node.attr in {"__subclasses__", "__globals__", "__mro__"}:
            note("dunder_escape", node.lineno, "attribute", node.attr)


def relevant(name):
    return name.endswith((".py", ".pth", ".so", ".pyd", ".dll", ".dylib", ".dist-info/METADATA")) or ".so." in PurePosixPath(name).name


def members(path):
    if path.is_dir():
        total = 0
        count = 0
        for root, dirs, files in os.walk(path, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in {".git", ".venv", "__pycache__"} and not (Path(root)/d).is_symlink())
            for filename in sorted(files):
                f = Path(root)/filename
                name = f.relative_to(path).as_posix()
                if f.is_symlink() or not relevant(name) or not f.is_file():
                    continue
                size = f.stat().st_size
                total += size
                count += 1
                if total > MAX_TOTAL or count > MAX_FILES:
                    raise ValueError("source input exceeds scan limit")
                yield name, None if size > MAX_MEMBER else f.read_bytes()
        return
    with zipfile.ZipFile(path) as archive:
        files = archive.infolist()
        if len(files) > MAX_FILES or sum(f.file_size for f in files) > MAX_TOTAL:
            raise ValueError("archive exceeds scan limit")
        seen = set()
        for f in files:
            name = f.filename
            if name in seen or name.startswith("/") or ".." in name.split("/") or "\\" in name:
                raise ValueError("ambiguous archive path")
            seen.add(name)
            if not f.is_dir() and relevant(name):
                yield name, None if f.file_size > MAX_MEMBER else archive.read(f)


def scan(path):
    output = {"format": "wheelcap-0.1", "kind": "source" if path.is_dir() else "wheel",
              "name": path.name, "findings": [], "warnings": [], "python_files_parsed": 0}
    if path.is_file():
        output["sha256"] = file_digest(path)
    def warn(name, reason):
        output["warnings"].append({"path": name, "reason": reason})
    for name, data in members(path):
        def note(rule, line, kind, symbol):
            output["findings"].append({"rule": rule, "path": name, "line": line, "kind": kind, "symbol": symbol})
        if name.endswith((".so", ".pyd", ".dll", ".dylib")) or ".so." in PurePosixPath(name).name:
            note("native_ext", 1, "file", "native")
            warn(name, "native implementation not analyzed")
        elif data is None:
            warn(name, "file exceeds scan limit")
        elif name.endswith(".dist-info/METADATA"):
            meta = BytesParser().parsebytes(data, headersonly=True)
            if meta.get("Name") and meta.get("Version"):
                output.update(name=str(meta["Name"]), version=str(meta["Version"]))
        elif name.endswith(".pth"):
            for i, line in enumerate(data.splitlines(), 1):
                if line.startswith((b"import ", b"import\t")):
                    note("install_hook", i, "startup", ".pth")
        else:
            try:
                analyze_python(data, note)
                output["python_files_parsed"] += 1
            except (SyntaxError, ValueError, UnicodeError, RecursionError, tokenize.TokenError) as exc:
                warn(name, type(exc).__name__)
    for key in ("findings", "warnings"):
        output[key].sort(key=canonical)
    return output


def diff(before, after):
    def counts(report):
        return Counter((f["rule"], f["path"], f["kind"], f["symbol"]) for f in report["findings"])
    def rows(counts):
        return [dict(rule=r, path=p, kind=k, symbol=s, count=n) for (r,p,k,s),n in sorted(counts.items())]
    left, right = counts(before), counts(after)
    return {"added": rows(right-left), "removed": rows(left-right),
            "before_warnings": before["warnings"], "after_warnings": after["warnings"]}


def merkle(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    nodes = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(nodes) > 1:
        pairs = [hashlib.sha256(b"\x01" + nodes[i] + nodes[i+1]).digest()
                 for i in range(0, len(nodes)-1, 2)]
        nodes = pairs + (nodes[-1:] if len(nodes)%2 else [])
    return nodes[0]


def receipt(report):
    header = {k: v for k, v in report.items() if k != "findings"}
    leaves = [canonical(header)] + [canonical(f) for f in report["findings"]]
    return {"format": "wheelcap-receipt-1", "algorithm": "RFC6962-SHA256",
            "report_sha256": digest(canonical(report)), "leaves": len(leaves),
            "root": merkle(leaves).hex()}


def sbom(report):
    component = {"type": "library", "name": report["name"]}
    if "version" in report:
        component["version"] = report["version"]
    if "sha256" in report:
        component["hashes"] = [{"alg": "SHA-256", "content": report["sha256"]}]
    counts = Counter(f["rule"] for f in report["findings"])
    component["properties"] = [{"name": "wheelcap:evidence-count:"+name, "value": str(n)}
                               for name,n in sorted(counts.items())]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": component}}


def sarif(report):
    tool = {"driver": {"name": "WheelCap", "rules": [{"id": k, "shortDescription": {"text": v}}
                                                      for k,v in RULES.items()]}}
    results = [{"ruleId": f["rule"], "level": "note",
                "message": {"text": f["kind"] + ": " + f["symbol"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(f["path"])},
                              "region": {"startLine": f["line"]}}}]} for f in report["findings"]]
    return {"version": "2.1.0", "runs": [{"tool": tool, "results": results}]}


def write_json(path, data):
    path.write_bytes(canonical(data)+b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan"); p.add_argument("input", type=Path); p.add_argument("output", type=Path)
    p = sub.add_parser("diff"); p.add_argument("before", type=Path); p.add_argument("after", type=Path)
    p = sub.add_parser("verify"); p.add_argument("report", type=Path); p.add_argument("receipt", type=Path)
    args = parser.parse_args()
    if args.command == "verify":
        return 0 if receipt(json.loads(args.report.read_bytes())) == json.loads(args.receipt.read_bytes()) else 1
    if args.command == "diff":
        print(json.dumps(diff(scan(args.before), scan(args.after)), indent=2))
        return 0
    report = scan(args.input)
    args.output.mkdir(parents=True, exist_ok=True)
    for name, data in [("report.json", report), ("receipt.json", receipt(report)),
                       ("wheelcap.cdx.json", sbom(report)), ("wheelcap.sarif", sarif(report))]:
        write_json(args.output/name, data)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as err:
        sys.exit(str(err))
