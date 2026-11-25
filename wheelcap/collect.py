"""Optional networked acquisition. Run separately from the offline analyzer."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote, urlsplit
from urllib.request import urlopen
from wheelcap import write_json
from dataset import compact

LIMIT = 100 * 1024**2


def choose(files):
    candidates = [x for x in files if x.get("packagetype") == "bdist_wheel"
                  and not x.get("yanked") and 0 < x.get("size", 0) <= LIMIT]
    return min(candidates, key=lambda x: (not x["filename"].endswith("-none-any.whl"),
                                          x["filename"]), default=None)


def download(project, temp):
    with urlopen("https://pypi.org/pypi/"+quote(project,safe="")+"/json", timeout=30) as resp:
        body = resp.read(16 * 1024**2 + 1)
    if len(body) > 16 * 1024**2:
        raise ValueError("metadata size limit")
    meta = json.loads(body)
    selected = choose(meta["urls"])
    if not selected:
        return {"project":project, "version":meta["info"]["version"], "status":"no eligible wheel"}
    url = selected["url"]
    filename = selected["filename"]
    if urlsplit(url).scheme != "https" or urlsplit(url).hostname != "files.pythonhosted.org":
        raise ValueError("unexpected wheel host")
    if Path(filename).name != filename or not filename.endswith(".whl") or "\\" in filename:
        raise ValueError("unexpected filename")
    path = temp/filename
    h = hashlib.sha256()
    size = 0
    with urlopen(url, timeout=45) as src, path.open("xb") as dst:
        for chunk in iter(lambda: src.read(1024**2), b""):
            size += len(chunk)
            if size > min(selected["size"], LIMIT):
                raise ValueError("download size limit")
            h.update(chunk)
            dst.write(chunk)
    if size != selected["size"] or h.hexdigest() != selected["digests"]["sha256"]:
        raise ValueError("artifact mismatch")
    return {"project":project, "status":"scanned", "wheel_url":url, **compact(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--limit", type=int, default=5, help="number of ranked projects (1..1000)")
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000:
        parser.error("limit must be 1..1000")
    ranking = json.loads(Path(__file__).with_name("top1000.json").read_text())
    out = args.output/ranking["snapshot"][:10]
    out.mkdir(parents=True, exist_ok=True)
    for rank, project in enumerate(ranking["projects"][:args.limit], 1):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+",project):
            raise ValueError("invalid project name")
        target = out/(project+".json")
        if target.exists() and json.loads(target.read_bytes()).get("status") == "scanned":
            continue
        with TemporaryDirectory(dir=out) as tmp:
            temp = Path(tmp)
            try:
                record = download(project, temp)
            except Exception as exc:
                record = {"project":project, "status":"error", "reason":str(exc)}
            record.update(rank=rank, ranking_snapshot=ranking["snapshot"])
            write_json(temp/"result.json",record)
            os.replace(temp/"result.json",target)


if __name__ == "__main__":
    main()
