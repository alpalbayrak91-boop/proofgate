# WheelCap 0.1

Independent, AI-generated AlpLab prototype. Runtime uses only the Python 3.10+ standard library. License for code: MIT. No model service is called. The optional collector uses the network. No distributions are installed, imported or rebuilt during analysis.

## Offline use

    python wheelcap.py scan release.whl results
    python wheelcap.py diff old.whl new.whl
    python wheelcap.py diff checked-out-src new.whl
    python wheelcap.py verify results/report.json results/receipt.json
    python dataset.py local-wheel-directory > runs.jsonl
    python -m unittest discover -v

Use the import root of a trusted local checkout (often its src directory) for source comparisons. Match the release tag and build target yourself. File paths are relative to that root. Generated files, moves, packaging layouts and native platform differences can all create legitimate differences. The comparison counts evidence per rule, relative path, evidence kind and symbol. Line movement alone does not count as a new finding. Compare full scan reports for exact locations.

Scan writes report.json, wheelcap.sarif, wheelcap.cdx.json and receipt.json. The CycloneDX document describes the subject and WheelCap observations. It does not inventory every dependency. A packager may include the document under its own .dist-info/sboms/ at build time per PEP 770. WheelCap keeps the input wheel intact. Produce a report about the final artifact externally if it must bind that artifact's hash. Embedding a document changes the wheel digest.

## Interpretation

An import, a call, a selected introspection attribute and an opaque binary are different kinds of evidence. The seven categories are heuristic. The install_hook label in 0.1 covers executable .pth startup lines only. It does not mean these lines ran during installation. The dunder_escape label means one of three attributes occurred; an escape was not demonstrated. Imports are resolved at file scope; lexical shadowing, reachability, runtime dispatch, indirect calls and native implementation behavior are not resolved. No matches carries no safety guarantee. Per-file warnings, number of files parsed and evidence kinds accompany the results. Existing directory output files with the same names are overwritten when scanning again.

The receipt uses SHA-256 with RFC 6962 leaf and internal-node prefixes and a WheelCap-specific canonical JSON encoding. Leaf zero binds report metadata and warnings; later leaves bind findings in order. Verification recomputes the whole report. Keep a trusted copy of the expected receipt separately. No external signature, timestamp, append-only service or inclusion-proof protocol is provided.

## Dataset

examples/observed-wheels.jsonl is actual metadata for five locally available release files. It is a convenience sample; it is not the top 1000. examples/latexrestricted/ contains a full sample and its receipt. No third-party wheel is redistributed.

top1000.json contains project names drawn from the 30-day download ranking published by hugovk/top-pypi-packages, dated 2026-11-01. Ranking provenance is recorded in that file. For optional online collection, run:

    python collect.py collection --limit 5

Use --limit 1000 to attempt the full list. The collector selects one non-yanked, size-limited wheel for the latest release available at retrieval, preferring a universal wheel, then lexical filename order. It records exact artifact URL and hash, verifies the download before scanning, and records skipped or failed projects. Repeating a collection resumes completed entries. It does not cover every platform and version. Before publishing, inspect error counts, check redistributable data terms, fix a release snapshot and publish collection time and coverage. The ranking snapshot date is not the wheel retrieval date. No full remote harvesting run or result publication was performed for this release.

## Verification

Eight unit tests cover nonexecution, package aliases, line shifts, directory versus wheel, startup/native/parse warnings, metadata locations, receipt modification, archive path checks and an odd-length Merkle tree. The supplied sample SARIF and CycloneDX objects were validated against OASIS SARIF 2.1.0 and CycloneDX 1.6 JSON schemas in the development environment. The optional collector was exercised with controlled local responses, not live PyPI. Reproducibility checks do not measure false alarms or missed behaviors.
