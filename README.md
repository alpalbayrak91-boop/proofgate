# ProofGate

Zero-dependency MIT toolkit for deterministic verification across formal Lean 4 specifications, restricted Python verification scripts, and tamper-evident cryptographic receipts.

## Components

1. **Lean 4 Specification-Faithfulness Gate (`proofgate.lean_gate`)**
   - Comment- and string-aware lexer that catches hidden proof loopholes:
     - `sorry`, `admit`, `s!"...sorry..."` interpolation evasion
     - Kernel/type-checker bypasses (`debug.skipKernelTC`, `Meta.mkSorry`, `addDecl` axiom smuggling)
     - Non-standard `#print axioms` checks (`Lean.ofReduceBool`, `Lean.trustCompiler`, custom `axiom` declarations)
     - Free-variable `decide` misuse and trivial constant-tactic padding (`>50%` binderless `decide`/`omega`/`rfl`/`trivial`)
2. **Python AST Safety Gate (`proofgate.ast_gate`)**
   - Static AST inspection rejecting dangerous imports (`os`, `subprocess`, `socket`, `ctypes`, `importlib`, etc.), dynamic evaluation (`eval`, `exec`, `compile`, `__import__`, `open`), dunder attribute escapes (`__class__`, `__subclasses__`), unbounded `while True` loops without `break`, and trivial constant-return stub functions.
3. **Muhur Cryptographic Receipt & RFC 6962 Merkle Verifier (`proofgate.muhur_rfc6962`)**
   - Deterministic RFC 8785 JSON Canonicalization (JCS subset for sorted keys and compact UTF-8 framing).
   - RFC 6962 domain-separated SHA-256 Merkle tree builder (`0x00` leaf prefix, `0x01` internal node prefix), audit inclusion path generator, and stateless verifier.

## Quickstart

```bash
python3 -m unittest discover -s tests -v
python3 -m proofgate.cli check-ast my_script.py
python3 -m proofgate.cli check-lean MyProof.lean
python3 -m proofgate.cli merkle-root record1.json record2.json
```

## Static Showcase & Security

- Zero external runtime dependencies (Python standard library only).
- Interactive client-side RFC 6962 receipt & AST check playground in `docs/index.html` (Strict-CSP3 compatible, zero external CDNs).
- License: MIT (Copyright 2026 Alp Albayrak).

## Technical Paper & Formal Verification (`v0.2.0`)

- **Empirical Technical Paper (`docs/PROOFGATE_PAPER.md`):** Documents the *Linear Compensation Paradox* across live multi-agent audit telemetry (`N=531` records, `N=1,546` continuous runs) and demonstrates how non-compensatory lexicographic gating lifts hard-defect catch rates to `100.00%` at `485k evaluations/sec`.
- **Lean 4 Formal Soundness Proof (`formal/ProofGateV3ReproBuildIsolationSoundness.lean`):** 22 machine-checked theorems (`0 sorry`, standard Lean 4 kernel axioms only) proving `.olean`/`.ilean` reproducible build factor isolation, trace-blindness elimination, and fail-closed verification soundness.
- **Citation & Archival:** Standard `CITATION.cff` and `.zenodo.json` metadata included for reproducible scholarly citation.
