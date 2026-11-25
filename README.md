# ProofGate v1.0.0 ("Omni-Gate")

Zero-dependency MIT verification suite uniting formal Lean 4 specification/diff gates, static Python AST verification, SARIF v2.1.0 IDE/Code-Scanning export, strict RFC 8785 JCS + RFC 6962 inclusion/consistency Merkle logs, in-toto SLSA Provenance v1.0 DSSEv1 envelopes, and non-compensatory multi-agent trajectory evaluation.

## Architecture & Modules (`proofgate` v1.0.0)

1. **Lean 4 Specification-Faithfulness & Vacuity Gate (`proofgate.lean_gate`)**
   - Offset-preserving comment- and string-aware lexer (`lex_lean_source`, `strip_lean_comments_and_strings`) handling nested `/- ... -/` comments, raw strings `r#"..."#`, `s!"...{...}..."` interpolation evasion, guillemets `«...»`, and Trojan Source invisible BiDi Unicode.
   - Detects `sorry`, `admit`, `debug.skipKernelTC`, `debug.proofAsSorry`, `Meta.mkSorry`, `addDecl`/`axiomDecl` smuggling, `native_decide`/`bv_decide`, `Lean.ofReduceBool`/`Lean.trustCompiler`, `@[extern]`/`@[implemented_by]`, chained `axiom` declarations, missing `set_option autoImplicit false`, `#print axioms` coverage (`cov_bps`), and contradictory hypothesis vacuity (e.g., `(h1 : x < 0) (h2 : x > 5)`, `(x : Nat) (h : x < 0)`, `(h1 : P) (h2 : ¬ P)`).
2. **Lean 4 PR Specification Diff Gate (`proofgate.diff_gate`)**
   - Alpha-normalizes theorem binders (`(a b : Nat)` vs `(x y : Nat)` vs `: ∀ (u v : Nat), ...`), detects cross-namespace moves and alpha-equivalent renames without false failures, and fails closed on dropped public theorems (`REJECT_THEOREM_DROPPED`) or mutated specifications (`REJECT_THEOREM_STATEMENT_CHANGED`).
3. **Python AST Safety Gate (`proofgate.ast_gate`)**
   - Static `ast.parse` inspector with exact AST source locations rejecting restricted modules (`os`, `sys`, `subprocess`, `socket`, `ctypes`, `importlib`, `urllib`, etc.), dynamic evaluation (`eval`, `exec`, `compile`, `__import__`, `open`, `getattr`), dunder escapes (`__class__`, `__subclasses__`), bounded `range(...)` limit violations, unbounded constant-true loops, and trivial constant-return stub functions.
4. **SARIF v2.1.0 Exporter (`proofgate.sarif_export`)**
   - Emits GitHub Code Scanning / VS Code compatible SARIF v2.1.0 (`PG-LEAN-*`, `PG-AST-*`, `PG-DIFF-*`, `PG-EVAL-*`), computing exact BMP/SMP UTF-16 `char_utf16` offsets and deterministic SHA-256 `partialFingerprints`.
5. **RFC 8785 JCS + RFC 6962 Inclusion & Consistency Log (`proofgate.muhur_rfc6962`)**
   - Strict RFC 8785 JSON Canonicalization (`canonical_json_dumps` / `canonical_json_bytes`): UTF-16-BE object key sorting, ECMAScript float formatting (`-0.0 -> 0`), and `NaN`/`Infinity` rejection.
   - RFC 6962 domain-separated SHA-256 Merkle tree (`0x00` leaf, `0x01` node) supporting both inclusion audit proofs (`inclusion_proof` / `verify_inclusion_proof`) and append-only consistency proofs (`consistency_proof(m, n)` / `verify_consistency_proof`).
6. **in-toto SLSA Provenance v1.0 & DSSEv1 (`proofgate.slsa_provenance`)**
   - Builds strict in-toto Statement v1 + SLSA Provenance v1.0 payloads and signs/verifies DSSEv1 Pre-Authentication Encoding (`DSSEv1 <typeLen> <type> <bodyLen> <body>`) envelopes with constant-time HMAC-SHA256 verification.
7. **Non-Compensatory Multi-Agent Evaluator (`proofgate.agent_eval`)**
   - Replaces linear additive scoring (eliminating the *Linear Compensation Paradox*) with the lexicographic 4-gate (`-26000..10000 bps`) and 6-tier (`<= 10004` fail vs `>= 10005` pass) lattices, Wilson 95% lower confidence bound (`wilson_lcb_bps`), sequential `PageCusumDetector` drift quarantine, JUnit XML (`export_junit_xml`), and Promptfoo v3 JSON (`export_promptfoo_json`).

## CLI Quickstart (`proofgate.cli`)

All verification subcommands run offline with zero external runtime dependencies and support `--format json|sarif|junit` (with `--format promptfoo` also supported by `eval-agents`):

```bash
python3 -W error::DeprecationWarning -m unittest discover -s tests -v
python3 -m proofgate.cli check-lean formal/ProofGateV1OmniGateSoundness.lean --strict --format sarif
python3 -m proofgate.cli check-ast my_operator.py --format json
python3 -m proofgate.cli diff-lean base.lean head.lean --format sarif
python3 -m proofgate.cli merkle-root r1.json r2.json --proof-index 0 --consistency-old 1
python3 -m proofgate.cli slsa-attest artifact.tar.gz --merkle --ephemeral-key --verify
python3 -m proofgate.cli eval-agents runs.json --format promptfoo
```

## Formal Verification & Measured Checks (v1.0.0)

- **Unit, Adversarial & Property-Based Tests:** `38` tests (`tests/test_proofgate.py`, `tests/test_sarif_and_ast.py`, `tests/test_muhur_and_slsa.py`, `tests/test_lean_and_diff_gate.py`, `tests/test_agent_eval_and_cli.py`, `tests/test_docs_and_hygiene.py`) passing with `0` failures and `0` warnings under `python3 -W error::DeprecationWarning -m unittest discover -s tests -v`. Includes 2,000-trial lexicographic lattice PBT, 500-trial randomized Merkle inclusion/consistency PBT, and exhaustive `(0 <= m <= n <= 16)` consistency matrix checks.
- **Pure-Init Lean 4 Soundness Proof (`formal/ProofGateV1OmniGateSoundness.lean`):** `16` machine-checked public theorems (`0` incomplete proofs, `0` custom axioms, `set_option autoImplicit false`, `set_option warningAsError true`, `#print axioms` on all 16 theorems) verified via:
  - `lean -M 1024 -j 1 --trust=0 -DwarningAsError=true formal/ProofGateV1OmniGateSoundness.lean` (exit `0`)
  - `proofgate_v61_unified_meta_gate.py --file formal/ProofGateV1OmniGateSoundness.lean` (`all_passed=true`, `score=20000`, `cov_bps=10000`)
- **Legacy v0.2.0 Build Isolation Proof (`formal/ProofGateV3ReproBuildIsolationSoundness.lean`):** Preserved (`22` theorems).
- **Static Showcase (`docs/index.html`):** Hash-pinned Strict-CSP3 (`0` inline-bypass, `0` external CDNs/URLs, `0` `chr(36)`, `0` backticks) *ProofGate v1.0 Interactive Verification Studio* running client-side WebCrypto RFC 6962 / SLSA v1.0 DSSE / Lean 4 / AST / Eval checks.
- **Technical Paper & Archival:** `docs/PROOFGATE_PAPER.md`, `CITATION.cff`, and `.zenodo.json` (`0.00 USD` runtime cost, MIT License, Copyright 2026 Alp Albayrak).
