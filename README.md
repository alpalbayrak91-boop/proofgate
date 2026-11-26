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

## What's New in v1.1.0 — Spec-Diff Reward-Hacking Gate (`audit_spec_vs_candidate_submission`)

- **Baseline-vs-Candidate Integrity Audit (`proofgate.spec_diff_reward_hack_gate`):** Parses Lean 4 declarations with nested-comment stripping (`strip_lean_comments`), blocks deleted specifications (`REJECT_DELETED_SPEC_DECL`), theorem/lemma binder or return-type mutations (`REJECT_THEOREM_SIGNATURE_MUTATION`), and target `def`/`abbrev` body stubbing (`REJECT_TARGET_IMPLEMENTATION_REWRITE`).
- **Concrete Local Typeclass Instance Blocker:** Prevents agents from shadowing core arithmetic or algebraic typeclasses (`Add`, `HAdd`, `Sub`, `Mul`, `Div`, `Mod`, `LE`, `LT`, `BEq`, `DecidableEq`, `Dvd`, `SMul`, `Inv`, etc.) on concrete core types (`Nat`, `Int`, `Rat`, `Real`, `Bool`, `UInt64`, etc.) via `[Add Nat]` / `(inst : Dvd Int)` local parameters (`REJECT_CONCRETE_LOCAL_INSTANCE`).
- **Escape Token Guard & Agent Skill:** Rejects `sorry`, `admit`, `axiom `, `unsafe `, `implemented_by`, `extern `, `lcProof`, and `trustCompiler` in active code, bundled with an agentskills.io-compatible skill at `skills/proofgate-formal-gate/SKILL.md` (`44` unit/PBT tests passing with zero warnings).


## What's New in v1.2.0 — Official Lean C++ `leanchecker` Kernel Replay & Optional `FastMCP` Server

- **Independent C++ `.olean` Kernel Replay (`proofgate.leanchecker_bridge`, `check-kernel` CLI):** Compiles standalone Lean 4 files in isolated temporary directories (`lean -R <dir> --trust=0 -DwarningAsError=true`) and replays the compiled `.olean` through Lean's official C++ `leanchecker` (`LEAN_PATH=<dir>:<stdlib>`), blocking environment-hacking metaprogramming bypasses (`PG-LEAN-014`, `PG-LEAN-015`). Gracefully returns `SKIPPED_NO_TOOLCHAIN` when Lean is not installed unless `--require-toolchain` is passed.
- **Optional FastMCP Server (`proofgate.mcp_server`, `proofgate-mcp`):** Lazy-imports `mcp.server.fastmcp.FastMCP` (keeping core `proofgate` 100% zero-dependency stdlib) to expose `proofgate_check_lean`, `proofgate_replay_kernel`, `proofgate_audit_spec_diff`, and `proofgate_export_sarif`.

## What's New in v1.3.0 — Zero-Dependency `goose` Stdio MCP Extension (`proofgate-goose-mcp`)

- **Stdlib-Only MCP JSON-RPC 2.0 Stdio Server (`proofgate.goose_mcp_stdio`, `proofgate-goose-mcp`):** Runs out of the box on Python 3.10+ without installing `mcp` or any third-party dependency, supporting both `Content-Length` framed and newline-delimited MCP `2024-11-05` / `2025-03-26` transports (`--strict-lifecycle` 2-phase handshake supported).
- **Operation Pale Fire YAML Recipe Pre-Gate (`proofgate_goose_scan_recipe`):** Blocks invisible Unicode codepoints (`ZWSP`/`ZWNJ`/`ZWJ`, BiDi overrides, Unicode Tag block `U+E0000..U+E007F`, variation selectors), Cyrillic/Greek confusable homoglyphs, hidden XML directives, and credential exfiltration while allowing standard environment variable interpolation.
- **Fail-Closed `PreToolCallHook` & Descriptor Pinning (`proofgate_goose_pre_tool_call`):** Enforces tool allowlists, blocks destructive shell/SQL invocations and credential path access, and detects SHA-256 tool-descriptor rug-pull mutations alongside RFC 6962 Merkle attestation receipts (`proofgate_goose_merkle_receipt`, `proofgate_goose_verify_lean`).

## What's New in v1.4.0 — Mathematical Substance & Non-Tautology Linter (`check-substance`)

- **Semantic Substance & Tautology Gate (`proofgate.substance_linter`, `check-substance` CLI, `proofgate_check_substance` MCP tool):** Parses Lean 4 declarations using the offset-preserving lexer and classifies theorems into `SUBSTANTIVE`, `CERTIFICATE_HELPER` (referenced batch helpers), `TRIVIAL_CLOSED_DECIDE` (`PG-LEAN-016`), `TRIVIAL_DEF_UNFOLD` (`PG-LEAN-017`), and `TRIVIAL_TAUTOLOGY` (`PG-LEAN-018`). Emits `substance_bps`, `summary_ratio`, and GitHub Code Scanning SARIF v2.1.0 results without breaking quantified or helper-backed proofs.
