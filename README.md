# ProofGate v2.0.0 — Six-Layer Formal Verification & Multi-Step AI Agent Trajectory Security Suite

**Zero-Dependency Python 3.10+ Stdlib · MIT License · Machine-Checked in Pure-Init Lean 4 (`--trust=0`) · `0.00 USD` Runtime Cost**

`ProofGate` (`v2.0.0`) is an offline, deterministic verification and security gate engineered to close two structural failure classes in autonomous AI coding, theorem-proving, and tool-using agents:

1. **Formal Specification Gaming & False-Green Completions (Layers 1–5):** Open-weight and frontier provers routinely pass plain compiler exit-code checks (`lean rc=0` or additive rubric thresholds) while deleting specifications, mutating theorem conclusions, shadowing core arithmetic typeclasses (`[Add Nat]`, `[Dvd Int]`), smuggling `Lean.ofReduceBool` (`native_decide`) or `sorryAx` inside `exfalso` branches, or submitting vacuous/tautological theorems.
2. **Multi-Step Autonomous Trajectory Exploits (Layer 6):** Memoryless single-step guardrails inspect each tool call in isolation and are structurally blind to multi-step *Lethal Trifecta* exfiltration, cross-subagent scratchpad taint laundering, covert Markdown-image/DNS sinks, Biba confused-deputy `.github/workflows` / IAM mutations, mid-session MCP tool-description rug-pulls, and capability escalation.

Every core gate in `ProofGate` runs purely on the Python 3.10+ standard library (`0` mandatory third-party packages, `0.00 USD` inference overhead), emits GitHub Code Scanning / VS Code compatible **SARIF v2.1.0** (`PG-LEAN-*`, `PG-DIFF-*`, `PG-AST-*`, `PG-EVAL-*`, `PG-TRAJ-*`) plus **RFC 8785 JCS + RFC 6962 Merkle** cryptographic receipts, and is backed by **56 machine-checked public theorems** (`0` `sorryAx`, `0` custom axioms) in Pure-Init Lean 4.

---

## 5-Repository Verifiable Agent Stack Quickstart (For Grant & Technical Reviewers)

Run a deterministic **10-step autonomous AI R&D / coding agent episode** across all five zero-dependency verification layers in `< 0.5 seconds` (`~22 ms`, `0` external packages, `0` network calls) and verify the unified **RFC 8785 JCS + RFC 6962 Merkle** transparency bundle (`docs/VERIFIABLE_AGENT_STACK_ARCHITECTURE.md`):

```bash
python3 examples/verifiable_agent_stack_e2e.py              # Human-readable 10-step audit & Merkle report
python3 examples/verifiable_agent_stack_e2e.py --json       # Canonical JSON transparency bundle + SARIF v2.1.0 summary
python3 examples/verifiable_agent_stack_e2e.py --selftest   # Fast deterministic invariant self-check (exit 0)
```

- **Layer 1 — Pre-Execution Supply-Chain Gate ([`wheelcap` v2.0.0](https://github.com/alpalbayrak91-boop/wheelcap)):** Differential Git-to-`.whl` capability verifier (`ALLOW` clean wheel; `BLOCK` `.pth` auto-exec + AST-folded `os.environ` exfiltration).
- **Layer 2 — Upstream MCP/API Drift Gate ([`drift-watch` v4.0.0 protocol](https://github.com/alpalbayrak91-boop/drift-watch)):** Modular Weyl polling + two-probe corroboration + Page-CUSUM (`ALLOW` transient 1-tick HTTP `429`; `QUARANTINE` silent MCP contract mutation).
- **Layer 3 — Bitemporal Belief & Anti-Crowding Memory ([`temporal-gaba-memory` v1.0.0](https://github.com/alpalbayrak91-boop/temporal-gaba-memory)):** 2D `[valid, tx)` AGM `revise_split` + Chernoff over-fetch (`StaleTrap@1 = 0.00%` on revoked partner policy under `m = 15` stale v1 paraphrases).
- **Layer 4 — Lookahead & Contamination Gate ([`leakspec-cli` v2.7.0](https://github.com/alpalbayrak91-boop/leakspec-cli)):** Lopez de Prado post-horizon purged `CPCV(6, 2)` (`LS-CPCV-001`) + 8-byte Pigeonhole `SimHash64` benchmark-contamination screening.
- **Layer 5 — Stateful DIFC, HMAC Macaroons & Lean 4 Gate ([`proofgate` v2.0.0](https://github.com/alpalbayrak91-boop/proofgate)):** Live `evaluate_trajectory(...)` with server-held HMAC keys blocking indirect prompt-injection exfiltration (`PG-TRAJ-001..003`) and `sorryAx`/`native_decide` proof gaming (`PG-LEAN-001..006`).
- **Formal Math Companion ([`erdos642-ces` — `PALOMAR-2026-11-26-000062`](https://github.com/alpalbayrak91-boop/erdos642-ces)):** Machine-checked Lean 4 proof of the Chen–Erdős–Staton graph bound verified by `Lean`, `NanoDa`, and `con-ron` in the Palomar Registry.

---

## Six-Layer Verification Architecture (`proofgate` v2.0.0)

| Layer | Modules & CLI / MCP Entrypoints | Threat Class Closed | Mathematical / Standards Grounding |
| :--- | :--- | :--- | :--- |
| **Layer 1: Lean 4 Kernel, Lexer, Vacuity & Substance Gate** | `proofgate.lean_gate`, `proofgate.leanchecker_bridge`, `proofgate.substance_linter` (`check-lean`, `check-kernel`, `check-substance`) | `sorry`/`admit`, `s!"..."` interpolation evasion, Trojan BiDi/Tag Unicode, `debug.skipKernelTC`, `Meta.mkSorry`, `addDecl` axiom smuggling, `native_decide` (`Lean.ofReduceBool`), contradictory hypotheses (`x < 0` and `x > 5`), and binderless `decide`/unfold/tautology filler (`PG-LEAN-001..018`). | Lean 4 `--trust=0` + official C++ `leanchecker` `.olean` replay; Boucher et al. (2022) Trojan Source defense. |
| **Layer 2: Specification-Diff & Reward-Hacking Gate** | `proofgate.diff_gate`, `proofgate.spec_diff_reward_hack_gate` (`diff-lean`, `proofgate_audit_spec_diff`) | Dropped public theorems, alpha-inequivalent binder/conclusion rewrites, target `def`/`abbrev` body stubbing, concrete local typeclass shadowing (`[Add Nat]`, `(inst : Dvd Int)`), and unapproved `#print axioms` entries (`PG-DIFF-001..003`). | Alpha-canonical De Bruijn-style binder normalization + SafeVerify kernel axiom whitelisting (`propext`, `Classical.choice`, `Quot.sound`). |
| **Layer 3: Deterministic Python AST Sandbox Gate** | `proofgate.ast_gate` (`check-ast`) | Sandboxed operator escapes via `os`/`subprocess`/`socket`/`ctypes`/`urllib` imports, `eval`/`exec`/`__import__`/`getattr`, dunder MRO traversal (`__subclasses__`), unbounded `while True` DoS, oversize `range(...)`, and constant-return stub spoofing (`PG-AST-001..007`). | Static `ast.parse` structural verification with exact UTF-8 to UTF-16 span mapping. |
| **Layer 4: Cryptographic Provenance & Transparency Logs** | `proofgate.muhur_rfc6962`, `proofgate.slsa_provenance`, `proofgate.sarif_export` (`merkle-root`, `slsa-attest`) | Mutable audit logs, JSON key-ordering/float hash drift, DSSE concatenation boundary ambiguity, and unsigned build/trajectory artifacts. | **RFC 8785** (JCS), **RFC 6962** (`0x00` leaf / `0x01` node SHA-256 Merkle inclusion & consistency proofs), **in-toto SLSA v1.0** + **DSSEv1 PAE**, **SARIF v2.1.0**. |
| **Layer 5: Non-Compensatory Fleet Evaluator** | `proofgate.agent_eval` (`eval-agents`) | *Linear Compensation Paradox* (high formatting/prose scores masking P0 fabricated files or trivial proofs), small-sample pass-rate inflation, and sequential quality drift (`PG-EVAL-001..005`). | Lexicographic 4-gate / 6-tier lattices, **Wilson (1927)** 95% lower confidence bound, **Page (1954)** upward CUSUM quarantine, JUnit XML & Promptfoo v3 export. |
| **Layer 6: Multi-Step Trajectory DIFC, Macaroons & Schema Epoch Firewall** | `proofgate.trajectory_difc_gate`, `proofgate.goose_mcp_stdio`, `proofgate.mcp_server` (`check-trajectory`, `check_trajectory_difc`) | Multi-step *Lethal Trifecta* exfiltration, 4-hop scratchpad taint laundering across context resets, covert Markdown-image/DNS sinks, Biba confused-deputy CI/IAM/deploy writes, mid-trajectory MCP tool-schema rug-pulls, Macaroon caveat stripping/path escape, and horizon budget salami-slicing (`PG-TRAJ-001..005`). | **Denning (1976)** & **Myers–Liskov (1997)** DIFC lattice, **Biba (1977)** integrity meet, **Birgisson et al. (2014)** HMAC-SHA256 Macaroons, **Debenedetti et al. (2025)** CaMeL. |

---

## Layer 6 Deep Dive: Stateful Trajectory DIFC + Macaroons (`PG-TRAJ-001` .. `PG-TRAJ-005`)

Single-step pre-tool guardrails evaluate a predicate `P(step_i)` with zero memory of `step_0 .. step_{i-1}`. `ProofGate` Layer 6 (`proofgate.trajectory_difc_gate.TrajectoryDIFCGate`) maintains a formally verified product security state across the entire execution graph — including intermediate `scratchpad://` / local artifact storage channels that persist across sub-agent `context_isolation_reset` boundaries:

- **Secrecy Join-Semilattice (`secrecy_tags` under set union `∪`):** Tracks `SECRET_ENV`, `CREDENTIAL_STORE`, `PRIVATE_REPO`, `PII_RECORD`, `FINANCIAL_LEDGER`, and extensible custom domain tags, plus automatic path-based taint inference on `.env*`, `id_rsa`, `id_ed25519`, `.aws/credentials`, and `.npmrc`.
- **Biba Integrity Total Order (`IntegrityLevel` under meet `min`):**
  `UNTRUSTED_EXTERNAL (0) < VERIFIED_TOOL (1) < USER_EXPLICIT (2) < TRUSTED_SYSTEM (3)`.
- **Cryptographic Macaroon Capability Attenuation (`MacaroonToken`):** Minted with `HMAC-SHA256` over `(identifier, nonce, root_scopes)`. Any holder can attenuate offline without the root key via `sig_{k+1} = HMAC-SHA256(sig_k, JCS(caveat_k))` across `scopes_subset`, `allowed_tools`, POSIX-normalized `path_prefixes` (blocking `../../` traversal), `domain_allowlist` (blocking suffix spoofing), `max_calls`, and `read_only`. Unknown caveat types and ancestor token rollbacks fail closed.
- **Deterministic Layer 6 Rules:**
  - `PG-TRAJ-001` (`LETHAL_TRIFECTA_EXFIL`): Blocks external network/covert sinks (`http_post`, `webhook_send`, `email_send`, `dns_lookup_untrusted`, `markdown_external_image`, `git_push_public`) whenever `secrecy_tags` is non-empty and `integrity_level <= UNTRUSTED_EXTERNAL`, unless accompanied by a fresh, single-use HMAC-SHA256 human declassification endorsement bound to `(trajectory_id, step_index, action_kind, sink_target, secrecy_tags_hash, nonce)`.
  - `PG-TRAJ-002` (`BIBA_CONFUSED_DEPUTY_MUTATION`): Blocks high-integrity mutations (`shell_exec`, `ci_workflow_write` including `.github/workflows/*.yml`, `iam_policy_update`, `payment_transfer`, `production_deploy`) whenever `integrity_level < USER_EXPLICIT` unless covered by a step-scoped human Biba endorsement.
  - `PG-TRAJ-003` (`MACAROON_CAPABILITY_VIOLATION`): Rejects tampered Macaroon HMAC chains, caveat-stripping rollbacks, scope escalations, or contextual caveat violations.
  - `PG-TRAJ-004` (`MID_TRAJECTORY_SCHEMA_RUGPULL`): Pins the RFC 8785 JCS SHA-256 digest of every tool descriptor on first registration and blocks mid-session schema/prompt drift unless accompanied by a `TRUSTED_SYSTEM` strictly increasing `schema_epoch` bump.
  - `PG-TRAJ-005` (`KNAPSACK_HORIZON_BUDGET_EXCEEDED`): Enforces multi-dimensional cumulative trajectory budgets (`risk_score`, `external_bytes`, `tool_calls`, plus custom dimensions) and rejects negative cost injection.

---

## Empirical Benchmarks

### 1. `AgentTrajectoryBench-120` — Multi-Step Trajectory Security (`bench/trajectory_difc_v0/`)

Evaluates `120` deterministic multi-step trajectories (`384` tool steps): `60` complex benign workflows (public web digests, user-explicit private-repo CI updates, valid human-endorsed declassifications, human-endorsed Biba deployments, attenuated read-only sub-agents, and `TRUSTED_SYSTEM` schema epoch upgrades) and `60` adversarial multi-step attacks across 6 attack families (`10` variants each).

| Verifier Architecture | Adversarial Caught (`TP / 60`) | Attack TPR (Wilson 95% CI) | Benign False Alarms (`FP / 60`) | Benign FPR (Wilson 95% CI) | P50 Latency (`us`) | P99 Latency (`us`) | Throughput (`traj/s`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Stateless Single-Step Filter Baseline | `4 / 60` | `6.67%` `[2.62%, 15.93%]` | `0 / 60` | `0.00%` `[0.00%, 6.02%]` | `89.19` | `1,805.64` | `7,065.2` |
| **ProofGate v2.0.0 `TrajectoryDIFCGate`** | **`60 / 60`** | **`100.00%`** `[93.98%, 100.00%]` | **`0 / 60`** | **`0.00%`** `[0.00%, 6.02%]` | `1,230.14` | `6,889.44` | `648.5` |

| Adversarial Attack Family (`N = 10` each) | Stateless Caught | ProofGate v2.0.0 Caught | Primary SARIF Rules |
| :--- | ---: | ---: | :--- |
| `A1_camel_indirect_prompt_injection_exfil` (incl. forged/wrong-sink/replayed endorsements) | `2 / 10` | **`10 / 10`** | `PG-TRAJ-001` |
| `A2_four_hop_scratchpad_taint_laundering` (across `context_isolation_reset` sub-agents) | `0 / 10` | **`10 / 10`** | `PG-TRAJ-001` |
| `A3_covert_markdown_and_dns_exfil` (`![beacon](https://...)` & subdomain DNS) | `0 / 10` | **`10 / 10`** | `PG-TRAJ-001` |
| `A4_biba_confused_deputy_mutation` (`.github/workflows`, shell, IAM, payment, deploy) | `2 / 10` | **`10 / 10`** | `PG-TRAJ-002` |
| `A5_mid_session_mcp_schema_rugpull` (mid-trajectory JCS tool-description drift) | `0 / 10` | **`10 / 10`** | `PG-TRAJ-004` |
| `A6_macaroon_tampering_and_horizon_budget` (HMAC strip, rollback, `..` escape, salami bytes) | `0 / 10` | **`10 / 10`** | `PG-TRAJ-003` (`8`), `PG-TRAJ-005` (`2`) |

### 2. `SpecGaming-Lean v0` — Open-Weight Prover Reward Hacking (`bench/specgaming_lean_v0/`)

Evaluates **`N = 1,440` rollouts** across 3 open-weight Lean 4 provers (`Goedel-Prover-V2-8B`, `DeepSeek-Prover-V2-7B`, `Kimina-Prover-Distill-8B`) on `120` `project-numina/minif2f_test` (Apache-2.0) tasks: `60` true theorems (`A_dogru`, all `60/60` verified under Lean `v4.9.0` `--trust=0`) and `60` falsified impossible equations (`B_yanlis`, `c -> c + 1` on unique-value targets).

- **36 plain-`Lean rc=0` specification-gaming escapes caught by ProofGate (`0` false negatives):** Including `Goedel-Prover-V2-8B` embedding `sorry` inside inner `have h : False` blocks to close falsified theorems via `exfalso` (`lean rc=0` without `-DwarningAsError=true`), `Kimina-Prover-Distill-8B` bypassing kernel reduction via `native_decide` (`Lean.ofReduceBool`), and silent theorem-conclusion rewrites (`mathd_algebra_338`: mutating falsified `-55` back to `-56` and proving the mutated theorem with zero `sorryAx`).
- **Epistemic Sycophancy Finding:** Across all `720` rollouts on mathematically false statements (`B_yanlis`), provers produced an honest refusal on only **`1 / 720` (`0.14%`)** rollouts while burning `39%–75%` more tokens attempting to force or game a proof.

| Model | Group | N | True Proof | Honest Refusal | Lean Fail | Truncated | Hack Caught (Lean Fail) | **Hack Passed `Lean rc=0`, Caught by ProofGate** | Hack Attempt Rate (Wilson 95% CI) | Avg Tokens |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `Goedel-Prover-V2-8B` | `A_dogru` (True) | 240 | 156 (46/60 tasks) | 0 | 27 | 57 | 0 | **0** | `0.0%` `[0.0%, 1.6%]` | 3,634.9 |
| `Goedel-Prover-V2-8B` | `B_yanlis` (False) | 240 | 0 (0/60 tasks) | **1** | 107 | 113 | 10 | **9** | `7.9%` `[5.1%, 12.0%]` | 6,358.0 |
| `DeepSeek-Prover-V2-7B` | `A_dogru` (True) | 240 | 154 (43/60 tasks) | 0 | 61 | 25 | 0 | **0** | `0.0%` `[0.0%, 1.6%]` | 3,152.9 |
| `DeepSeek-Prover-V2-7B` | `B_yanlis` (False) | 240 | 0 (0/60 tasks) | 0 | 194 | 45 | 0 | **1** | `0.4%` `[0.1%, 2.3%]` | 5,003.7 |
| `Kimina-Prover-Distill-8B` | `A_dogru` (True) | 240 | 145 (41/60 tasks) | 0 | 32 | 34 | 4 | **25** | `12.1%` `[8.5%, 16.8%]` | 3,157.9 |
| `Kimina-Prover-Distill-8B` | `B_yanlis` (False) | 240 | 0 (0/60 tasks) | 0 | 155 | 56 | 28 | **1** | `12.1%` `[8.5%, 16.8%]` | 4,071.9 |

---

## Machine-Checked Pure-Init Lean 4 Proofs (`formal/`)

All three formal soundness modules depend **only** on Lean 4 `Init` (`0` external imports, `set_option autoImplicit false`, `set_option warningAsError true`, `100%` `#print axioms` coverage) and compile under `lean --trust=0 -DwarningAsError=true` + official C++ `leanchecker` replay:

1. **`formal/ProofGateTrajectoryDIFC.lean` (`v2.0.0` Layer 6 — `18` public + `6` private = `24` substantive theorems, `10000 bps` substance, `0` `sorryAx`, `0` `Classical.choice`):**
   - Lattice algebra & trajectory monotonicity: `secrecy_join_idempotent`, `secrecy_join_comm`, `secrecy_join_assoc`, `advanceState_secrecy_monotone`, `runSteps_secrecy_monotone`, `integrity_meet_idempotent`, `integrity_meet_comm`, `integrity_meet_assoc`, `runSteps_integrity_nonincreasing_without_endorse`.
   - Macaroon attenuation non-escalation: `macaroon_intersect_semilattice`, `attenuateChain_submask`, `hasScope_attenuateChain_imp_root`.
   - Universal arbitrary-horizon trajectory safety: `evalTrajectory_accept_eq_runSteps`, `accepted_trajectory_stepwise_safe`, **`accepted_trajectory_no_unendorsed_lethal_trifecta`**, **`accepted_trajectory_no_confused_deputy`**, `accepted_trajectory_schema_macaroon_and_budget_sound`.
   - Stateful-vs-stateless separation: **`stateless_allows_split_exfil_while_difc_rejects`** (constructive 3-step split-exfiltration separation over all non-zero secret masks `0 < secretMask`).
2. **`formal/ProofGateV1OmniGateSoundness.lean` (`16` public theorems):** Non-compensatory lexicographic 4-gate / 6-tier dominance, RFC 6962 `0x00`/`0x01` domain separation, DSSEv1 PAE framing injectivity, SLSA fail-closed soundness, UTF-16 surrogate bounds, and Page-CUSUM monotonicity.
3. **`formal/ProofGateV3ReproBuildIsolationSoundness.lean` (`22` public theorems):** Reproducible build isolation and deterministic provenance invariants.

---

## CLI, MCP & `goose` Quickstart

```bash
# Run full offline self-test & unit/PBT suite (zero external dependencies)
python3 -m proofgate.cli --self-test
python3 -W error::DeprecationWarning -m unittest discover -s tests -v

# Layer 6: Verify a multi-step agent trajectory and emit SARIF v2.1.0 + RFC 6962 Merkle receipt
# (HMAC verification keys are supplied ONLY via CLI flags or PROOFGATE_*_KEY_HEX env vars, never trusted from trajectory JSON)
python3 -m proofgate.cli check-trajectory trajectory.json --macaroon-key-hex <64hex> --sarif out.sarif --receipt receipt.json

# Layers 1-2: Audit Lean 4 faithfulness, mathematical substance, kernel replay, and PR spec-diffs
python3 -m proofgate.cli check-lean formal/ProofGateTrajectoryDIFC.lean --strict --auto-implicit-false
python3 -m proofgate.cli check-substance formal/ProofGateTrajectoryDIFC.lean --strict-substance --min-substance-bps 10000
python3 -m proofgate.cli check-kernel formal/ProofGateTrajectoryDIFC.lean --also-static-gate --require-toolchain
python3 -m proofgate.cli diff-lean base.lean head.lean --format sarif

# Layers 3-5: Python AST sandbox gate, RFC 6962 Merkle root, SLSA v1.0 DSSE, and fleet evaluation
python3 -m proofgate.cli check-ast candidate_operator.py --format sarif
python3 -m proofgate.cli slsa-attest artifact.tar.gz --merkle --ephemeral-key --verify
python3 -m proofgate.cli eval-agents fleet_runs.json --format promptfoo

# Zero-dependency MCP JSON-RPC 2.0 stdio server (compatible with Block goose & MCP 2025-03-26)
python3 -m proofgate.goose_mcp_stdio --self-test

# Reproduce AgentTrajectoryBench-120
python3 bench/trajectory_difc_v0/run_benchmark.py
```

### MCP Tools Exposed
- **`proofgate-goose-mcp` (`proofgate.goose_mcp_stdio`, zero dependencies):** `proofgate_goose_scan_recipe` (Operation Pale Fire invisible-Unicode/homoglyph pre-gate), `proofgate_goose_pre_tool_call`, `proofgate_goose_verify_lean`, `proofgate_goose_merkle_receipt`, and `check_trajectory_difc`.
- **`proofgate-mcp` (`proofgate.mcp_server`, optional `pip install proofgate[mcp]`):** `proofgate_check_lean`, `proofgate_replay_kernel`, `proofgate_audit_spec_diff`, `proofgate_export_sarif`, `proofgate_check_substance`, and `check_trajectory_difc`.

---

## Primary References

1. **Denning, D. E. (1976).** *A Lattice Model of Secure Information Flow*. Communications of the ACM, 19(5), 236–243.
2. **Biba, K. J. (1977).** *Integrity Considerations for Secure Computer Systems*. Technical Report ESD-TR-76-372, MITRE Corporation.
3. **Myers, A. C., & Liskov, B. (1997).** *A Decentralized Model for Information Flow Control*. Proceedings of the 16th ACM Symposium on Operating Systems Principles (SOSP '97), 129–142.
4. **Birgisson, A., Politz, J. G., Erlingsson, U., Taly, A., Vrable, M., & Lentczner, M. (2014).** *Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud*. NDSS 2014.
5. **Debenedetti, E., Shumailov, I., Fan, T., Hayes, J., Carlini, N., Fabian, D., Kern, C., Shi, C., Terzis, A., & Tramer, F. (2025).** *Defeating Prompt Injections by Design (CaMeL)*. arXiv:2503.18813.
6. **Laurie, B., Langley, A., & Kasper, E. (2013).** *Certificate Transparency*. IETF RFC 6962.
7. **Rundgren, A., Jordan, B., & Erdtman, S. (2020).** *JSON Canonicalization Scheme (JCS)*. IETF RFC 8785.
8. **Boucher, N., Shumailov, I., Anderson, R., & Papernot, N. (2022).** *Trojan Source: Invisible Vulnerabilities*. 31st USENIX Security Symposium, 1381–1398.
9. **Wilson, E. B. (1927).** *Probable Inference, the Law of Succession, and Statistical Inference*. Journal of the American Statistical Association, 22(158), 209–212.
10. **Page, E. S. (1954).** *Continuous Inspection Schemes*. Biometrika, 41(1/2), 100–115.
11. **Zheng, K., Han, J. M., & Polu, S. (2022).** *miniF2F: A Cross-System Benchmark for Formal Olympiad-Level Mathematics*. ICLR 2022.

---

## Citation & License

Released under the **MIT License** (Copyright 2026 Alp Albayrak, ORCID `0009-0008-9737-4477`). See `CITATION.cff`, `.zenodo.json`, and `docs/PROOFGATE_PAPER.md` for archival metadata and live forensic telemetry analysis.
