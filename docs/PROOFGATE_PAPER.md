# AlpLab-ProofGate: Non-Compensatory Lexicographic Meta-Auditing, AST-Safe Operator Verification, and Lean 4.36 Hygiene Gates for Autonomous Multi-Agent Fleets

**Artifact ID:** `V16-UFUK2-VITRIN-PROOFGATE-04` (Updated `IS-PG-01` Related Work & BibTeX Merge: `FLEX-202611202157-2E4945`)  
**Research Track:** `KONU-3-LEAN4-META-DENETIM` / `KONU-1-BULUT-OS` (UFUK-2B Open-Source Showcase & arXiv Preprint Draft)  
**Measurement Timestamp (UTC):** `2026-11-19T07:39Z` (Related Work & BibTeX consolidated `2026-11-21`)  
**Execution Cost:** `0.00 USD` (KURAL-3 compliant: zero `chr(36)` currency symbols)  
**Artifact Honesty Notice:** Live empirical telemetry is queried directly from AlpLab PostgreSQL 17 (`audit_verdicts`, `fleet_audit_runs`, `verified_operators`, `audit_evidence_log`, `agent_task_queue`, `host_command_queue`). Benchmark timings and verification matrices were executed live in `isolated_python_sandbox` (`v16_ufuk2_vitrin_proofgate_04_bench_v1..v3`, `k1_is_pg_01_paper_readme_merge_audit_20261121`, `exit_code=0`). All proposed open-source repository files under `alplab_proofgate/` are explicitly marked `TASLAK_ONERI` and are NOT claimed to exist or be compiled on disk unless listed under Section 3.3.

---

## Abstract

Autonomous multi-agent engineering fleets frequently produce **false-green completions** (`sahte-TAMAMLANDI`): tasks self-reported as complete while referencing nonexistent repository files (`EKSIK_DOSYA`), emitting constant-only trivial formal proofs (`TRIVIAL_ISPAT`), duplicating prior outputs (`KOPYA_CIKTI`), or bypassing cross-model verification. In an empirical forensic audit of AlpLab v15 production telemetry (`audit_verdicts`, N=531 audited records; `fleet_audit_runs`, N=1,546 continuous fleet audit runs; `verified_operators`, N=49 verified Python operators; `audit_evidence_log`, N=7,091 counterexample evidence logs), we uncover a structural failure mode we term the **Linear Compensation Paradox**. Under the legacy additive penalty scorer (`puan >= 75 -> GECTI`), **45.74% (59/129)** of records containing hard integrity defects leaked through as `GECTI`, including **48.35% (44/91)** of `EKSIK_DOSYA` violations and **71.43% (5/7)** of `TRIVIAL_ISPAT` violations. Among `agent_task_queue` tasks marked `TAMAMLANDI` and audited by Allean (N=465), **25.38% (118/465)** contained at least one hard integrity defect, yet the legacy additive gate downgraded only **50.85% (60/118)** while letting **49.15% (58/118)** pass. Furthermore, **100.00% (1,546/1,546)** of continuous `fleet_audit_runs` lacked Git provenance (`git_shas = {}`), and **4.79% (74/1,546)** flagged `recent_unverified_done_count > 0` (690 cumulative unverified-DONE observations).

To close these failure modes with zero paid API overhead (`0.00 USD`), we present **AlpLab-ProofGate**, an open-source, fail-closed verification architecture combining: (1) a **non-compensatory lexicographic 4-gate / 6-tier scoring lattice** (`INV-09..INV-13`) formalized in Init-only Lean 4.36.0 (`formal/Konu3MetaAuditInv09Inv12.lean`, `formal/Konu3MetaAuditInv13ProvenanceChain.lean`), (2) a **deterministic Python AST-Safe static verifier** validated across 49 live cumulative operators (`0/49` unsafe imports, `0/49` unsafe builtins, `0/49` `chr(36)`), (3) a **Lean 4 static triviality and axiom-hygiene scanner**, and (4) **capability-sound dispatch and cross-family typed JSON refereeing**. On an exact live replay of all N=531 `audit_verdicts` defect vectors (`isolated_python_sandbox`), the deployed PG17 operator `lexicographic_meta_audit_4gate_bps` lifts `EKSIK_DOSYA` catch rate from **51.65% to 100.00%** (+48.35 pp), `TRIVIAL_ISPAT` catch rate from **28.57% to 100.00%** (+71.43 pp), and strict P0 catch rate (`EKSIK_DOSYA`, `TRIVIAL_ISPAT`, `KOPYA_CIKTI`; N=110) from **55.45% to 100.00%** at **485,295.2 evaluations/sec** (P50 = `1.329 us`, P99 = `5.351 us`), while escalating `ANLIK_SURE` under `ProofGate-Strict` reaches **100.00% (129/129)** across all five hard defect classes. Across 10,000 randomized property-based trials, ProofGate incurs **0/10,000** invariant violations; its AST-Safe verifier achieves **100.00% TPR / 0.00% FPR** (P50 = `98.96 us`) and its multi-binder-aware Lean 4 hygiene scanner achieves **100.00% TPR / 0.00% FPR** (P50 = `37.35 us`).

---

## 1. Introduction: The Linear Compensation Paradox in Multi-Agent Auditing

Modern LLM agent fleets execute code generation, database migrations, and theorem proving at scale, but autonomous self-reporting (`status = TAMAMLANDI` / `DONE`) is systematically unreliable. Standard mitigation pipelines attach an automated post-hoc scorer that starts from a base score of 100 and subtracts linear penalties per detected defect (e.g., `-15` for a single missing file, `-20` for a trivial proof, `-20` for an anomalous instantaneous duration, `-30` for short output, `-40` for duplicate output), passing any candidate whose total remains at or above a threshold (e.g., `puan >= 75 -> GECTI`).

Live forensic data from AlpLab v15 proves that **linear additive scoring is mathematically unsound for epistemic integrity**. Whenever a single P0 defect carries a penalty smaller than `100 - threshold` (here `100 - 75 = 25`), an agent that emits an otherwise well-formatted response automatically compensates for a fabricated file path (`100 - 15 = 85 -> GECTI`) or a constant-only trivial theorem (`100 - 20 = 80 -> GECTI`). We call this failure mode the **Linear Compensation Paradox**: high superficial quality scores mask catastrophic soundness defects.

**Contributions of AlpLab-ProofGate:**
1. **Live Production Forensics:** Exact empirical measurement of false-green `TAMAMLANDI`, `EKSIK_DOSYA`, `TRIVIAL_ISPAT`, provenance blindness, and operator safety across six live PG17 tables (`N=531` Allean audits, `N=1,546` continuous fleet runs, `N=49` verified operators, `N=7,091` counterexample records, `N=237` AGY host commands).
2. **Non-Compensatory Lexicographic Gate Lattice (`INV-08..INV-13`):** Strict tier dominance where any P0 integrity defect, missing disk artifact, capability mismatch, empty Git provenance, or prose-only referee verdict maps to a hard veto tier strictly below every clean pass, independent of superficial quality score.
3. **Zero-Dependency Static Verifiers:** Sub-millisecond Python `ast` safety verification and multi-binder-aware Lean 4.36 triviality/axiom hygiene scanning suitable for synchronous CI/CD and MCP tool-gate enforcement.
4. **Open-Source Packaging Blueprint (`TASLAK_ONERI`):** Clean modular architecture (`alplab_proofgate`) designed for drop-in adoption by multi-agent coding and formal-verification harnesses.

---

## 2. Empirical Forensic Measurements (Live PG17 Telemetry)

All measurements in this section were queried directly via `postgres_sql` against AlpLab PostgreSQL 17 on `2026-11-19` prior to benchmark replay.

### 2.1 `audit_verdicts` Defect & Legacy Leakage Audit (N=531)

Across the measurement window `2026-11-18 21:19:25Z` to `2026-11-19 07:19:47Z`, `audit_verdicts` contains **531 audited records** (466 from `agent_task_queue`, 65 from `host_command_queue`). Overall legacy score statistics: mean `92.92`, median `100.0`, min `40`, max `100`. Records with zero findings: **101/531 (19.02%)**; records with at least one finding: **430/531 (80.98%)**. Legacy verdicts: **460 `GECTI` (86.63%)**, **70 `KISMEN` (13.18%)**, **1 `KALDI` (0.19%)**. Cross-model referee invocation (`hakem IS NOT NULL`) occurred on only **12/531 (2.26%)** records, with a finalized `hakem_karar` on only **1/531 (0.19%)** (`codex/codex(abonelik) -> KALDI`).

**Table 1: Complete Finding Taxonomy and Legacy Additive Leakage in `audit_verdicts` (N=531)**

| Finding Code (`bulgular.kod`) | Severity Class | Total Occurrences | Distinct Records Affected (% of 531) | Legacy `GECTI` (Leaked) | Legacy `KISMEN` / `KALDI` (Caught) | Legacy Catch Rate | Legacy Mean Score (Min-Max) |
|---|---|---:|---:|---:|---:|---:|---|
| `KIP_UYUSMAZ` | P1 Soft | 367 | 367 (69.11%) | 316 | 51 / 0 | 13.90% | 92.81 (45-100) |
| `EKSIK_DOSYA` | **P0 Hard** | 147 | **91 (17.14%)** | **44** | **47 / 0** | **51.65%** | 69.42 (45-85) |
| `KIP_KANITI_YOK` | P1 Soft | 45 | 45 (8.47%) | 39 | 6 / 0 | 13.33% | 87.89 (50-95) |
| `KOPYA_CIKTI` | **P0 Hard** | 15 | **15 (2.82%)** | **0** | **14 / 1** | **100.00%** | 56.33 (40-60) |
| `ANLIK_SURE` | **P0/P1 Hard-Timing** | 14 | **14 (2.64%)** | **10** | **4 / 0** | **28.57%** | 73.93 (50-80) |
| `KISA_CIKTI` | **P1 Hard-Length** | 9 | **9 (1.69%)** | **0** | **9 / 0** | **100.00%** | 69.44 (65-70) |
| `TRIVIAL_ISPAT` | **P0 Hard** | 7 | **7 (1.32%)** | **5** | **1 / 1** | **28.57%** | 72.14 (40-80) |
| **Any Strict P0 (`EKSIK`/`TRIVIAL`/`KOPYA`)** | **Composite P0** | — | **110 (20.72%)** | **49** | **60 / 1** | **55.45%** | — |
| **Any Hard-5 (`EKSIK`/`TRIVIAL`/`KOPYA`/`KISA`/`ANLIK`)** | **Composite Hard-5** | — | **129 (24.29%)** | **59** | **69 / 1** | **54.26%** | — |

Key forensic insight from the 7 `TRIVIAL_ISPAT` records: 5 of 7 (71.43%) scored exactly `puan = 80` and received `GECTI` despite explicit detector notes such as `"4/4 teorem sabit sayi uzerinde tek taktik"` (`b3fad649-e12c-4de7-8183-4b9a49a80ae7`) and `"3/5 teorem sabit sayi uzerinde tek taktik"` (`3fc2bb09-f1ad-4513-9994-e20845e5a175`, `a5a870e9-d781-40d6-b9f8-efc00ae11d9f`). Only when `TRIVIAL_ISPAT` co-occurred with `EKSIK_DOSYA` (`puan = 65 -> KISMEN`) or `KOPYA_CIKTI` (`puan = 40 -> KALDI`) did the legacy additive scorer stop it.

### 2.2 Sahte-TAMAMLANDI Rate (`agent_task_queue` JOIN `audit_verdicts`)

Across the full task ledger `agent_task_queue` (N=1,147 rows across 16 statuses), **776 tasks** hold `durum = 'TAMAMLANDI'`, while upstream guards already quarantined **80** tasks into `KANITSIZ_KARANTINA_INV03`, **72** into `DLQ_INCELEME_INV03`, **15** into `BOS_CIKTI_ARSIV`, and **5** into `ZOMBIE_LIMIT_ASILDI`. Joining `audit_verdicts` onto `agent_task_queue` yields **466 matched tasks** (465 `TAMAMLANDI`, 1 `KANITSIZ_KARANTINA_INV03`):

**Table 2: Empirical False-DONE (`Sahte-TAMAMLANDI`) Prevalence Among Audited `TAMAMLANDI` Tasks (N=465)**

| Subset of Audited `TAMAMLANDI` Tasks | Count | Share of 465 | Legacy `GECTI` (Leaked) | Legacy `KISMEN` (Caught) | Legacy Catch Rate |
|---|---:|---:|---:|---:|---:|
| Total Audited `TAMAMLANDI` Tasks | 465 | 100.00% | 405 (87.10%) | 60 (12.90%) | — |
| Containing Any Hard-5 Defect | **118** | **25.38%** | **58** | **60** | **50.85%** |
| Containing `EKSIK_DOSYA` | 90 | 19.35% | 43 | 47 | 52.22% |
| Containing `ANLIK_SURE` | 14 | 3.01% | 10 | 4 | 28.57% |
| Containing `KOPYA_CIKTI` | 9 | 1.94% | 0 | 9 | 100.00% |
| Containing `TRIVIAL_ISPAT` | 6 | 1.29% | 5 | 1 | 16.67% |
| Containing `KISA_CIKTI` | 5 | 1.08% | 0 | 5 | 100.00% |

Roughly **1 in 4 (`25.38%`)** self-reported `TAMAMLANDI` tasks exhibited a hard integrity defect upon automated inspection, and the legacy linear scorer missed nearly **half (`49.15%`, 58/118)** of them.

### 2.3 Continuous Fleet Audit Telemetry (`fleet_audit_runs`, N=1,546)

Between `2026-11-14 09:17:04Z` and `2026-11-19 07:36:53Z`, `alplab-meta-auditor-v1` recorded **1,546 continuous audit runs** with 2,735 cumulative open findings (mean `1.77`, max `5`):

**Table 3: Longitudinal Findings Across `fleet_audit_runs` (N=1,546)**

| Telemetry Indicator | Runs Triggered | Share of 1,546 | Breakdown by Verdict (`FAIL` / `WARN` / `PASS`) | Operational Interpretation |
|---|---:|---:|---|---|
| Total Audit Runs | 1,546 | 100.00% | `988` (63.91%) / `79` (5.11%) / `479` (30.98%) | Continuous fail-closed fleet monitoring |
| `git_shas` Empty (`{}`) | **1,546** | **100.00%** | `988` / `79` / `479` | **INV-13 Provenance Blind Spot:** 0 runs bound to live Git HEAD |
| `stalled_retry3_count > 0` | 931 | 60.22% | `857` / `74` / `0` | Repeated retry exhaustion without root-cause fix |
| `drift.sapma_sayisi > 0` | 900 | 58.21% | `900` / `0` / `0` | INV-02 3-root synchronization drift |
| `pending_cross_reviews > 0` | 711 | 45.99% | `691` / `20` / `0` | Cross-family referee backlog / liveness bottleneck |
| `recent_unverified_done_count > 0` | **74** | **4.79%** | **`74` / `0` / `0`** | **690 total unverified-DONE events** (max 10/run); 100% triggered `FAIL` |
| `mcp_lock.protosafe_hazards_count > 0` | 0 | 0.00% | `0` / `0` / `0` | ProtoSafe flat-schema lock maintained across all runs |
| `stuck_running_count > 0` | 0 | 0.00% | `0` / `0` / `0` | Zero zombie-running tasks at snapshot points |

Crucially, while `alplab-meta-auditor-v1` achieves **100.00% (74/74)** `FAIL` escalation whenever `recent_unverified_done_count > 0`, it still marked **479 runs `PASS`** despite `git_shas = {}` (zero commit-hash provenance binding). Closing this gap is the core motivation for `INV-13`.

### 2.4 Operator Corpus Safety (`verified_operators`, N=49) and Upstream Preflight Gates

1. **`verified_operators` (N=49, `2026-11-16 20:26Z` to `2026-11-19 07:28Z`):** All **49/49 (100.00%)** operators are marked `verified = true` and contain executable Python definitions (`95,786` total bytes; min `255 B`, max `12,336 B`, mean `1,954.8 B`), spanning 6 branches (`research_branch`: 40, `core_system_branch`: 40, `production_branch`: 19, `compliance_branch`: 11, `simulation_branch`: 9, `planning_branch`: 5; multi-branch tagging). Live SQL regex audit confirms:
   - `0/49` contain `chr(36)` (100.00% KURAL-3 compliant)
   - `0/49` contain unsafe imports (`os`, `sys`, `subprocess`, `socket`, `urllib`, `requests`, `shutil`, `pathlib`)
   - `0/49` contain unsafe builtins (`open`, `eval`, `exec`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `locals`)
   - `0/49` contain unbounded `while True` loops
   - `1/49` contains the substring `sorry` solely as the boolean gate parameter name `lean_zero_sorry` in `lexicographic_meta_audit_4gate_bps`
2. **`audit_evidence_log` (N=7,091 evidence rows):**
   - `ALP_GOAL_AUDIT`: `5,727` `QED_KANITLANDI` (`4,937` `gemini-3.6-flash`, `790` `deterministic-lean-guard`) vs **599 `COUNTEREXAMPLE_REDDEDILDI`** (`583` `gemini-3.6-flash`, `16` `gemini-4-argon`; **9.47% rejection rate**).
   - `KONTROL_GEREKLI_AUDIT` (`KontrolGerekliBagimsizDenetci`): `557` `TAMAMLANDI_ONAYLANDI` vs **134 `COUNTEREXAMPLE_REDDEDILDI`** (**19.39% rejection rate**, 134/134 with explicit counterexamples).
   - `QUEUE_TAMAMLANDI_AUDIT` (`RuthlessClaimVerifier`): **74/74 `COUNTEREXAMPLE_REDDEDILDI`** (100.00% counterexample-backed rejections on flagged queue completions).
3. **`host_command_queue` (N=237 host commands):**
   - `100` `TAMAMLANDI` (42.19%), **64 `KARANTINA_EKSIK_TASLAK` (27.00%)** intercepted preflight by `on_filtre_eksik_taslak` before consuming host Lean/AGY slots, `39` `HATA` (including **3** blocked by INV-12 `hicbiri_tier2_yetenek_uyumsuz`), `32` `DEVREDILDI_TIER2`, and `2` `IPTAL_MUKERRER_HEDEF`.

---

## 3. Formal Architecture: The AlpLab-ProofGate 4-Gate Lexicographic Lattice

AlpLab-ProofGate replaces linear additive scoring with a strict **fail-closed 4-gate pipeline** governed by invariants `INV-08` through `INV-13`.

### 3.1 Mathematical Specification of the Non-Compensatory Scoring Lattice

Let a candidate audit artifact carry non-negative integer defect counters `P0 = (p0_fake_commit, p0_trivial_proof, p0_missing_file, p0_axiom_bypass, p0_copy_output)` and `P1 = (p1_mode_mismatch, p1_no_mode_proof, p1_short_output, p1_instant_duration)`, binary provenance/referee flags `F = (git_sha_present, roots_synced, lean_zero_sorry, lean_axioms_clean, referee_reachable, referee_distinct_family, referee_approved)`, and bounded quality score `q in [0, 10000]`.

**Tiered Veto Mapping (`lexicographic_meta_audit_4gate_bps`, deployed in PG17):**
- **Tier -6 (`-26000 bps`):** Malformed domain (any negative count or non-binary flag).
- **Tier -5 (`-25000 bps`, KALDI):** Any `sum(P0) > 0` (`EKSIK_DOSYA`, `TRIVIAL_ISPAT`, `KOPYA_CIKTI`, `SAHTE_COMMIT`, `AXIOM_BYPASS`).
- **Tier -4 (`-24000 bps`, KALDI):** Provenance or Lean kernel failure (`git_sha_present = 0` or `roots_synced = 0` or `lean_zero_sorry = 0` or `lean_axioms_clean = 0`).
- **Tier -3 (`-23000 bps`, KARANTINA_HAKEM):** Cross-family referee unreachable or same-family self-review (`referee_reachable = 0` or `referee_distinct_family = 0`).
- **Tier -2 (`-22000 bps`, KALDI):** Cross-family referee rejection (`referee_approved = 0`).
- **Tier 0 (`[0, 10000] bps`):** All hard gates passed; `score = max(0, 10000 - 200*p1_mode - 500*p1_noproof - 3000*p1_short - 2000*p1_instant)`, with `GECTI iff score >= 7500`.

**6-Tier Strict Provenance Lattice (`inv13LexScore6Tier`, INV-13 extension):**
For full workspace, capability, provenance, referee-liveness, and budget coupling:
```
score6(ws, cap, prov, live, bud, p1, q) =
  0                   if ws = 0
  1                   if cap = 0
  2                   if prov = 0          (git_sha_count = 0 OR p0_defects > 0)
  3                   if live = 0          (referee_age > TTL OR stuck_reviews > 0 OR same_family != 0 OR typed_json != 1)
  4 + min(10000, q)   if bud = 0 OR p1 > 0
  10005 + min(10000, q)  otherwise         (Clean PASS)
```
**Non-Compensatory Dominance Theorem (INV-09 / INV-13):** For all `q_bad, q_clean in Nat`, whenever any hard gate fails (`ws=0 or cap=0 or prov=0 or live=0 or bud=0 or p1 > 0`), `score6(..., q_bad) <= 10004 < 10005 <= score6(1, 1, 1, 1, 1, 0, q_clean)`. No amount of prose length or superficial quality can cross the `10004 -> 10005` barrier.

### 3.2 The Four Verification Gates

1. **Gate 1 — Workspace Preflight & Provenance Chain (`INV-12` / `INV-13`):** Verifies every referenced file exists on disk with `bytes > 0` (eliminating `EKSIK_DOSYA` before dispatch, matching the live 64/237 `KARANTINA_EKSIK_TASLAK` preflight guard), binds `git_sha_count >= 1`, and enforces WORM row-to-row hash chaining (`prev_chain_hash = head_chain_hash`, `next_chain_hash != prev_chain_hash`, `next_chain_hash > 0`).
2. **Gate 2 — Capability-Sound Dispatch & AST-Safe Operator Sandbox (`INV-12`):** Encodes task requirements and target worker capabilities as 4-bit masks (`bit0: lean_host`, `bit1: pg_ddl`, `bit2: repo_write`, `bit3: cross_audit`) and rejects any dispatch where `(req_mask & tgt_mask) != req_mask` (`-24000 bps`). All candidate Python operators pass through a zero-dependency `ast.parse` whitelist rejecting forbidden imports (`os`, `sys`, `subprocess`, `socket`, `urllib`, `requests`, `shutil`, `pathlib`, `ctypes`, `importlib`, `pickle`, `builtins`), forbidden calls (`eval`, `exec`, `compile`, `__import__`, `open`, `getattr`, `setattr`, `delattr`, `globals`, `locals`), dunder escape chains (`__class__`, `__mro__`, `__subclasses__`, `__globals__`, `__builtins__`), unbounded `while True` loops, and `chr(36)`.
3. **Gate 3 — Lean 4.36.0 Hygiene & Non-Triviality Gate (`INV-08` / `INV-09`):** Strips line (`--`) and block (`/- ... -/`) comments, rejects `sorry`, `admit`, custom `axiom`, `native_decide`, free-variable `decide`, missing `#print axioms`, `chr(36)`, and flags `TRIVIAL_ISPAT` whenever more than 50% of theorems in a module have zero universal parameters and single-tactic constant proofs (`decide`/`rfl`/`omega`/`norm_num`). On host compilation, requires `lean --trust=0`, `lake build`, and `lake env leanchecker` with `RC = 0`.
4. **Gate 4 — Typed Cross-Family Referee & Atomic 4-Gate Self-Modification (`INV-10` / `INV-11`):** Bans `PROSE_AS_DONE` by requiring a typed JSON verdict schema (`typed_verdict_json = 1`), enforces `same_family_referee = 0` (e.g., Gemini-family output audited by Claude/Codex-family referee), enforces bounded referee freshness (`referee_age_sec <= max_referee_age_sec`, `stuck_review_count = 0`), and rolls back any self-modification missing any of the 4 gates (`opsec`, `pytest`, `lean4`, `adversarial_audit`) or failing `pre_sha_id = active_root_sha`.

### 3.3 Existing Formal Workspace Artifacts and Honest Compilation Status

The following Lean 4.36.0 files exist on disk in the AlpLab workspace (verified via `hub_workspace_list` and `hub_workspace_read`):
- `formal/Konu3MetaAuditInv09Inv12.lean`: 10 theorems (Teorem 75-84 covering INV-09 dominance, INV-10 atomic 4-gate rollback, INV-11 `PROSE_AS_DONE`/same-family block, INV-12 capability soundness, liveness retry, replay idempotency, and canonical closed-term witnesses; 10/10 `#print axioms`; 0 `sorry`; Init-only).
- `formal/Konu3MetaAuditInv13ProvenanceChain.lean`: 8 theorems (Teorem 85-92 covering empty `git_shas` block, referee blackout/stuck-review block, WORM hash-chain tamper preservation, strict epoch monotonicity, replay idempotency, AGY timeout budget gate, 6-tier lexicographic dominance, and 2026-11-19 live telemetry witnesses; 8/8 `#print axioms`; 0 `sorry`; Init-only).
- `formal/AlpLabVitrinEpistemicGate.lean`: 7 theorems covering ZESE minor/axiom/budget gates and epistemic vitrin state-transition idempotency (7/7 `#print axioms`; 0 `sorry`).

**Honest Verification Status:** Querying `host_command_queue` confirms `0` completed host AGY compilation jobs referencing `Konu3MetaAuditInv09Inv12.lean` or `Konu3MetaAuditInv13ProvenanceChain.lean` as of `2026-11-19T07:39Z`, and `isolated_python_sandbox` executes in an isolated Python container without `lean`/`lake`. Therefore, per ProofGate's own anti-false-DONE rule, host `lean --trust=0` / `lake build` / `leanchecker` `RC=0` sealing of those two files is recorded as **PENDING_HOST_LEAN_DISPATCH** rather than claimed as compiled.

---

## 4. Open-Source Repository Architecture (`AlpLab-ProofGate`) — `TASLAK_ONERI`

The following repository layout is a **proposed open-source packaging blueprint (`TASLAK_ONERI`)** for publishing AlpLab-ProofGate as a standalone Apache-2.0 / MIT package. None of the paths below under `alplab_proofgate/` are claimed to be created on disk in this turn.

```text
alplab-proofgate/                          # TASLAK_ONERI open-source repo layout
├── pyproject.toml                         # Zero external runtime deps (Python >= 3.10 stdlib)
├── README.md                              # Quickstart, 4-gate diagram, arXiv citation
├── LICENSE                                # Apache-2.0
├── alplab_proofgate/
│   ├── __init__.py
│   ├── lattice.py                         # INV-09..INV-13 lexicographic 4-gate & 6-tier scorers
│   ├── ast_guard.py                       # Deterministic Python AST-Safe verifier (0-dep)
│   ├── lean_hygiene.py                    # Multi-binder Lean 4 static triviality & axiom scanner
│   ├── provenance.py                      # Git HEAD rev-parse + SHA-256 WORM hash-chain verifier
│   ├── capability.py                      # INV-12 4-bit capability mask dispatch guard
│   ├── referee.py                         # INV-11 typed JSON verdict parser (bans PROSE_AS_DONE)
│   └── cli.py                             # `proofgate verify --artifact ... --repo ...`
├── lean/
│   ├── lakefile.lean                      # Lean 4.36.0 Init-only (zero Mathlib dependency)
│   ├── ProofGate/
│   │   ├── Inv09Inv12Lattice.lean         # Port of formal/Konu3MetaAuditInv09Inv12.lean
│   │   └── Inv13ProvenanceChain.lean      # Port of formal/Konu3MetaAuditInv13ProvenanceChain.lean
├── sql/
│   └── pg17_proofgate_worm_ledger.sql     # TASLAK_ONERI PG17 CHECK constraints & WORM chain trigger
├── benchmarks/
│   ├── replay_allean_n531.py              # Reproducible live corpus replay (27-tuple distribution)
│   ├── pbt_invariants_10k.py              # 10,000-trial property-based parity suite
│   ├── bench_ast_safe_24.py               # 12 clean + 12 adversarial AST bypass suite
│   └── bench_lean_hygiene_16.py           # 6 clean + 10 adversarial Lean spoof suite
└── tests/
    └── test_proofgate_end_to_end.py       # Pytest parity suite (Python == SQL == Lean witnesses)
```

### 4.1 Design Principles for External Adoption
- **Zero Runtime Dependencies (`0.00 USD`):** Core gates (`lattice.py`, `ast_guard.py`, `lean_hygiene.py`, `provenance.py`, `capability.py`) rely exclusively on Python standard library (`ast`, `hashlib`, `json`, `re`) and Init-only Lean 4.36.0 — requiring no LLM API keys and introducing sub-millisecond overhead.
- **Pluggable Cross-Family Referee Contract:** Rather than hard-coding a vendor, `referee.py` validates a typed JSON envelope `{model_family, verdict, counterexamples, evidence_sha256}` and fails closed if `referee.model_family == producer.model_family` or if the output is unparsed prose (`PROSE_AS_DONE`).
- **PostgreSQL 17 WORM Provenance Enforcement (`TASLAK_ONERI`):** Enforces `jsonb_typeof(git_shas) = 'object' AND git_shas <> '{}'::jsonb` on `verdict = 'PASS'` rows and stores `prev_chain_hash` / `chain_hash` so historical audit rows cannot be silently altered.

---

## 5. Experimental Benchmarks & Validation

All experiments were executed live in `isolated_python_sandbox` (`exit_code = 0`, cost `0.00 USD`, `0` `chr(36)` characters in outputs) on `2026-11-19`:
- **Run 1 (`v16_ufuk2_vitrin_proofgate_04_bench_v1`):** Exact N=531 live corpus replay, 106,200-evaluation latency benchmark, 10,000-trial PBT, 24-case AST-Safe benchmark, and initial Lean hygiene benchmark (`SHA-256` canonical matrix without timing: `c0e1b9f98336a170a3434fc025c0ac23f4ba6efb43101064b4ba1b52534fd7d4`).
- **Run 2 (`v16_ufuk2_vitrin_proofgate_04_bench_v2`):** Diagnostic run that isolated a real false-positive bug in the single-binder Lean regex (`FPR = 16.67%` on multi-variable binder `(p0 p1 q1 q2 : Nat)`).
- **Run 3 (`v16_ufuk2_vitrin_proofgate_04_bench_v3`):** Patched multi-binder Lean hygiene scanner (`[\(\{]\s*[\w\s]+:`) confirming `100.00% TPR` / `0.00% FPR` (`SHA-256` confusion matrix: `6db35a1053b2dd7d81841aa6741464d11c1d97ab418c5cf5d97d9b322e3266f6`).

### 5.1 Benchmark 1: Exact Live Replay on `audit_verdicts` (N=531)

We replayed the exact lossless 27-tuple defect distribution representing all **531 live rows** of `audit_verdicts` across four gate regimes:
- **`B0_SelfReport`:** Baseline without gate (accepts all agent self-reports).
- **`B1_LegacyLinear`:** Exact deployed additive Allean verdict (`puan >= 75 -> GECTI`).
- **`B2_ProofGate_Lex4Gate`:** Exact deployed PG17 operator `lexicographic_meta_audit_4gate_bps` (P0 non-compensatory veto `-25000 bps` for `EKSIK_DOSYA`, `TRIVIAL_ISPAT`, `KOPYA_CIKTI`; P1 weighted penalty for `KISA_CIKTI` `-3000`, `ANLIK_SURE` `-2000`, `KIP_KANITI_YOK` `-500`, `KIP_UYUSMAZ` `-200`; `GECTI iff >= 7500`).
- **`B3_ProofGate_Strict_All5`:** Full `inv13LexScore6Tier` policy escalating `ANLIK_SURE` and `KISA_CIKTI` into the hard-veto set alongside P0.

**Table 4: Catch Rate (Recall) & Wilson 95% CI Across All N=531 Live `audit_verdicts` Records**

| Defect Category (Live N) | `B0_SelfReport` Catch % | `B1_LegacyLinear` Catch % [95% CI] | `B2_ProofGate_Lex4Gate` Catch % [95% CI] | `B3_ProofGate_Strict_All5` Catch % [95% CI] | Gain (`B2` vs `B1`) |
|---|---:|---:|---:|---:|---:|
| `EKSIK_DOSYA` (N=91) | 0.00% (0/91) | 51.65% (47/91) [41.52, 61.64] | **100.00% (91/91)** [95.95, 100.00] | **100.00% (91/91)** [95.95, 100.00] | **+48.35 pp** |
| `TRIVIAL_ISPAT` (N=7) | 0.00% (0/7) | 28.57% (2/7) [8.22, 64.11] | **100.00% (7/7)** [64.57, 100.00] | **100.00% (7/7)** [64.57, 100.00] | **+71.43 pp** |
| `KOPYA_CIKTI` (N=15) | 0.00% (0/15) | 100.00% (15/15) [79.61, 100.00] | **100.00% (15/15)** [79.61, 100.00] | **100.00% (15/15)** [79.61, 100.00] | 0.00 pp |
| `KISA_CIKTI` (N=9) | 0.00% (0/9) | 100.00% (9/9) [70.09, 100.00] | **100.00% (9/9)** [70.09, 100.00] | **100.00% (9/9)** [70.09, 100.00] | 0.00 pp |
| `ANLIK_SURE` (N=14) | 0.00% (0/14) | 28.57% (4/14) [11.72, 54.65] | 28.57% (4/14) [11.72, 54.65] | **100.00% (14/14)** [78.47, 100.00] | +71.43 pp (`B3`) |
| **Strict P0 Composite (N=110)** | 0.00% (0/110) | 55.45% (61/110) [46.14, 64.40] | **100.00% (110/110)** [96.63, 100.00] | **100.00% (110/110)** [96.63, 100.00] | **+44.55 pp** |
| **Hard-5 Composite (N=129)** | 0.00% (0/129) | 54.26% (70/129) [45.67, 62.61] | **92.25% (119/129)** [86.32, 95.74] | **100.00% (129/129)** [97.11, 100.00] | **+37.99 pp / +45.74 pp** |

**Overall Verdict Shift Across N=531:**
- `B1_LegacyLinear`: `460 GECTI`, `71 NON_GECTI` (`1` hard `KALDI` veto).
- `B2_ProofGate_Lex4Gate`: `412 GECTI`, `119 NON_GECTI` (**110** hard `-25000 bps` P0 vetoes). Eliminates **49/49 (100.00%)** strict P0 false-green leaks (`44` `EKSIK_DOSYA` + `5` `TRIVIAL_ISPAT`).
- `B3_ProofGate_Strict_All5`: `402 GECTI`, `129 NON_GECTI` (**129** hard vetoes). Eliminates the remaining **10** standalone `ANLIK_SURE` timing-anomaly leaks (`-340 sn` negative-duration / clock-skew artifacts).

**Scoring Latency (200x Corpus Replay = 106,200 Evaluations of `lexicographic_meta_audit_4gate_bps`):**
- Total elapsed wall time: `0.2188 s`
- Throughput: **`485,295.2 ops/sec`**
- Latency percentiles: **P50 = `1.329 us`**, **P95 = `3.253 us`**, **P99 = `5.351 us`**

### 5.2 Benchmark 2: Property-Based Invariant Verification (10,000 Randomized Trials)

Executed with fixed seed `20261119` across `lexicographic_meta_audit_4gate_bps`, `konu3_inv12_capability_pceb_4gate_meta_audit_bps`, and `inv13_lex_score_6tier`:

| Invariant Property | Trials | Violations | Measured Pass Rate |
|---|---:|---:|---:|
| `INV-09` Non-Compensatory P0 Dominance (`P0 >= 1 => -25000 < clean`) | 10,000 | **0** | 100.00% |
| `INV-11` `PROSE_AS_DONE` & Same-Family Referee Rejection (`-22000`) | 10,000 | **0** | 100.00% |
| `INV-12` Capability Bitmask Soundness (`(req & tgt) != req => -24000`) | 10,000 | **0** | 100.00% |
| `INV-13` 6-Tier Strict Dominance (`any defect => score < clean`) | 10,000 | **0** | 100.00% |

### 5.3 Benchmark 3: Python AST-Safe Verifier Micro-Benchmark (N=24)

Evaluated `ProofGateASTVerifier` over 12 clean mathematical/gate operators (including the 3 KONU-3 PG17 operator kernels) and 12 adversarial bypass payloads (`eval`, `exec`, `__import__`, aliased `import os as harmless`, `from subprocess import run`, `open('/etc/hosts')`, `getattr` obfuscation, `().__class__.__mro__[1].__subclasses__()`, `globals()`, `while True`, `chr(36)` KURAL-3 violation, `compile`):

| Verifier Module | Clean (TN / FP) | Adversarial (TP / FN) | TPR | FPR | P50 Latency | P99 Latency |
|---|---:|---:|---:|---:|---:|---:|
| `ProofGateASTVerifier` (24 cases, 100x timed) | 12 / 0 | 12 / 0 | **100.00%** | **0.00%** | `98.96 us` | `479.78 us` |
| `ProofGateLeanHygieneScanner` v2 (pre-fix, 16 cases) | 5 / 1 | 10 / 0 | 100.00% | 16.67% | `38.49 us` | `153.08 us` |
| `ProofGateLeanHygieneScanner` v3 (multi-binder fix, 16 cases) | **6 / 0** | **10 / 0** | **100.00%** | **0.00%** | **`37.35 us`** | **`154.56 us`** |

**Methodological Note on v2 -> v3 Regression Discovery:** During live benchmarking, `v2` triggered a false positive (`TRIVIAL_ISPAT:2/3`) on clean theorem `theorem t1 (p0 p1 q1 q2 : Nat)` because its parameter regex matched only single-identifier binders `(\w+ :)`. Patching to multi-binder syntax `[\(\{]\s*[\w\s]+:` in `v3` eliminated the false positive (0/6 FP) while maintaining 10/10 TP across `sorry`, `admit`, custom `axiom`, `native_decide`, free-variable `decide`, `TRIVIAL_ISPAT` (`3/3` and `3/5`), missing `#print axioms`, and `chr(36)` leaks, and correctly ignoring `sorry`/`axiom`/`native_decide` inside `--` and `/- ... -/` comments.

---

<!-- BEGIN_PROOFGATE_README_RELATED_WORK -->
## 6. Related Work (IS-PG-01 Consolidated Literature)

ProofGate sits at the intersection of three verification pillars: **(1) cross-family AI referee panels with explicit fail-closed abstention**, **(2) sorry-free Lean 4 kernel checking (zero custom axioms, compiler-trust filtering, vacuity/triviality hygiene)**, and **(3) deterministic static AST code gating**. Prior work addresses these pillars individually, but no existing system unifies all three inside a single non-compensatory, fail-closed admission gate.

### 6.1 3-Pillar Architectural Comparison (Consolidated Canonical 8 Studies)

| System / Study (Year) | Cross-Family AI Judges | Sorry-Free Lean 4 Kernel Gate | Deterministic AST Code Gate | Verified Source |
| :--- | :--- | :--- | :--- | :--- |
| **Kohli (2026)** — *Nine Judges, Two Effective Votes* | Diagnostic only (`n_eff = 2.18` across 7 families) | No | No | [arXiv:2605.29800](https://arxiv.org/abs/2605.29800) |
| **Awuni et al. (2026)** — *Who Judges Matters* | Bias measurement (3.4–8.4 pp same-family lift) | No | No | [arXiv:2609.17857](https://arxiv.org/abs/2609.17857) |
| **Acharya et al. (2026)** — *RoPoLL* | Robust geometric-median jury (Huber contamination) | No | No | [arXiv:2606.30931](https://arxiv.org/abs/2606.30931) |
| **Badshah et al. (2026)** — *Judge, Retrieve, or Abstain* | Calibrated `ABSTAIN` + Clopper-Pearson FDR control | No | No | [arXiv:2608.17994](https://arxiv.org/abs/2608.17994) |
| **Agarwal (2026)** — *Refute-or-Promote* | Cross-model adversarial critique (79–83% FP kill) | No (empirical C/C++ unit tests) | No | [arXiv:2604.19049](https://arxiv.org/abs/2604.19049) |
| **Zhao et al. (2026)** — *Bias in the Loop* | SE judge audit across 12 injected biases (CodeJudgeBench) | No | No | [arXiv:2604.16790](https://arxiv.org/abs/2604.16790) |
| **Sankar et al. (2026)** — *LEANGUARD* | No (human-written policies) | Yes (fail-closed LeanLTL runtime policies) | No | [arXiv:2611.02332](https://arxiv.org/abs/2611.02332) |
| **Li et al. (2026)** — *Goedel-Code-Prover* | No (proof search over pre-formalized specs) | Yes (Lean 4 + `ofReduceBool`/`trustCompiler` filter) | No | [arXiv:2603.19329](https://arxiv.org/abs/2603.19329) |
| **AlpLab-ProofGate (2026)** | **Yes — family-disjoint quorum + fail-closed `ABSTAIN`** | **Yes — 0-sorry, `--trust=0`, axiom & triviality gate** | **Yes — 0-dep Python AST whitelist gate** | This repository |

### 6.2 Closest Studies & Differentiation

1. **Nine Judges, Two Effective Votes: Correlated Errors Undermine LLM Evaluation Panels** — Guneet Kohli (**2026**). [arXiv:2605.29800](https://arxiv.org/abs/2605.29800) | [DOI: 10.48550/arXiv.2605.29800](https://doi.org/10.48550/arXiv.2605.29800). Kohli (2026) demonstrates that a nine-model evaluation panel spanning seven distinct LLM families collapses to roughly two effective independent votes (`n_eff = 2.18`) due to correlated training and alignment blind spots without any formal verification barrier. ProofGate breaks this correlation ceiling by restricting cross-family LLM consensus to a typed semantic gate chained behind deterministic AST inspection and sorry-free Lean 4 kernel checking.
2. **Who Judges Matters: Measuring Family-Conditioned Preference in LLM-as-Judge Panels** — David Ababio Awuni, Luke E. K. Achenie, Benjamin Tei Partey, Elvis Gyasi Owusu, Nii-Nai Derrick Sowah (**2026**). [arXiv:2609.17857](https://arxiv.org/abs/2609.17857) | [DOI: 10.48550/arXiv.2609.17857](https://doi.org/10.48550/arXiv.2609.17857). Awuni et al. (2026) quantify a 3.4 to 8.4 percentage-point same-family preference lift and a 55.4% AB/BA position-reversal rate across open-weight judge panels in pairwise text scoring, mitigating bias via post-hoc statistical estimators. ProofGate eliminates intra-family favoritism and pairwise positional fragility structurally by enforcing family-disjoint categorical verdicts (`same_family_referee = 0`) backed by an order-invariant AST code inspector and a sorry-free Lean 4 compilation gate.
3. **RoPoLL: Robust Panel of LLM Judges** — Anish Acharya, Kris W. Pan, Brian Verkhovsky (**2026**). [arXiv:2606.30931](https://arxiv.org/abs/2606.30931) | [DOI: 10.48550/arXiv.2606.30931](https://doi.org/10.48550/arXiv.2606.30931). RoPoLL formalizes multi-LLM jury aggregation under Huber contamination and replaces mean pooling with a geometric median estimator achieving a 1/2 breakdown point against corrupted judges on continuous reward benchmarks. In contrast, ProofGate enforces a non-compensatory lexicographic lattice (`INV-09..INV-13`) where statistical consensus—even under geometric-median aggregation—can never override a deterministic AST policy violation or an unverified Lean 4 proof obligation.
4. **Judge, Retrieve, or Abstain: Uncertainty-Guarded LLM Judging with Provable Risk Guarantees** — Sher Badshah, Ali Emami, Hassan Sajjad (**2026**, COLM 2026). [arXiv:2608.17994](https://arxiv.org/abs/2608.17994) | [DOI: 10.48550/arXiv.2608.17994](https://doi.org/10.48550/arXiv.2608.17994). Badshah et al. (2026) bound false discovery rates for reference-free LLM judges in open-domain QA using finite-sample Clopper-Pearson intervals to route uncertain decisions to web retrieval or abstention. ProofGate adapts calibrated fail-closed abstention (`ABSTAIN`) to formal verification faithfulness, replacing noisy web retrieval with deterministic AST structural validation and sorry-free Lean 4 type-checking.
5. **Refute-or-Promote: An Adversarial Stage-Gated Multi-Agent Review Methodology for High-Precision LLM-Assisted Defect Discovery** — Abhinav Agarwal (**2026**). [arXiv:2604.19049](https://arxiv.org/abs/2604.19049) | [DOI: 10.48550/arXiv.2604.19049](https://doi.org/10.48550/arXiv.2604.19049). Refute-or-Promote pairs cross-model adversarial critique with mandatory empirical test execution to eliminate 79%–83% of false-positive C/C++ vulnerability reports, catching a non-existent OpenSSL padding oracle unanimously endorsed by ten LLM reviewers. ProofGate shares this fail-closed stage-gated design but upgrades the empirical test gate into a deductive Lean 4 kernel proof gate coupled with a static AST code gate and a typed cross-family referee contract.
6. **Bias in the Loop: Auditing LLM-as-a-Judge for Software Engineering** — Zixiao Zhao, Amirreza Esmaeili, Fatemeh Fard (**2026**). [arXiv:2604.16790](https://arxiv.org/abs/2604.16790) | [DOI: 10.48550/arXiv.2604.16790](https://doi.org/10.48550/arXiv.2604.16790). Zhao et al. (2026) audit code judges across 5,352 software-engineering pairs on CodeJudgeBench under 12 prompt-injected biases, showing that authority, sentiment, and verbosity cues flip pairwise verdicts and degrade format validity. ProofGate neutralizes prompt-level judge fragility by banning prose-only completions (`PROSE_AS_DONE`), isolating executable Python operators behind a zero-dependency AST whitelist, and requiring sorry-free Lean 4 kernel proofs for invariant admission.
7. **LEANGUARD: Lean-Verified Guardrails for Tool-Using Agents** — Sreehari Sankar, Debargha Ganguly, Vikash Singh, Mohsen Hariri, Weicong Chen (**2026**). [arXiv:2611.02332](https://arxiv.org/abs/2611.02332) | [DOI: 10.48550/arXiv.2611.02332](https://doi.org/10.48550/arXiv.2611.02332). LeanGuard intercepts runtime agent tool calls and checks them against human-authored past-time Linear Temporal Logic (`LeanLTL`) policies in Lean 4 with fail-closed execution. Whereas LeanGuard assumes the formal Lean 4 policy specification is already faithfully written by human engineers, ProofGate audits the autoformalization and code-admission boundary itself—combining cross-family AI referees, static Python AST gating, and sorry-free Lean 4 compilation.
8. **Goedel-Code-Prover: Hierarchical Proof Search for Open State-of-the-Art Code Verification** — Zenan Li, Ziran Yang, Deyuan He, Haoyu Zhao, Andrew Zhao, Shange Tang, Kaiyu Yang, Aarti Gupta, Zhendong Su, Chi Jin (**2026**). [arXiv:2603.19329](https://arxiv.org/abs/2603.19329) | [DOI: 10.48550/arXiv.2603.19329](https://doi.org/10.48550/arXiv.2603.19329). Goedel-Code-Prover introduces hierarchical recursive lemma decomposition with `quickcheck` filtering, reaching 62.0% prove success across 427 Lean 4 code verification benchmarks while filtering out unsound `Lean.ofReduceBool` and `Lean.trustCompiler` axiom bypasses. Unlike Goedel-Code-Prover, which synthesizes proofs for pre-formalized specifications without a runtime judge or Python safety layer, ProofGate embeds strict Lean 4 axiom and triviality hygiene inside a 4-gate fleet admission pipeline paired with Python AST whitelisting and cross-family AI referees.

*Companion Autoformalization & Consensus Cross-References (verified on arXiv, `V15-TUR-20261120225024-E57DCA`):* Mei & Douglas (2026), *Beyond LLM Judge: Mechanical Verification for Agentic Autoformalization* ([arXiv:2610.20573](https://arxiv.org/abs/2610.20573) | [DOI: 10.48550/arXiv.2610.20573](https://doi.org/10.48550/arXiv.2610.20573)); Poiroux, Weiss, Kunčak, Bosselut (2025, EMNLP 2025), *Reliable Evaluation and Benchmarks for Statement Autoformalization* (`ProofNetVerif` / `BEq+`, [arXiv:2406.07222](https://arxiv.org/abs/2406.07222) | [DOI: 10.48550/arXiv.2406.07222](https://doi.org/10.48550/arXiv.2406.07222)); Hossain, Yousefi, Lim (2026), *Agreement Overstates Evidence: Error Dependence in LLM Judge Consensus* ([arXiv:2609.22512](https://arxiv.org/abs/2609.22512)); Gui, Yang, Shi (2026), *Evaluating the Robustness of Proof Autoformalization in Lean 4* ([arXiv:2606.14867](https://arxiv.org/abs/2606.14867)).
<!-- END_PROOFGATE_README_RELATED_WORK -->

---

## 7. Limitations, Threats to Validity, and Immediate Engineering Roadmap

1. **Live Git Provenance Wiring (`git_shas`):** Although `INV-13` formally models `git_sha_count >= 1`, `1,546/1,546` (`100.00%`) live rows in `fleet_audit_runs` still record `{}`. Enabling host `git rev-parse HEAD` capture in `alplab-meta-auditor-v1` is required before activating the PG17 `CHECK` constraint on `verdict = 'PASS'`.
2. **Cross-Family Referee Coverage & Liveness:** Only `12/531` (`2.26%`) `audit_verdicts` records triggered a referee and only `1/531` (`0.19%`) recorded a completed `hakem_karar`, while `711/1,546` (`45.99%`) fleet audit runs reported `pending_cross_reviews > 0`. Enforcing fail-closed `INV-11` requires healthy cross-family referee throughput (e.g., Claude/Codex subscription queue SLA) to prevent liveness stalls.
3. **Host Lean 4.36.0 Compilation Gate:** `formal/Konu3MetaAuditInv09Inv12.lean` and `formal/Konu3MetaAuditInv13ProvenanceChain.lean` must be dispatched to a host AGY slot running Lean 4.36.0 (`lean --trust=0`, `lake build`, `lake env leanchecker`) to obtain machine-checked `RC=0` `.olean` SHA-256 certificates.
4. **Policy Calibration for `ANLIK_SURE`:** Under `B2` (`lexicographic_meta_audit_4gate_bps`), standalone `ANLIK_SURE` (`-2000 bps` -> `8000 >= 7500`) still passes unless paired with another defect (`10/14` leaked), whereas `B3` achieves `14/14` (`100.00%`) catch. Production operators must distinguish benign cached fast-paths from clock-skew / negative-duration anomalies (`-340 sn`) by splitting `ANLIK_SURE` into `NEGATIVE_DURATION_P0` (hard veto) vs `FAST_EXEC_WARN_P1`.

---

## 8. Reproducibility & Verification Manifest

| Verification Artifact | Source / Job ID | Result | Cost |
|---|---|---|---|
| Live PG17 `audit_verdicts` | `postgres_sql` (`N=531`) | 91 `EKSIK_DOSYA`, 7 `TRIVIAL_ISPAT`, 15 `KOPYA`, 9 `KISA`, 14 `ANLIK` | `0.00 USD` |
| Live PG17 `fleet_audit_runs` | `postgres_sql` (`N=1,546`) | 988 FAIL, 479 PASS, 79 WARN; 1,546 empty `git_shas`; 74 unverified-DONE runs (690 events) | `0.00 USD` |
| Live PG17 `verified_operators` | `postgres_sql` (`N=49`) | 49/49 `verified=true`, 0 unsafe imports/builtins, 0 `chr(36)`, 95,786 B | `0.00 USD` |
| Sandbox Replay + PBT + AST Bench | `isolated_python_sandbox` (`v16_ufuk2_vitrin_proofgate_04_bench_v1`) | `exit_code=0`, `485,295.2 ops/s`, 0/10,000 PBT violations, AST 12/12 TP 0/12 FP | `0.00 USD` |
| Sandbox Lean Hygiene Bench (patched) | `isolated_python_sandbox` (`v16_ufuk2_vitrin_proofgate_04_bench_v3`) | `exit_code=0`, 10/10 TP, 0/6 FP, P50 `37.35 us`, P99 `154.56 us` | `0.00 USD` |
| IS-PG-01 Related Work & BibTeX Merge | `isolated_python_sandbox` (`k1_is_pg_01_paper_readme_merge_audit_20261121`) + `tools/proofgate_merge_related_work_is_pg_01.py` | 8/8 canonical arXiv + DOI + BibTeX verified; 9/9 paper & README merge/idempotency/fail-closed unit tests PASS; `0` `chr(36)` | `0.00 USD` |
| Written Report Artifact | `workspace_artifact_writer` (`reports/VITRIN_02_PROOFGATE_PAPER.md`) | Updated on disk with Section 6 Related Work & Section 9 BibTeX; `0` `chr(36)` characters | `0.00 USD` |

---

<!-- BEGIN_PROOFGATE_BIBTEX -->
## 9. BibTeX Bibliography (Canonical 8 Studies — IS-PG-01)

```bibtex
@misc{kohli2026nine,
  title         = {Nine Judges, Two Effective Votes: Correlated Errors Undermine LLM Evaluation Panels},
  author        = {Kohli, Guneet},
  year          = {2026},
  eprint        = {2605.29800},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2605.29800},
  url           = {https://arxiv.org/abs/2605.29800}
}

@misc{awuni2026whojudges,
  title         = {Who Judges Matters: Measuring Family-Conditioned Preference in LLM-as-Judge Panels},
  author        = {Awuni, David Ababio and Achenie, Luke E. K. and Partey, Benjamin Tei and Owusu, Elvis Gyasi and Sowah, Nii-Nai Derrick},
  year          = {2026},
  eprint        = {2609.17857},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2609.17857},
  url           = {https://arxiv.org/abs/2609.17857}
}

@misc{acharya2026ropoll,
  title         = {RoPoLL: Robust Panel of LLM Judges},
  author        = {Acharya, Anish and Pan, Kris W. and Verkhovsky, Brian},
  year          = {2026},
  eprint        = {2606.30931},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2606.30931},
  url           = {https://arxiv.org/abs/2606.30931}
}

@inproceedings{badshah2026judge,
  title         = {Judge, Retrieve, or Abstain: Uncertainty-Guarded LLM Judging with Provable Risk Guarantees},
  author        = {Badshah, Sher and Emami, Ali and Sajjad, Hassan},
  booktitle     = {Conference on Language Modeling (COLM)},
  year          = {2026},
  eprint        = {2608.17994},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2608.17994},
  url           = {https://arxiv.org/abs/2608.17994}
}

@misc{agarwal2026refute,
  title         = {Refute-or-Promote: An Adversarial Stage-Gated Multi-Agent Review Methodology for High-Precision LLM-Assisted Defect Discovery},
  author        = {Agarwal, Abhinav},
  year          = {2026},
  eprint        = {2604.19049},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2604.19049},
  url           = {https://arxiv.org/abs/2604.19049}
}

@misc{zhao2026bias,
  title         = {Bias in the Loop: Auditing LLM-as-a-Judge for Software Engineering},
  author        = {Zhao, Zixiao and Esmaeili, Amirreza and Fard, Fatemeh},
  year          = {2026},
  eprint        = {2604.16790},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2604.16790},
  url           = {https://arxiv.org/abs/2604.16790}
}

@misc{sankar2026leanguard,
  title         = {LEANGUARD: Lean-Verified Guardrails for Tool-Using Agents},
  author        = {Sankar, Sreehari and Ganguly, Debargha and Singh, Vikash and Hariri, Mohsen and Chen, Weicong},
  year          = {2026},
  eprint        = {2611.02332},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2611.02332},
  url           = {https://arxiv.org/abs/2611.02332}
}

@misc{li2026goedelcodeprover,
  title         = {Goedel-Code-Prover: Hierarchical Proof Search for Open State-of-the-Art Code Verification},
  author        = {Li, Zenan and Yang, Ziran and He, Deyuan and Zhao, Haoyu and Zhao, Andrew and Tang, Shange and Yang, Kaiyu and Gupta, Aarti and Su, Zhendong and Jin, Chi},
  year          = {2026},
  eprint        = {2603.19329},
  archivePrefix = {arXiv},
  doi           = {10.48550/arXiv.2603.19329},
  url           = {https://arxiv.org/abs/2603.19329}
}
```
<!-- END_PROOFGATE_BIBTEX -->

---

## 10. ProofGate v1.0.0 ("Omni-Gate") Production Release Architecture & Verified Metrics

Building directly on the empirical PG17 audit findings and non-compensatory formalization in Sections 1–9, **ProofGate v1.0.0 ("Omni-Gate")** consolidates every verification layer into a zero-external-dependency Python 3.10+ standard-library package (`pyproject.toml` `version = "1.0.0"`) backed by Pure-Init Lean 4.36.0 soundness proofs (`formal/ProofGateV1OmniGateSoundness.lean`, `16` public theorems).

### 10.1 Production Capabilities Added in `v1.0.0`

| Subsystem | Module | Key Standards & Invariants Enforced |
|---|---|---|
| **SARIF v2.1.0 Exporter** | `proofgate/sarif_export.py` | GitHub Code Scanning / VS Code SARIF v2.1.0 (`PG-LEAN-*`, `PG-AST-*`, `PG-DIFF-*`, `PG-EVAL-*`), BMP/SMP UTF-16 `char_utf16` offsets, deterministic SHA-256 `partialFingerprints`. |
| **Strict JCS & RFC 6962 Log** | `proofgate/muhur_rfc6962.py` | Strict RFC 8785 JCS (UTF-16-BE key sorting, `-0.0 -> 0`, `NaN`/`Infinity` rejection) + RFC 6962 `0x00`/`0x01` Merkle tree with both inclusion (`audit_path`) and append-only consistency (`consistency_proof(m, n)`). |
| **SLSA v1.0 & DSSEv1 PAE** | `proofgate/slsa_provenance.py` | in-toto Statement v1 + SLSA Provenance v1.0 predicate + DSSEv1 PAE (`DSSEv1 len(type) type len(body) body`) constant-time HMAC-SHA256 signing & fail-closed subject/builder verification. |
| **Lean 4 Gate & Vacuity** | `proofgate/lean_gate.py` | Offset-preserving nested-comment/raw-string/`s!"..."` lexer, kernel bypass detectors (`debug.skipKernelTC`, `Meta.mkSorry`, `addDecl`/`axiomDecl`, `Lean.ofReduceBool`, `Lean.trustCompiler`), `set_option autoImplicit false`, `#print axioms` `cov_bps`, and interval/propositional vacuity detection. |
| **Lean PR Spec Diff Gate** | `proofgate/diff_gate.py` | Alpha-normalizes bound variables and `∀`/`→` forms across revisions to permit safe namespace moves and alpha-renames while rejecting dropped public theorems and mutated statements. |
| **Agent Trajectory Evaluator** | `proofgate/agent_eval.py` | Non-compensatory 4-gate (`-26000..10000 bps`) & 6-tier (`<= 10004` vs `>= 10005`) lattices, Wilson 95% lower confidence bound (`wilson_lcb_bps`), sequential `PageCusumDetector` quarantine, JUnit XML & Promptfoo v3 JSON export. |
| **Unified CLI & Web Studio** | `proofgate/cli.py`, `docs/index.html` | 6 CLI subcommands (`check-lean`, `check-ast`, `diff-lean`, `merkle-root`, `slsa-attest`, `eval-agents`) with `--format json|sarif|junit|promptfoo`, plus hash-pinned Strict-CSP3 client-side WebCrypto studio. |

### 10.2 Measured Verification Evidence (`v1.0.0`)

1. **Pure-Init Lean 4.36.0 Kernel (`formal/ProofGateV1OmniGateSoundness.lean`):**
   - `lean -M 1024 -j 1 --trust=0 -DwarningAsError=true formal/ProofGateV1OmniGateSoundness.lean`: **exit `0`**, `16/16` public theorems verified with zero custom axioms and `0` incomplete proofs (`[]`, `[propext]`, `[propext, Quot.sound]`).
   - `proofgate_v61_unified_meta_gate.py`: **`all_passed = true`**, **`score = 20000`**, **`cov_bps = 10000`**, `0` findings (`cost_usd = "0.0000 USD"`).
2. **Python Automated Suite (`python3 -W error::DeprecationWarning -m unittest discover -s tests -v`):**
   - **`38/38` tests PASS** (`0` failures, `0` warnings under `-W error::DeprecationWarning`), covering 2,000-trial lexicographic lattice PBT, 500-trial Merkle inclusion/consistency PBT, exhaustive `(0 <= m <= n <= 16)` consistency matrix, strict RFC 8785 JCS + DSSE/SLSA tamper tests, Lean vacuity & alpha-diff adversarial cases, Strict-CSP3 HTML hash validation, and repository-wide `chr(36) == 0` KURAL-3 enforcement.

