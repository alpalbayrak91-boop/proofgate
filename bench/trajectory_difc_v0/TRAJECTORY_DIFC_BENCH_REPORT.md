# ProofGate v2.0.0 Layer 6 — AgentTrajectoryBench-120 Benchmark Report

- **Benchmark Suite:** `AgentTrajectoryBench-120` (`bench/trajectory_difc_v0/run_benchmark.py`)
- **Dataset Size:** `120` multi-step trajectories (`60` benign workflows + `60` adversarial multi-step attacks, `384` total tool steps)
- **Runtime Cost:** `0.00 USD` (100% deterministic offline Python 3.10+ stdlib)
- **Formal Backing:** Machine-checked in Pure-Init Lean 4 (`formal/ProofGateTrajectoryDIFC.lean`, `lean --trust=0 -DwarningAsError=true`, `18` public theorems, `0` custom axioms, `10000 bps` substance)

## Aggregate Detection & Latency Comparison

| Verifier Architecture | Adversarial Caught (`TP / 60`) | Attack TPR (Wilson 95% CI) | Benign False Alarms (`FP / 60`) | Benign FPR (Wilson 95% CI) | P50 Latency (`us`) | P99 Latency (`us`) | Throughput (`traj/s`) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Stateless Single-Step Filter Baseline | `4 / 60` | `6.67%` `[2.62%, 15.93%]` | `0 / 60` | `0.00%` `[0.00%, 6.02%]` | `89.19` | `1805.64` | `7065.2` |
| **ProofGate v2.0.0 `TrajectoryDIFCGate`** | **`60 / 60`** | **`100.00%`** `[93.98%, 100.00%]` | **`0 / 60`** | **`0.00%`** `[0.00%, 6.02%]` | `1230.14` | `6889.44` | `648.5` |

## Per-Family Breakdown (6 Benign Categories + 6 Adversarial Attack Families)

| Trajectory Family | Ground Truth | N | Stateless Rejected | ProofGate v2.0.0 Rejected | Triggered ProofGate SARIF Rules |
| :--- | :--- | ---: | ---: | ---: | :--- |
| `B1_public_web_digest` | `BENIGN` | 10 | 0/10 | **0/10** | — |
| `B2_user_explicit_repo_ci` | `BENIGN` | 10 | 0/10 | **0/10** | — |
| `B3_human_endorsed_declassification` | `BENIGN` | 10 | 0/10 | **0/10** | — |
| `B4_human_endorsed_biba_mutation` | `BENIGN` | 10 | 0/10 | **0/10** | — |
| `B5_attenuated_readonly_subagent` | `BENIGN` | 10 | 0/10 | **0/10** | — |
| `B6_trusted_schema_epoch_upgrade` | `BENIGN` | 10 | 0/10 | **0/10** | — |
| `A1_camel_indirect_prompt_injection_exfil` | `ADVERSARIAL` | 10 | 2/10 | **10/10** | `PG-TRAJ-001` (10) |
| `A2_four_hop_scratchpad_taint_laundering` | `ADVERSARIAL` | 10 | 0/10 | **10/10** | `PG-TRAJ-001` (10) |
| `A3_covert_markdown_and_dns_exfil` | `ADVERSARIAL` | 10 | 0/10 | **10/10** | `PG-TRAJ-001` (10) |
| `A4_biba_confused_deputy_mutation` | `ADVERSARIAL` | 10 | 2/10 | **10/10** | `PG-TRAJ-002` (10) |
| `A5_mid_session_mcp_schema_rugpull` | `ADVERSARIAL` | 10 | 0/10 | **10/10** | `PG-TRAJ-004` (10) |
| `A6_macaroon_tampering_and_horizon_budget` | `ADVERSARIAL` | 10 | 0/10 | **10/10** | `PG-TRAJ-003` (8), `PG-TRAJ-005` (2) |

## Why Stateless Guardrails Fail on Multi-Step Agent Trajectories

1. **Cross-Step Lethal Trifecta & 4-Hop Scratchpad Laundering (`PG-TRAJ-001`):** In `A1` and `A2`, secret ingestion (`SECRET_ENV`, `CREDENTIAL_STORE`, `PRIVATE_REPO`, `PII_RECORD`, `FINANCIAL_LEDGER`), untrusted external prompt ingestion (`UNTRUSTED_EXTERNAL`), and outbound network transmission occur on distinct steps or across `context_isolation_reset` sub-agent boundaries via intermediate `scratchpad://` artifacts. Stateless per-step filters see only benign-looking individual calls (`8/10` missed in `A1`, `10/10` missed in `A2`), whereas `TrajectoryDIFCGate` propagates `(secrecy_join, integrity_meet)` monotonically across both ambient context and storage channels (`10/10` caught in both, while permitting `10/10` cryptographically endorsed human declassifications in `B3`).
2. **Covert Markdown Image & Untrusted DNS Sinks (`PG-TRAJ-001`):** In `A3`, exfiltration occurs via rendered Markdown external image tags or subdomain DNS queries (`0/10` caught by stateless baseline vs `10/10` caught by `TrajectoryDIFCGate`).
3. **Biba Confused-Deputy CI/IAM/Deploy Mutations (`PG-TRAJ-002`):** In `A4`, untrusted PR comments or unverified external feeds drive `.github/workflows/*.yml` edits, IAM updates, payment transfers, or deployments (`2/10` blatant shell payloads caught by stateless regex vs `10/10` caught by Biba integrity meet `< USER_EXPLICIT`, with `0/10` false positives on user-explicit CI updates in `B2` and endorsed deploys in `B4`).
4. **Mid-Session MCP Tool-Description Rug-Pulls (`PG-TRAJ-004`):** In `A5`, a remote MCP server mutates its tool description after initial approval (`0/10` caught by stateless inspection vs `10/10` caught by RFC 8785 JCS SHA-256 schema epoch pinning, while allowing `10/10` `TRUSTED_SYSTEM` epoch bumps in `B6`).
5. **Macaroon Capability Tampering & Horizon Budget Salami-Slicing (`PG-TRAJ-003`, `PG-TRAJ-005`):** In `A6`, HMAC caveat stripping, ancestor token rollback, POSIX `..` path traversal, domain suffix spoofing, and multi-step cumulative byte/risk overruns are all caught (`10/10` vs `0/10` stateless).

## Reproducibility

```bash
python3 bench/trajectory_difc_v0/run_benchmark.py
```
