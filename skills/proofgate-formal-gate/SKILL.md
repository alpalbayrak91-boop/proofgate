---
name: proofgate-formal-gate
description: Fail-closed Lean 4 kernel (--trust=0) and AST spec-diff verification skill preventing AI reward hacking, theorem weakening, concrete-type local instance shadowing, and axiom smuggling. Standardized for Agentic AI Foundation (agentskills.io).
---
# ProofGate Formal Verification Gate

Use this skill whenever verifying LLM-generated Lean 4 proofs or formal software specifications.

## Mandatory Checks
1. **Spec-Diff Reward-Hacking Gate (`proofgate/spec_diff_reward_hack_gate.py`)**: Compare baseline specification against candidate proof to ensure zero target `def` stubbing, zero domain narrowing, zero concrete-type local instance shadowing (`[Add Nat]`), and zero escape tokens (`sorry`, `axiom`, `implemented_by`, `extern`).
2. **Kernel Environment Gate (`lean --trust=0` + `KernelEnvSnapshot`)**: Verify `collectAxioms` contains only `[propext, Classical.choice, Quot.sound]` and zero non-canonical typeclass constructors (`HAdd.mk`).
