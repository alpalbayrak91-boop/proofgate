# ProofGate Gate 2.9: Claim-Obligation-Certificate (COC), Swarm Quarantine & Vendi VS_2/VAS_2

**AWS-OSS-NOV30-2026 Showcase Module** (Requested Credit: `1000.00 USD`, 80% Lock Cap: `800.00 USD`, Runtime Software Cost: `0.00 USD`, MIT License, Zero External Dependencies).

## Core Capabilities (`proofgate check-g29-claimcert`)

1. **Claim-Obligation-Certificate (COC) DAG Verifier & Zero-Leak Swarm Quarantine**
   - Monotone IFC taint lattice (`0=CLEAN .. 4=KERNEL_ESCAPE`, fail-closed on out-of-range, `bool`, and `int` subclasses) propagates taint across claim dependency graphs.
   - Rejected claims and their downstream dependents are redacted before swarm broadcast (`raw_leak_detected=false`, `broadcast_contagion_risk_bps=0`) and sealed under an RFC 6962 SHA-256 Merkle root.
2. **True Scope-Stack De Bruijn + Signed Bellman-Ford DBM Auditor**
   - Detects `sorry`/`admit`, custom `axiom`, `native_decide`/`bv_decide`/`lcProof`, `@[extern]`/`@[implemented_by]`, negative-weight DBM hypothesis cycles, unguarded or shadowed `/`, `Real.log`, `tsum`, `Polynomial.natDegree`/`leadingCoeff`, and `Nat` monus (`0 - a`, `a - b`).
3. **Pre-Training Loophole Exposure Predictor (`Exposure = Propensity * EscapeRate`)**
   - Ranks exploit families by exposure and confirms zero residual exposure once gate rules close escape paths.
4. **Zero-Preserving Canonical AST Vendi `VS_2` & Exact `O(N)` `VAS_2`**
   - Alpha-normalizes binders, inlines immutable temps, simplifies algebraic identities, and strips post-return unreachable dead code (`G29-D11` closure: collapses post-return clone inflation from `1.604414` to exact `1.000000`).
   - Canonical clean 5-operator portfolio achieves `VS_2 = 4.000073` (`>= 3.0`) with `vas2_max_diff = 0.0`.
5. **Pure-Init Lean 4 Soundness Proof (`formal/ProofGateG29ClaimCertExposureQuarantineSoundness.lean`)**
   - Machine-checked on Lean 4 with `set_option warningAsError true`, `0 sorry`, `0` custom axioms, and `10/10` clean `#print axioms` checks (`exit_code=0`, empty `stderr`).

## CLI Quickstart

```bash
python3 -m proofgate.cli check-g29-claimcert --self-test --format json
python3 -m proofgate.cli check-g29-claimcert --quarantine-demo --format sarif --sarif-out g29_demo.sarif
python3 -W error::DeprecationWarning -m unittest discover -s tests -v
```
