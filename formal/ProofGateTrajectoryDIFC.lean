-- SPDX-License-Identifier: MIT
-- ProofGate v2.0.0 Layer 6 — Pure-Init Lean 4 Formal Soundness of Trajectory DIFC & Macaroons
-- Grounded in:
--   * Denning (1976), A Lattice Model of Secure Information Flow, CACM 19(5)
--   * Biba (1977), Integrity Considerations for Secure Computer Systems, ESD-TR-76-372
--   * Myers & Liskov (1997), A Decentralized Model for Information Flow Control, SOSP '97
--   * Birgisson et al. (2014), Macaroons: Cookies with Contextual Caveats, NDSS 2014
--   * Debenedetti et al. (2025), Defeating Prompt Injections by Design (CaMeL), arXiv:2503.18813
-- Pure Lean 4 Init only: zero external imports, zero incomplete proofs, zero Classical.choice.

set_option warningAsError true
set_option autoImplicit false

namespace ProofGate.TrajectoryDIFC

-- ============================================================================
-- 1. Security Lattice Primitives (Secrecy Join |||, Integrity Meet min, Macaroons &&&)
-- ============================================================================

/-- Biba integrity level constants: UNTRUSTED_EXTERNAL (0) < VERIFIED_TOOL (1)
    < USER_EXPLICIT (2) < TRUSTED_SYSTEM (3). -/
def untrustedExternal : Nat := 0
def verifiedTool      : Nat := 1
def userExplicit      : Nat := 2
def trustedSystem     : Nat := 3

/-- Meet operator on the total-order integrity lattice. -/
def integrityMeet (a b : Nat) : Nat := min a b

/-- Test whether a capability scope bit is enabled in a Macaroon scope bitmask. -/
def hasScope (mask scopeBit : Nat) : Bool := mask.testBit scopeBit

/-- Sequential Macaroon contextual caveat attenuation across an arbitrary chain of masks. -/
def attenuateChain : Nat → List Nat → Nat
  | acc, [] => acc
  | acc, c :: cs => attenuateChain (acc &&& c) cs

-- ============================================================================
-- 2. Multi-Step Agent Trajectory Semantics & Deterministic DIFC Gate
-- ============================================================================

/-- Classification of tool invocations within an autonomous agent trajectory. -/
inductive ActionKind where
  | benignOp              : ActionKind
  | externalSink          : ActionKind
  | highIntegrityMutation : ActionKind
  deriving DecidableEq, Repr

/-- Deterministic rejection codes corresponding to PG-TRAJ-001 .. PG-TRAJ-005. -/
inductive RejectCode where
  | lethalTrifectaExfil           : RejectCode
  | bibaConfusedDeputy            : RejectCode
  | macaroonCapabilityViolation   : RejectCode
  | midTrajectorySchemaRugpull    : RejectCode
  | knapsackHorizonBudgetExceeded : RejectCode
  deriving DecidableEq, Repr

/-- Product security lattice state carried across multi-step execution. -/
structure TrajState where
  secrecy        : Nat
  integrity      : Nat
  macaroonScopes : Nat
  cumulativeCost : Nat
  budgetLimit    : Nat
  deriving DecidableEq, Repr

/-- Single tool-invocation transition descriptor in an agent trajectory. -/
structure Step where
  action            : ActionKind
  addedSecrecy      : Nat
  inputIntegrity    : Nat
  caveatMask        : Nat
  hasCaveat         : Bool
  requiredScopeBit  : Nat
  requiresScope     : Bool
  schemaChanged     : Bool
  trustedEpochBump  : Bool
  endorsedTrifecta  : Bool
  endorsedBiba      : Bool
  costDelta         : Nat
  deriving DecidableEq, Repr

/-- Outcome of evaluating a single step or an entire multi-step trajectory. -/
inductive GateOutcome where
  | accept (finalState : TrajState) : GateOutcome
  | reject (code : RejectCode)      : GateOutcome
  deriving DecidableEq, Repr

/-- Pure lattice state evolution for a single step (secrecy join, integrity meet, Macaroon &&&). -/
def advanceState (s : TrajState) (st : Step) : TrajState :=
  { secrecy        := s.secrecy ||| st.addedSecrecy
  , integrity      := integrityMeet s.integrity st.inputIntegrity
  , macaroonScopes := if st.hasCaveat then (s.macaroonScopes &&& st.caveatMask) else s.macaroonScopes
  , cumulativeCost := s.cumulativeCost + st.costDelta
  , budgetLimit    := s.budgetLimit
  }

/-- Unconditional multi-step lattice state folding over an arbitrary trajectory. -/
def runSteps : TrajState → List Step → TrajState
  | s, [] => s
  | s, st :: rest => runSteps (advanceState s st) rest

/-- Fail-closed Layer 6 trajectory step evaluator enforcing PG-TRAJ-001 .. PG-TRAJ-005. -/
def evalStep (s : TrajState) (st : Step) : GateOutcome :=
  let s' := advanceState s st
  if st.schemaChanged && !st.trustedEpochBump then
    GateOutcome.reject RejectCode.midTrajectorySchemaRugpull
  else if st.requiresScope && !(hasScope s'.macaroonScopes st.requiredScopeBit) then
    GateOutcome.reject RejectCode.macaroonCapabilityViolation
  else if (st.action == ActionKind.externalSink) &&
          decide (0 < s'.secrecy) &&
          decide (s'.integrity ≤ untrustedExternal) &&
          !st.endorsedTrifecta then
    GateOutcome.reject RejectCode.lethalTrifectaExfil
  else if (st.action == ActionKind.highIntegrityMutation) &&
          decide (s'.integrity < userExplicit) &&
          !st.endorsedBiba then
    GateOutcome.reject RejectCode.bibaConfusedDeputy
  else if decide (s'.budgetLimit < s'.cumulativeCost) then
    GateOutcome.reject RejectCode.knapsackHorizonBudgetExceeded
  else
    GateOutcome.accept s'

/-- Multi-step trajectory verifier folding `evalStep` fail-closed across `List Step`. -/
def evalTrajectory : TrajState → List Step → GateOutcome
  | s, [] => GateOutcome.accept s
  | s, st :: rest =>
    match evalStep s st with
    | GateOutcome.accept s1 => evalTrajectory s1 rest
    | GateOutcome.reject c  => GateOutcome.reject c

/-- Stepwise safety invariant holding at every transition along a trajectory from `s`. -/
def TrajectoryStepwiseSafe : TrajState → List Step → Prop
  | _, [] => True
  | s, st :: rest =>
    let s' := advanceState s st
    ((st.schemaChanged = true) → st.trustedEpochBump = true) ∧
    ((st.requiresScope = true) → hasScope s'.macaroonScopes st.requiredScopeBit = true) ∧
    ((st.action = ActionKind.externalSink ∧ 0 < s'.secrecy ∧ s'.integrity ≤ untrustedExternal) →
      st.endorsedTrifecta = true) ∧
    ((st.action = ActionKind.highIntegrityMutation ∧ s'.integrity < userExplicit) →
      st.endorsedBiba = true) ∧
    (s'.cumulativeCost ≤ s'.budgetLimit) ∧
    TrajectoryStepwiseSafe s' rest

-- ============================================================================
-- 3. Stateless Single-Step Guardrail Baseline & 3-Step Split-Exfil Construction
-- ============================================================================

/-- Memoryless per-step filter inspecting each `Step` in isolation without cross-step taint state. -/
def statelessStepOk (st : Step) : Bool :=
  let sameStepTrifecta :=
    (st.action == ActionKind.externalSink) &&
    decide (0 < st.addedSecrecy) &&
    decide (st.inputIntegrity ≤ untrustedExternal) &&
    !st.endorsedTrifecta
  let sameStepRugpull := st.schemaChanged && !st.trustedEpochBump
  !sameStepTrifecta && !sameStepRugpull && decide (st.costDelta ≤ 100)

/-- Stateless trajectory evaluation: conjunction of isolated single-step checks. -/
def evalStatelessTrajectory (tr : List Step) : Bool :=
  tr.all statelessStepOk

/-- Clean initial trajectory state at USER_EXPLICIT integrity with full scope bitmask `7`. -/
def initCleanState (budget : Nat) : TrajState :=
  { secrecy        := 0
  , integrity      := userExplicit
  , macaroonScopes := 7
  , cumulativeCost := 0
  , budgetLimit    := budget
  }

/-- Canonical 3-step split-exfiltration trajectory parameterized over any secret bitmask:
    Step 0 reads private secret under USER_EXPLICIT integrity;
    Step 1 ingests untrusted external data (dropping integrity to UNTRUSTED_EXTERNAL);
    Step 2 invokes an unendorsed external sink carrying zero new step-local secret flags. -/
def splitExfilAttack (secretMask : Nat) : List Step :=
  [ { action           := ActionKind.benignOp
    , addedSecrecy     := secretMask
    , inputIntegrity   := userExplicit
    , caveatMask       := 7
    , hasCaveat        := false
    , requiredScopeBit := 0
    , requiresScope    := true
    , schemaChanged    := false
    , trustedEpochBump := false
    , endorsedTrifecta := false
    , endorsedBiba     := false
    , costDelta        := 1
    }
  , { action           := ActionKind.benignOp
    , addedSecrecy     := 0
    , inputIntegrity   := untrustedExternal
    , caveatMask       := 7
    , hasCaveat        := false
    , requiredScopeBit := 0
    , requiresScope    := true
    , schemaChanged    := false
    , trustedEpochBump := false
    , endorsedTrifecta := false
    , endorsedBiba     := false
    , costDelta        := 1
    }
  , { action           := ActionKind.externalSink
    , addedSecrecy     := 0
    , inputIntegrity   := userExplicit
    , caveatMask       := 7
    , hasCaveat        := false
    , requiredScopeBit := 1
    , requiresScope    := true
    , schemaChanged    := false
    , trustedEpochBump := false
    , endorsedTrifecta := false
    , endorsedBiba     := false
    , costDelta        := 1
    }
  ]

-- ============================================================================
-- Internal Structural Lemmas
-- ============================================================================

private theorem evalStep_accept_invariants (s s1 : TrajState) (st : Step)
    (hAcc : evalStep s st = GateOutcome.accept s1) :
    s1 = advanceState s st ∧
    ((st.schemaChanged = true) → st.trustedEpochBump = true) ∧
    ((st.requiresScope = true) → hasScope (advanceState s st).macaroonScopes st.requiredScopeBit = true) ∧
    ((st.action = ActionKind.externalSink ∧
      0 < (advanceState s st).secrecy ∧
      (advanceState s st).integrity ≤ untrustedExternal) →
      st.endorsedTrifecta = true) ∧
    ((st.action = ActionKind.highIntegrityMutation ∧
      (advanceState s st).integrity < userExplicit) →
      st.endorsedBiba = true) ∧
    ((advanceState s st).cumulativeCost ≤ (advanceState s st).budgetLimit) := by
  unfold evalStep at hAcc
  dsimp only at hAcc
  split at hAcc
  · contradiction
  · rename_i hNotSchema
    split at hAcc
    · contradiction
    · rename_i hNotMac
      split at hAcc
      · contradiction
      · rename_i hNotTri
        split at hAcc
        · contradiction
        · rename_i hNotBiba
          split at hAcc
          · contradiction
          · rename_i hNotBud
            injection hAcc with hStateEq
            refine ⟨hStateEq.symm, ?_, ?_, ?_, ?_, ?_⟩
            · intro hSc
              cases hBump : st.trustedEpochBump
              · exfalso
                apply hNotSchema
                simp [hSc, hBump]
              · rfl
            · intro hReq
              cases hHas : hasScope (advanceState s st).macaroonScopes st.requiredScopeBit
              · exfalso
                apply hNotMac
                simp [hReq, hHas]
              · rfl
            · rintro ⟨hAct, hSec, hInt⟩
              cases hEnd : st.endorsedTrifecta
              · exfalso
                apply hNotTri
                simp [hAct, hSec, hInt, hEnd]
              · rfl
            · rintro ⟨hAct, hInt⟩
              cases hEndB : st.endorsedBiba
              · exfalso
                apply hNotBiba
                simp [hAct, hInt, hEndB]
              · rfl
            · exact Nat.not_lt.mp (by simpa using hNotBud)

private theorem runSteps_append (s : TrajState) (xs ys : List Step) :
    runSteps s (xs ++ ys) = runSteps (runSteps s xs) ys := by
  induction xs generalizing s with
  | nil => rfl
  | cons hd tl ih =>
    simp [List.cons_append, runSteps, ih]

private theorem evalTrajectory_split_accept (xs ys : List Step) (s0 sFinal : TrajState)
    (hAcc : evalTrajectory s0 (xs ++ ys) = GateOutcome.accept sFinal) :
    evalTrajectory s0 xs = GateOutcome.accept (runSteps s0 xs) ∧
    evalTrajectory (runSteps s0 xs) ys = GateOutcome.accept sFinal := by
  induction xs generalizing s0 with
  | nil =>
    exact ⟨rfl, hAcc⟩
  | cons hd tl ih =>
    simp only [List.cons_append, evalTrajectory] at hAcc
    cases hStep : evalStep s0 hd with
    | reject c =>
      rw [hStep] at hAcc
      contradiction
    | accept s1 =>
      rw [hStep] at hAcc
      have hInv := (evalStep_accept_invariants s0 s1 hd hStep).1
      subst hInv
      have hSub := ih (advanceState s0 hd) hAcc
      simp only [evalTrajectory, hStep, runSteps]
      exact hSub

-- ============================================================================
-- 18 Substantive Public Theorems (0 incomplete proofs, 0 Classical.choice, 10000 bps)
-- ============================================================================

/-- Theorem 01: Idempotence of secrecy bitmask join (`|||`). -/
theorem secrecy_join_idempotent (a : Nat) : (a ||| a) = a := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_or]
  exact Bool.or_self (a.testBit i)

/-- Theorem 02: Commutativity of secrecy bitmask join (`|||`). -/
theorem secrecy_join_comm (a b : Nat) : (a ||| b) = (b ||| a) := by
  apply Nat.eq_of_testBit_eq
  intro i
  simp [Nat.testBit_or, Bool.or_comm]

/-- Theorem 03: Associativity of secrecy bitmask join (`|||`). -/
theorem secrecy_join_assoc (a b c : Nat) : ((a ||| b) ||| c) = (a ||| (b ||| c)) := by
  apply Nat.eq_of_testBit_eq
  intro i
  simp [Nat.testBit_or, Bool.or_assoc]

/-- Theorem 04: Single-step secrecy monotonicity — once secrecy bit `tag` is set, advancing any
    step preserves `tag`. -/
theorem advanceState_secrecy_monotone (s : TrajState) (st : Step) (tag : Nat)
    (hTainted : s.secrecy.testBit tag = true) :
    (advanceState s st).secrecy.testBit tag = true := by
  unfold advanceState
  simp [Nat.testBit_or, hTainted]

/-- Theorem 05: Multi-step secrecy monotonicity — secrecy taint never decreases along arbitrary
    finite trajectories `tr : List Step`. -/
theorem runSteps_secrecy_monotone (tr : List Step) (s : TrajState) (tag : Nat)
    (hTainted : s.secrecy.testBit tag = true) :
    (runSteps s tr).secrecy.testBit tag = true := by
  induction tr generalizing s with
  | nil =>
    exact hTainted
  | cons hd tl ih =>
    simp only [runSteps]
    exact ih (advanceState s hd) (advanceState_secrecy_monotone s hd tag hTainted)

/-- Theorem 06: Idempotence of Biba integrity lattice meet (`min`). -/
theorem integrity_meet_idempotent (a : Nat) : integrityMeet a a = a := by
  unfold integrityMeet
  omega

/-- Theorem 07: Commutativity of Biba integrity lattice meet (`min`). -/
theorem integrity_meet_comm (a b : Nat) : integrityMeet a b = integrityMeet b a := by
  unfold integrityMeet
  omega

/-- Theorem 08: Associativity of Biba integrity lattice meet (`min`). -/
theorem integrity_meet_assoc (a b c : Nat) :
    integrityMeet (integrityMeet a b) c = integrityMeet a (integrityMeet b c) := by
  unfold integrityMeet
  omega

/-- Theorem 09: Multi-step Biba integrity monotonic degradation — without external reset, ambient
    integrity along any trajectory `tr` is bounded above by initial integrity `s.integrity`. -/
theorem runSteps_integrity_nonincreasing_without_endorse (tr : List Step) (s : TrajState) :
    (runSteps s tr).integrity ≤ s.integrity := by
  induction tr generalizing s with
  | nil =>
    exact Nat.le_refl s.integrity
  | cons hd tl ih =>
    simp only [runSteps]
    have hNext : (advanceState s hd).integrity ≤ s.integrity := by
      dsimp only [advanceState, integrityMeet]
      exact Nat.min_le_left s.integrity hd.inputIntegrity
    have hRest := ih (advanceState s hd)
    omega

/-- Theorem 10: Semilattice laws (idempotence, commutativity, associativity) for Macaroon
    capability intersection (`&&&`). -/
theorem macaroon_intersect_semilattice (a b c : Nat) :
    (a &&& a) = a ∧
    (a &&& b) = (b &&& a) ∧
    ((a &&& b) &&& c) = (a &&& (b &&& c)) := by
  refine ⟨?_, ?_, ?_⟩
  · apply Nat.eq_of_testBit_eq
    intro i
    rw [Nat.testBit_and]
    exact Bool.and_self (a.testBit i)
  · apply Nat.eq_of_testBit_eq
    intro i
    simp [Nat.testBit_and, Bool.and_comm]
  · apply Nat.eq_of_testBit_eq
    intro i
    simp [Nat.testBit_and, Bool.and_assoc]

/-- Theorem 11: Monotonic submask attenuation across arbitrary Macaroon caveat chains —
    attenuating `root` by any list of caveats `cs` always remains a bitwise submask of `root`. -/
theorem attenuateChain_submask (cs : List Nat) (root : Nat) :
    (attenuateChain root cs &&& root) = attenuateChain root cs := by
  have hGen : ∀ (ms : List Nat) (acc bound : Nat),
      (acc &&& bound) = acc → (attenuateChain acc ms &&& bound) = attenuateChain acc ms := by
    intro ms
    induction ms with
    | nil =>
      intro acc bound hSub
      exact hSub
    | cons c rest ih =>
      intro acc bound hSub
      simp only [attenuateChain]
      apply ih (acc &&& c) bound
      apply Nat.eq_of_testBit_eq
      intro i
      have hBit : (acc &&& bound).testBit i = acc.testBit i := congrArg (fun x => x.testBit i) hSub
      rw [Nat.testBit_and] at hBit ⊢
      rw [Nat.testBit_and]
      cases hA : acc.testBit i <;> cases hB : bound.testBit i <;> cases hC : c.testBit i <;>
        simp_all
  apply hGen cs root root
  exact (macaroon_intersect_semilattice root root root).1

/-- Theorem 12: Zero capability escalation under Macaroon delegation — any scope bit authorized
    after an arbitrary caveat chain `cs` must already have been authorized in `root`. -/
theorem hasScope_attenuateChain_imp_root (cs : List Nat) (root scopeBit : Nat)
    (hGranted : hasScope (attenuateChain root cs) scopeBit = true) :
    hasScope root scopeBit = true := by
  have hSub := attenuateChain_submask cs root
  have hBit := congrArg (fun x => x.testBit scopeBit) hSub
  unfold hasScope at hGranted ⊢
  rw [Nat.testBit_and, hGranted] at hBit
  simpa using hBit

/-- Theorem 13: State determinism of accepted trajectories — whenever `evalTrajectory s0 tr`
    accepts `sFinal`, `sFinal` equals the exact lattice fold `runSteps s0 tr`. -/
theorem evalTrajectory_accept_eq_runSteps (tr : List Step) (s0 sFinal : TrajState)
    (hAcc : evalTrajectory s0 tr = GateOutcome.accept sFinal) :
    sFinal = runSteps s0 tr := by
  induction tr generalizing s0 with
  | nil =>
    simp only [evalTrajectory, runSteps] at hAcc ⊢
    injection hAcc with hEq
    exact hEq.symm
  | cons hd tl ih =>
    simp only [evalTrajectory] at hAcc
    cases hStep : evalStep s0 hd with
    | reject c =>
      rw [hStep] at hAcc
      contradiction
    | accept s1 =>
      rw [hStep] at hAcc
      have hS1 := (evalStep_accept_invariants s0 s1 hd hStep).1
      subst hS1
      exact ih (advanceState s0 hd) hAcc

/-- Theorem 14: Inductive stepwise soundness — acceptance of `tr` guarantees `TrajectoryStepwiseSafe`
    across every intermediate transition in `tr`. -/
theorem accepted_trajectory_stepwise_safe (tr : List Step) (s0 sFinal : TrajState)
    (hAcc : evalTrajectory s0 tr = GateOutcome.accept sFinal) :
    TrajectoryStepwiseSafe s0 tr := by
  induction tr generalizing s0 with
  | nil =>
    exact trivial
  | cons hd tl ih =>
    simp only [evalTrajectory] at hAcc
    cases hStep : evalStep s0 hd with
    | reject c =>
      rw [hStep] at hAcc
      contradiction
    | accept s1 =>
      rw [hStep] at hAcc
      rcases evalStep_accept_invariants s0 s1 hd hStep with ⟨hEq, hSc, hMac, hTri, hBib, hBud⟩
      subst hEq
      exact ⟨hSc, hMac, hTri, hBib, hBud, ih (advanceState s0 hd) hAcc⟩

/-- Theorem 15 (Main DIFC Safety Theorem — No Unendorsed Lethal Trifecta):
    For EVERY trajectory decomposition `tr1 ++ st :: tr2`, if `evalTrajectory` accepts, then at
    step `st` where accumulated secrecy taint is non-zero and accumulated integrity is untrusted,
    any `externalSink` action MUST carry a verified human declassification endorsement. -/
theorem accepted_trajectory_no_unendorsed_lethal_trifecta
    (tr1 tr2 : List Step) (st : Step) (s0 sFinal : TrajState)
    (hAcc : evalTrajectory s0 (tr1 ++ st :: tr2) = GateOutcome.accept sFinal)
    (hSink : st.action = ActionKind.externalSink)
    (hTaint : 0 < (advanceState (runSteps s0 tr1) st).secrecy)
    (hUntrusted : (advanceState (runSteps s0 tr1) st).integrity ≤ untrustedExternal) :
    st.endorsedTrifecta = true := by
  have hSplit := evalTrajectory_split_accept tr1 (st :: tr2) s0 sFinal hAcc
  have hSafeTail := accepted_trajectory_stepwise_safe (st :: tr2) (runSteps s0 tr1) sFinal hSplit.2
  exact hSafeTail.2.2.1 ⟨hSink, hTaint, hUntrusted⟩

/-- Theorem 16 (Biba Confused-Deputy Non-Escalation Theorem):
    For EVERY trajectory decomposition `tr1 ++ st :: tr2`, if `evalTrajectory` accepts, then no
    `highIntegrityMutation` step occurs below `userExplicit` integrity without explicit endorsement. -/
theorem accepted_trajectory_no_confused_deputy
    (tr1 tr2 : List Step) (st : Step) (s0 sFinal : TrajState)
    (hAcc : evalTrajectory s0 (tr1 ++ st :: tr2) = GateOutcome.accept sFinal)
    (hMut : st.action = ActionKind.highIntegrityMutation)
    (hLowInt : (advanceState (runSteps s0 tr1) st).integrity < userExplicit) :
    st.endorsedBiba = true := by
  have hSplit := evalTrajectory_split_accept tr1 (st :: tr2) s0 sFinal hAcc
  have hSafeTail := accepted_trajectory_stepwise_safe (st :: tr2) (runSteps s0 tr1) sFinal hSplit.2
  exact hSafeTail.2.2.2.1 ⟨hMut, hLowInt⟩

private theorem nonempty_accept_final_budget (tl : List Step) (s0 sFinal : TrajState) (hd : Step)
    (hAcc : evalTrajectory s0 (hd :: tl) = GateOutcome.accept sFinal) :
    sFinal.cumulativeCost ≤ sFinal.budgetLimit := by
  induction tl generalizing s0 hd with
  | nil =>
    simp only [evalTrajectory] at hAcc
    cases hStep : evalStep s0 hd with
    | reject c =>
      rw [hStep] at hAcc
      contradiction
    | accept s1 =>
      rw [hStep] at hAcc
      dsimp only [evalTrajectory] at hAcc
      injection hAcc with hEq
      rcases evalStep_accept_invariants s0 s1 hd hStep with ⟨hS1, _, _, _, _, hBud⟩
      rw [← hEq, hS1]
      exact hBud
  | cons hd2 tl2 ih =>
    simp only [evalTrajectory] at hAcc
    cases hStep : evalStep s0 hd with
    | reject c =>
      rw [hStep] at hAcc
      contradiction
    | accept s1 =>
      rw [hStep] at hAcc
      exact ih s1 hd2 hAcc

private theorem zero_or_eq (m : Nat) : (0 ||| m) = m := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_or]
  simp

private theorem or_zero_eq (m : Nat) : (m ||| 0) = m := by
  apply Nat.eq_of_testBit_eq
  intro i
  rw [Nat.testBit_or]
  simp

/-- Theorem 17 (Mid-Trajectory Schema Pinning, Macaroon Scope & Horizon Budget Soundness):
    For EVERY accepted trajectory `tr1 ++ st :: tr2`, any schema mutation at step `st` had a
    `TRUSTED_SYSTEM` epoch bump, every required Macaroon scope bit was present, and final
    cumulative cost satisfies the horizon budget bound. -/
theorem accepted_trajectory_schema_macaroon_and_budget_sound
    (tr1 tr2 : List Step) (st : Step) (s0 sFinal : TrajState)
    (hAcc : evalTrajectory s0 (tr1 ++ st :: tr2) = GateOutcome.accept sFinal) :
    (st.schemaChanged = true → st.trustedEpochBump = true) ∧
    (st.requiresScope = true →
      hasScope (advanceState (runSteps s0 tr1) st).macaroonScopes st.requiredScopeBit = true) ∧
    sFinal.cumulativeCost ≤ sFinal.budgetLimit := by
  have hSplit := evalTrajectory_split_accept tr1 (st :: tr2) s0 sFinal hAcc
  have hSafeTail := accepted_trajectory_stepwise_safe (st :: tr2) (runSteps s0 tr1) sFinal hSplit.2
  have hBudEnd := nonempty_accept_final_budget tr2 (runSteps s0 tr1) sFinal st hSplit.2
  exact ⟨hSafeTail.1, hSafeTail.2.1, hBudEnd⟩

/-- Theorem 18 (Strict Stateful-vs-Stateless Separation on 3-Step Split Exfiltration):
    For EVERY non-zero secret bitmask `0 < secretMask` and horizon budget `3 <= budget`, the
    memoryless single-step filter `evalStatelessTrajectory` accepts `splitExfilAttack secretMask`,
    whereas stateful `evalTrajectory` deterministically rejects with `lethalTrifectaExfil`. -/
theorem stateless_allows_split_exfil_while_difc_rejects
    (secretMask budget : Nat)
    (hSecret : 0 < secretMask)
    (hBudget : 3 ≤ budget) :
    evalStatelessTrajectory (splitExfilAttack secretMask) = true ∧
    evalTrajectory (initCleanState budget) (splitExfilAttack secretMask) =
      GateOutcome.reject RejectCode.lethalTrifectaExfil ∧
    (∀ sFinal,
      evalTrajectory (initCleanState budget) (splitExfilAttack secretMask) ≠
        GateOutcome.accept sFinal) := by
  have hScope0 : hasScope 7 0 = true := by decide
  have hScope1 : hasScope 7 1 = true := by decide
  have hNotBud1 : ¬ (budget < 1) := by omega
  have hNotBud2 : ¬ (budget < 2) := by omega
  have hSec1 : (0 ||| secretMask) = secretMask := zero_or_eq secretMask
  have hSec2 : (secretMask ||| 0) = secretMask := or_zero_eq secretMask
  have hStateless : evalStatelessTrajectory (splitExfilAttack secretMask) = true := by
    unfold splitExfilAttack evalStatelessTrajectory statelessStepOk untrustedExternal
    simp
  have hStateful :
      evalTrajectory (initCleanState budget) (splitExfilAttack secretMask) =
        GateOutcome.reject RejectCode.lethalTrifectaExfil := by
    have hMin22 : min 2 2 = 2 := rfl
    have hMin20 : min 2 0 = 0 := rfl
    have hMin02 : min 0 2 = 0 := rfl
    simp [splitExfilAttack, initCleanState, evalTrajectory, evalStep, advanceState, integrityMeet,
      untrustedExternal, userExplicit, hScope0, hScope1, hNotBud1, hNotBud2, hSec1, hSec2,
      hSecret, hMin22, hMin20, hMin02]
  refine ⟨hStateless, hStateful, ?_⟩
  intro sFinal hContra
  rw [hStateful] at hContra
  contradiction

#print axioms secrecy_join_idempotent
#print axioms secrecy_join_comm
#print axioms secrecy_join_assoc
#print axioms advanceState_secrecy_monotone
#print axioms runSteps_secrecy_monotone
#print axioms integrity_meet_idempotent
#print axioms integrity_meet_comm
#print axioms integrity_meet_assoc
#print axioms runSteps_integrity_nonincreasing_without_endorse
#print axioms macaroon_intersect_semilattice
#print axioms attenuateChain_submask
#print axioms hasScope_attenuateChain_imp_root
#print axioms evalTrajectory_accept_eq_runSteps
#print axioms accepted_trajectory_stepwise_safe
#print axioms accepted_trajectory_no_unendorsed_lethal_trifecta
#print axioms accepted_trajectory_no_confused_deputy
#print axioms accepted_trajectory_schema_macaroon_and_budget_sound
#print axioms stateless_allows_split_exfil_while_difc_rejects

end ProofGate.TrajectoryDIFC
