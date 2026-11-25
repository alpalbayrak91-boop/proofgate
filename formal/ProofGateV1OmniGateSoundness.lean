-- SPDX-License-Identifier: MIT
-- ProofGate v1.0.0 ("Omni-Gate") — Pure-Init Lean 4 Formal Soundness Proofs
-- Covers:
--   1. Non-compensatory lexicographic 4-gate and 6-tier scoring (Linear Compensation Paradox elimination)
--   2. RFC 6962 domain-separated Merkle tree (leaf vs node separation, order sensitivity, tamper detection)
--   3. DSSEv1 Pre-Authentication Encoding (PAE) unambiguous framing & SLSA Provenance v1.0 fail-closed gate
--   4. Lean 4 vacuity interval unsatisfiability & PR diff alpha-rename / theorem-drop safety
--   5. SARIF UTF-16 code-unit offset bounds, Page-CUSUM monotonicity/quarantine, and Omni-Gate master soundness
-- Zero external imports, zero custom axioms, 0 incomplete proofs, 0 chr(36), 0 chr(96).

set_option warningAsError true
set_option autoImplicit false

namespace ProofGate.OmniGate

-- ============================================================================
-- 1. Non-Compensatory Lexicographic 4-Gate & 6-Tier Lattice
-- ============================================================================

/-- Non-compensatory 4-gate lexicographic score in basis points (Tier -6..Tier 0). -/
def lex4GateBps (p0 : Nat) (provClean refReach refDiffFam refApproved : Bool)
    (p1Penalty q : Nat) : Int :=
  if 10000 < q then -26000
  else if 0 < p0 then -25000
  else if !provClean then -24000
  else if !(refReach && refDiffFam) then -23000
  else if !refApproved then -22000
  else
    let qi : Int := Int.ofNat q
    let pi : Int := Int.ofNat p1Penalty
    if qi ≤ pi then 0 else qi - pi

/-- Legacy additive linear baseline score (0..100 scale) exhibiting the Linear Compensation Paradox. -/
def linearBaselinePts (qPts p0Missing p0Trivial : Nat) : Int :=
  let pen : Int := Int.ofNat (15 * p0Missing + 20 * p0Trivial)
  let qi : Int := Int.ofNat qPts
  if qi ≤ pen then 0 else qi - pen

/-- Non-compensatory 6-tier INV-13 strict dominance score: hard fail <= 10004 < 10005 <= clean PASS. -/
def lex6TierScore (ws cap prov live bud : Bool) (p1 q : Nat) : Nat :=
  let qClamped := min 10000 q
  if !ws then 0
  else if !cap then 1
  else if !prov then 2
  else if !live then 3
  else if !bud || 0 < p1 then 4 + qClamped
  else 10005 + qClamped

-- ============================================================================
-- 2. RFC 6962 Merkle Tree Domain Separation & DSSEv1 PAE Framing
-- ============================================================================

/-- Abstract collision-resistant tagged hash primitive modeling SHA-256(tag || a || b). -/
structure TaggedHashAlg where
  hash3 : Nat → Nat → Nat → Nat

/-- Collision resistance (injectivity) of the tagged hash primitive. -/
def TaggedHashAlg.Injective (alg : TaggedHashAlg) : Prop :=
  ∀ t1 a1 b1 t2 a2 b2,
    alg.hash3 t1 a1 b1 = alg.hash3 t2 a2 b2 → t1 = t2 ∧ a1 = a2 ∧ b1 = b2

/-- RFC 6962 Section 2.1 leaf hash with domain separator tag 0 (0x00). -/
def rfc6962Leaf (alg : TaggedHashAlg) (payload : Nat) : Nat :=
  alg.hash3 0 payload 0

/-- RFC 6962 Section 2.1 interior node hash with domain separator tag 1 (0x01). -/
def rfc6962Node (alg : TaggedHashAlg) (left right : Nat) : Nat :=
  alg.hash3 1 left right

/-- DSSEv1 Pre-Authentication Encoding modeled over Nat byte streams with explicit length prefixes. -/
def dssePaeStream (payloadType body : List Nat) : List Nat :=
  [payloadType.length] ++ payloadType ++ [body.length] ++ body

/-- SLSA Provenance v1.0 + DSSEv1 verification evidence record. -/
structure SlsaEvidence where
  dsseSignatureValid : Bool
  inTotoStatementV1  : Bool
  slsaProvenanceV1   : Bool
  subjectsMatched    : Bool
  builderIdPresent   : Bool
  deriving DecidableEq, Repr

/-- Fail-closed SLSA Provenance v1.0 gate. -/
def verifySlsaGate (ev : SlsaEvidence) : Bool :=
  ev.dsseSignatureValid &&
  ev.inTotoStatementV1 &&
  ev.slsaProvenanceV1 &&
  ev.subjectsMatched &&
  ev.builderIdPresent

-- ============================================================================
-- 3. Lean PR Diff Gate, UTF-16 Offsets, Page-CUSUM, and Omni-Gate Master
-- ============================================================================

/-- PR theorem-retention gate: checks that every base proposition appears in head unless drops allowed. -/
def diffGateAccepts (baseProps headProps : List Nat) (allowDrops : Bool) : Bool :=
  allowDrops || baseProps.all (fun p => headProps.contains p)

/-- UTF-16 code-unit width of a Unicode scalar (1 for BMP, 2 for SMP surrogate pairs). -/
def utf16CharWidth (isSmp : Bool) : Nat :=
  if isSmp then 2 else 1

/-- Total UTF-16 code-unit length accumulated from a list of BMP/SMP scalar flags. -/
def totalUtf16Units : List Bool → Nat
  | [] => 0
  | b :: rest => utf16CharWidth b + totalUtf16Units rest

/-- One-sided upward Page-CUSUM state transition (clamped at 0). -/
def pageCusumStep (state obs refSlack : Nat) : Nat :=
  if state + obs ≤ refSlack then 0 else state + obs - refSlack

/-- Complete ProofGate v1.0.0 Omni-Gate certification receipt. -/
structure OmniGateReceipt where
  sarifValid        : Bool
  slsaValid         : Bool
  merkleConsistent  : Bool
  leanClean         : Bool
  astClean          : Bool
  diffNoDrop        : Bool
  evalLexPass       : Bool
  cusumClear        : Bool
  chr36Count        : Nat
  incompleteProofs  : Nat
  customAxioms      : Nat
  pbtTotal          : Nat
  pbtPassed         : Nat
  advTotal          : Nat
  advPassed         : Nat
  deriving DecidableEq, Repr

/-- Fail-closed master verifier for ProofGate v1.0.0 Omni-Gate receipts. -/
def verifyOmniGate (r : OmniGateReceipt) : Bool :=
  r.sarifValid &&
  r.slsaValid &&
  r.merkleConsistent &&
  r.leanClean &&
  r.astClean &&
  r.diffNoDrop &&
  r.evalLexPass &&
  r.cusumClear &&
  decide (r.chr36Count = 0) &&
  decide (r.incompleteProofs = 0) &&
  decide (r.customAxioms = 0) &&
  decide (1000 ≤ r.pbtTotal) &&
  decide (r.pbtPassed = r.pbtTotal) &&
  decide (12 ≤ r.advTotal) &&
  decide (r.advPassed = r.advTotal)

-- ============================================================================
-- Helper Lemmas (all reachable from public theorems)
-- ============================================================================

private theorem list_append_eq_len_left {α : Type} :
    ∀ {xs ys as bs : List α}, xs.length = ys.length → xs ++ as = ys ++ bs → xs = ys ∧ as = bs
  | [], [], _, _, _, hEq => ⟨rfl, hEq⟩
  | x :: xs', y :: ys', as, bs, hLen, hEq => by
    simp only [List.length_cons] at hLen
    rcases List.cons.inj hEq with ⟨rfl, hRest⟩
    have hTail := list_append_eq_len_left (Nat.succ.inj hLen) hRest
    exact ⟨congrArg (fun tl => x :: tl) hTail.1, hTail.2⟩

private theorem list_all_eq_true_iff {α : Type} (p : α → Bool) (xs : List α) :
    xs.all p = true ↔ ∀ x, x ∈ xs → p x = true := by
  induction xs with
  | nil =>
    simp
  | cons hd tl ih =>
    simp only [List.all_cons, Bool.and_eq_true, List.mem_cons, forall_eq_or_imp]
    constructor
    · intro h
      exact ⟨h.1, ih.mp h.2⟩
    · intro h
      exact ⟨h.1, ih.mpr h.2⟩

-- ============================================================================
-- 16 Public Soundness Theorems (0 incomplete proofs, 0 custom axioms)
-- ============================================================================

/-- Theorem 01: Constructive witness of the Linear Compensation Paradox — a single P0 missing-file
    defect passes the legacy additive baseline (>= 75) yet is strictly rejected (-25000 < 7500)
    by ProofGate's lexicographic 4-gate scorer. -/
theorem thm01_linear_compensation_paradox_witness :
    linearBaselinePts 100 1 0 = 85 ∧
    75 ≤ linearBaselinePts 100 1 0 ∧
    lex4GateBps 1 true true true true 0 10000 = -25000 ∧
    lex4GateBps 1 true true true true 0 10000 < 7500 := by
  decide

/-- Theorem 02: Non-compensatory P0 veto dominance — for every candidate with p0 >= 1 and valid
    quality q <= 10000, lex4GateBps equals -25000 regardless of referee approval or superficial quality. -/
theorem thm02_lex4gate_strict_p0_veto
    (p0 p1Penalty q : Nat)
    (provClean refReach refDiffFam refApproved : Bool)
    (hq : q ≤ 10000)
    (hp0 : 0 < p0) :
    lex4GateBps p0 provClean refReach refDiffFam refApproved p1Penalty q = -25000 ∧
    lex4GateBps p0 provClean refReach refDiffFam refApproved p1Penalty q < 0 := by
  have hqNot : ¬ (10000 < q) := Nat.not_lt.mpr hq
  unfold lex4GateBps
  simp only [hqNot, ↓reduceIte, hp0]
  decide

/-- Theorem 03: Provenance and cross-family referee veto isolation — missing provenance maps to
    -24000, unreachable or same-family referee maps to -23000, and rejected referee maps to -22000;
    all fail strictly below 0 regardless of p1Penalty or quality q <= 10000. -/
theorem thm03_lex4gate_provenance_and_referee_veto
    (p1Penalty q : Nat)
    (refReach refDiffFam refApproved : Bool)
    (hq : q ≤ 10000) :
    (lex4GateBps 0 false refReach refDiffFam refApproved p1Penalty q = -24000) ∧
    (refReach = false ∨ refDiffFam = false →
      lex4GateBps 0 true refReach refDiffFam refApproved p1Penalty q = -23000) ∧
    (lex4GateBps 0 true true true false p1Penalty q = -22000) := by
  have hqNot : ¬ (10000 < q) := Nat.not_lt.mpr hq
  refine ⟨?_, ?_, ?_⟩
  · unfold lex4GateBps
    simp [hqNot]
  · intro hBad
    unfold lex4GateBps
    rcases hBad with hr | hf
    · simp [hqNot, hr]
    · simp [hqNot, hf]
  · unfold lex4GateBps
    simp [hqNot]

/-- Theorem 04: 6-tier INV-13 non-compensatory spectral gap — any failure in workspace, capability,
    provenance, liveness, budget, or P1 defects yields score <= 10004 < 10005 <= clean PASS score. -/
theorem thm04_lex6tier_non_compensatory_gap
    (ws cap prov live bud : Bool)
    (p1 qBad qClean : Nat)
    (hFail : ws = false ∨ cap = false ∨ prov = false ∨ live = false ∨ bud = false ∨ 0 < p1) :
    lex6TierScore ws cap prov live bud p1 qBad ≤ 10004 ∧
    10005 ≤ lex6TierScore true true true true true 0 qClean ∧
    lex6TierScore ws cap prov live bud p1 qBad < lex6TierScore true true true true true 0 qClean := by
  have hClean : 10005 ≤ lex6TierScore true true true true true 0 qClean := by
    simp [lex6TierScore]
  have hBound : lex6TierScore ws cap prov live bud p1 qBad ≤ 10004 := by
    unfold lex6TierScore
    rcases hFail with h | h | h | h | h | h
    · simp [h]
    · cases ws <;> simp [h]
    · cases ws <;> cases cap <;> simp [h]
    · cases ws <;> cases cap <;> cases prov <;> simp [h]
    · cases ws <;> cases cap <;> cases prov <;> cases live <;> simp [h] <;> omega
    · cases ws <;> cases cap <;> cases prov <;> cases live <;> cases bud <;> simp [h] <;> omega
  exact ⟨hBound, hClean, by omega⟩

/-- Theorem 05: RFC 6962 domain separation — under an injective hash primitive, a leaf digest
    (prefix 0x00) can never equal an interior node digest (prefix 0x01), blocking second-preimage
    tree-forgery attacks. -/
theorem thm05_rfc6962_domain_separation
    (alg : TaggedHashAlg) (hInj : alg.Injective) (payload left right : Nat) :
    rfc6962Leaf alg payload ≠ rfc6962Node alg left right := by
  intro hEq
  unfold rfc6962Leaf rfc6962Node at hEq
  have hParts := hInj 0 payload 0 1 left right hEq
  omega

/-- Theorem 06: RFC 6962 node injectivity and non-commutativity — distinct sibling digests
    cannot be swapped without mutating the parent hash. -/
theorem thm06_rfc6962_node_injective_and_order_sensitive
    (alg : TaggedHashAlg) (hInj : alg.Injective) (l1 r1 l2 r2 : Nat) :
    (rfc6962Node alg l1 r1 = rfc6962Node alg l2 r2 → l1 = l2 ∧ r1 = r2) ∧
    (l1 ≠ r1 → rfc6962Node alg l1 r1 ≠ rfc6962Node alg r1 l1) := by
  refine ⟨?_, ?_⟩
  · intro hEq
    unfold rfc6962Node at hEq
    have hParts := hInj 1 l1 r1 1 l2 r2 hEq
    exact hParts.2
  · intro hNeq hSwap
    unfold rfc6962Node at hSwap
    have hParts := hInj 1 l1 r1 1 r1 l1 hSwap
    exact hNeq hParts.2.1

/-- Theorem 07: Tamper sensitivity on a 2-leaf RFC 6962 Merkle tree — mutating either the left
    or the right payload strictly changes the Merkle root. -/
theorem thm07_rfc6962_tamper_breaks_two_leaf_root
    (alg : TaggedHashAlg) (hInj : alg.Injective) (x1 x1' x2 : Nat)
    (hDiff : x1' ≠ x1) :
    rfc6962Node alg (rfc6962Leaf alg x1') (rfc6962Leaf alg x2) ≠
    rfc6962Node alg (rfc6962Leaf alg x1) (rfc6962Leaf alg x2) := by
  intro hEq
  unfold rfc6962Node rfc6962Leaf at hEq
  have hNode := (hInj 1 (alg.hash3 0 x1' 0) (alg.hash3 0 x2 0) 1 (alg.hash3 0 x1 0) (alg.hash3 0 x2 0) hEq).2.1
  have hLeaf := (hInj 0 x1' 0 0 x1 0 hNode).2.1
  exact hDiff hLeaf

/-- Theorem 08: DSSEv1 PAE framing injectivity — length-prefixed framing uniquely recovers both
    payloadType and body, eliminating raw concatenation boundary ambiguity. -/
theorem thm08_dsse_pae_framing_injective (t1 b1 t2 b2 : List Nat) :
    dssePaeStream t1 b1 = dssePaeStream t2 b2 → t1 = t2 ∧ b1 = b2 := by
  intro hEq
  unfold dssePaeStream at hEq
  simp only [List.cons_append, List.nil_append] at hEq
  have hLenT : t1.length = t2.length := (List.cons.inj hEq).1
  have hRest1 : t1 ++ [b1.length] ++ b1 = t2 ++ [b2.length] ++ b2 := (List.cons.inj hEq).2
  have hSplit1 := list_append_eq_len_left hLenT (by simpa [List.append_assoc] using hRest1)
  have hTail : b1.length :: b1 = b2.length :: b2 := by
    simpa [List.cons_append, List.nil_append] using hSplit1.2
  have hB : b1 = b2 := (List.cons.inj hTail).2
  exact ⟨hSplit1.1, hB⟩

/-- Theorem 09: SLSA Provenance v1.0 + DSSEv1 gate soundness and fail-closed rejection — acceptance
    holds iff signature, in-toto v1 type, SLSA v1 predicate, subject digests, and builder ID all pass. -/
theorem thm09_slsa_provenance_fail_closed (ev : SlsaEvidence) :
    verifySlsaGate ev = true ↔
    (ev.dsseSignatureValid = true ∧
     ev.inTotoStatementV1 = true ∧
     ev.slsaProvenanceV1 = true ∧
     ev.subjectsMatched = true ∧
     ev.builderIdPresent = true) := by
  unfold verifySlsaGate
  simp only [Bool.and_eq_true]
  constructor
  · intro h
    exact ⟨h.1.1.1.1, h.1.1.1.2, h.1.1.2, h.1.2, h.2⟩
  · intro h
    exact ⟨⟨⟨⟨h.1, h.2.1⟩, h.2.2.1⟩, h.2.2.2.1⟩, h.2.2.2.2⟩

/-- Theorem 10: Vacuity detector mathematical soundness — any contradictory integer bounds (lo < x
    and x < hi with hi <= lo) or negative Nat constraint (Int.ofNat n < 0) is unsatisfiable (False). -/
theorem thm10_vacuity_contradictory_bounds_unsatisfiable
    (x lo hi : Int) (n : Nat) :
    (lo < x → x < hi → hi ≤ lo → False) ∧
    ((n : Int) < 0 → False) := by
  refine ⟨?_, ?_⟩
  · intro h1 h2 h3
    omega
  · intro hn
    omega

/-- Theorem 11: Lean PR diff gate fail-closed drop rejection — when allowDrops is false, dropping
    any base theorem proposition without an alpha-equivalent head theorem yields false. -/
theorem thm11_diff_gate_drop_always_rejected
    (baseProps headProps : List Nat) (droppedProp : Nat)
    (hInBase : droppedProp ∈ baseProps)
    (hMissingInHead : headProps.contains droppedProp = false) :
    diffGateAccepts baseProps headProps false = false := by
  unfold diffGateAccepts
  simp only [Bool.false_or]
  cases hAll : baseProps.all (fun p => headProps.contains p) with
  | false => rfl
  | true =>
    have hMem := (list_all_eq_true_iff (fun p => headProps.contains p) baseProps).mp hAll droppedProp hInBase
    rw [hMissingInHead] at hMem
    exact Bool.noConfusion hMem

/-- Theorem 12: Lean PR diff gate alpha-rename/move preservation — if every base canonical proposition
    appears in head (even at a different line, namespace, or theorem name), diffGateAccepts is true. -/
theorem thm12_diff_gate_reordering_preserves_acceptance
    (baseProps headProps : List Nat)
    (hRetained : ∀ p, p ∈ baseProps → headProps.contains p = true) :
    diffGateAccepts baseProps headProps false = true := by
  unfold diffGateAccepts
  simp only [Bool.false_or]
  exact (list_all_eq_true_iff (fun p => headProps.contains p) baseProps).mpr hRetained

/-- Theorem 13: SARIF UTF-16 code-unit bounds — for every scalar sequence, UTF-16 code-unit offset
    satisfies length <= totalUtf16Units <= 2 * length, and equals length when all scalars are BMP. -/
theorem thm13_utf16_code_unit_bounds (chars : List Bool) :
    chars.length ≤ totalUtf16Units chars ∧
    totalUtf16Units chars ≤ 2 * chars.length ∧
    ((∀ b, b ∈ chars → b = false) → totalUtf16Units chars = chars.length) := by
  induction chars with
  | nil =>
    simp [totalUtf16Units]
  | cons hd tl ih =>
    simp only [totalUtf16Units, List.length_cons, List.mem_cons, forall_eq_or_imp]
    have hW : 1 ≤ utf16CharWidth hd ∧ utf16CharWidth hd ≤ 2 := by
      cases hd <;> simp [utf16CharWidth]
    refine ⟨by omega, by omega, ?_⟩
    intro hBmp
    have hHd : hd = false := hBmp.1
    have hTl : totalUtf16Units tl = tl.length := ih.2.2 hBmp.2
    simp [utf16CharWidth, hHd, hTl]
    omega

/-- Theorem 14: Page-CUSUM sequential monotonicity and single-step threshold quarantine — CUSUM is
    monotone in both prior accumulator and observation, and any spike >= refSlack + thresh triggers alarm. -/
theorem thm14_page_cusum_monotone_and_alarm
    (s1 s2 x1 x2 refSlack thresh : Nat) :
    (s1 ≤ s2 → x1 ≤ x2 → pageCusumStep s1 x1 refSlack ≤ pageCusumStep s2 x2 refSlack) ∧
    (refSlack + thresh ≤ x1 → thresh ≤ pageCusumStep s1 x1 refSlack) := by
  refine ⟨?_, ?_⟩
  · intro hs hx
    unfold pageCusumStep
    split <;> split <;> omega
  · intro hSpike
    unfold pageCusumStep
    split <;> omega

/-- Theorem 15: Omni-Gate v1.0.0 master soundness and fail-closed rejection — acceptance implies all
    15 verification invariants across SARIF, SLSA, Merkle consistency, Lean, AST, PR Diff, Lex Eval,
    Page-CUSUM, KURAL-3 chr(36)==0, 0 incomplete proofs, and >=1000 PBT + >=12 adversarial checks. -/
theorem thm15_omni_gate_master_soundness_and_fail_closed (r : OmniGateReceipt) :
    (verifyOmniGate r = true →
      r.sarifValid = true ∧
      r.slsaValid = true ∧
      r.merkleConsistent = true ∧
      r.leanClean = true ∧
      r.astClean = true ∧
      r.diffNoDrop = true ∧
      r.evalLexPass = true ∧
      r.cusumClear = true ∧
      r.chr36Count = 0 ∧
      r.incompleteProofs = 0 ∧
      r.customAxioms = 0 ∧
      1000 ≤ r.pbtTotal ∧
      r.pbtPassed = r.pbtTotal ∧
      12 ≤ r.advTotal ∧
      r.advPassed = r.advTotal) ∧
    ((r.sarifValid = false ∨
      r.slsaValid = false ∨
      r.merkleConsistent = false ∨
      r.leanClean = false ∨
      r.astClean = false ∨
      r.diffNoDrop = false ∨
      r.evalLexPass = false ∨
      r.cusumClear = false ∨
      0 < r.chr36Count ∨
      0 < r.incompleteProofs ∨
      0 < r.customAxioms) →
      verifyOmniGate r = false) := by
  constructor
  · intro hPass
    rcases r with ⟨sa, sl, mk, ln, ast, df, ev, cu, c36, inc, cax, pt, pp, atot, ap⟩
    unfold verifyOmniGate at hPass
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hPass
    exact ⟨hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.2,
           hPass.1.1.1.1.2,
           hPass.1.1.1.2,
           hPass.1.1.2,
           hPass.1.2,
           hPass.2⟩
  · intro hBad
    unfold verifyOmniGate
    rcases hBad with h | h | h | h | h | h | h | h | h | h | h
    · simp [h]
    · simp [h]
    · simp [h]
    · simp [h]
    · simp [h]
    · simp [h]
    · simp [h]
    · simp [h]
    · simp [Nat.ne_of_gt h]
    · simp [Nat.ne_of_gt h]
    · simp [Nat.ne_of_gt h]

private def demoOmniPass : OmniGateReceipt :=
  { sarifValid := true
  , slsaValid := true
  , merkleConsistent := true
  , leanClean := true
  , astClean := true
  , diffNoDrop := true
  , evalLexPass := true
  , cusumClear := true
  , chr36Count := 0
  , incompleteProofs := 0
  , customAxioms := 0
  , pbtTotal := 2000
  , pbtPassed := 2000
  , advTotal := 16
  , advPassed := 16
  }

private def demoOmniFailDrop : OmniGateReceipt :=
  { demoOmniPass with diffNoDrop := false }

private def demoSlsaOk : SlsaEvidence :=
  { dsseSignatureValid := true
  , inTotoStatementV1 := true
  , slsaProvenanceV1 := true
  , subjectsMatched := true
  , builderIdPresent := true
  }

private def demoSlsaTampered : SlsaEvidence :=
  { demoSlsaOk with subjectsMatched := false }

/-- Theorem 16: Concrete decidable end-to-end witness certifying Omni-Gate passing and fail-closed
    behaviors across lexicographic 6-tier scoring, DSSE PAE disambiguation, SLSA, PR diff,
    UTF-16 surrogate lengths, Page-CUSUM drift quarantine, and master receipt verification. -/
theorem thm16_omni_gate_concrete_witness :
    lex6TierScore true true true true true 0 10000 = 20005 ∧
    lex6TierScore true true false true true 0 10000 = 2 ∧
    dssePaeStream [1, 2] [3] ≠ dssePaeStream [1] [2, 3] ∧
    verifySlsaGate demoSlsaOk = true ∧
    verifySlsaGate demoSlsaTampered = false ∧
    diffGateAccepts [101, 202] [202, 101, 303] false = true ∧
    diffGateAccepts [101, 202] [101, 303] false = false ∧
    totalUtf16Units [false, true, false] = 4 ∧
    pageCusumStep 10 25 15 = 20 ∧
    verifyOmniGate demoOmniPass = true ∧
    verifyOmniGate demoOmniFailDrop = false := by
  decide

#print axioms thm01_linear_compensation_paradox_witness
#print axioms thm02_lex4gate_strict_p0_veto
#print axioms thm03_lex4gate_provenance_and_referee_veto
#print axioms thm04_lex6tier_non_compensatory_gap
#print axioms thm05_rfc6962_domain_separation
#print axioms thm06_rfc6962_node_injective_and_order_sensitive
#print axioms thm07_rfc6962_tamper_breaks_two_leaf_root
#print axioms thm08_dsse_pae_framing_injective
#print axioms thm09_slsa_provenance_fail_closed
#print axioms thm10_vacuity_contradictory_bounds_unsatisfiable
#print axioms thm11_diff_gate_drop_always_rejected
#print axioms thm12_diff_gate_reordering_preserves_acceptance
#print axioms thm13_utf16_code_unit_bounds
#print axioms thm14_page_cusum_monotone_and_alarm
#print axioms thm15_omni_gate_master_soundness_and_fail_closed
#print axioms thm16_omni_gate_concrete_witness

end ProofGate.OmniGate
