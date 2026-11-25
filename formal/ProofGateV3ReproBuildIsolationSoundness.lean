-- SPDX-License-Identifier: MIT
-- TASLAK_ONERI: formal/ProofGateV3ReproBuildIsolationSoundness.lean
-- WEB-PITCH-PROOFGATE-V3-REPRO-BUILD-FACTOR-LAB-20261125 / KONU-3-LEAN4-META-DENETIM
-- PITCH-1F4DB351A967 (ProofGate CI v3): DR-KONU-PG-27 Lean 4 / Lake Reproducible Build
-- Factor Isolation & Semantic Equivalence Gate — Pure Lean 4 Kernel Soundness Proofs
--   1. 2x2x2 full factorial design (Y: path / -R, A: lean-toolchain githash/version,
--      B: lake-manifest rev private vs public) + 12-run schedule (8 + D0_tekrar + 3 probes)
--   2. Lake weakLeanArgs / weakLeancArgs trace blindness vs moreLeanArgs full coverage
--   3. Issue-16591 stale .olean residue rejection (clean workspace invariant)
--   4. Issue-16658 quadratic setup.json transitive path surface vs flat -R .olean
--   5. Semantic equivalence resilience (leanchecker --fresh --threads=1 + lake comparator)
--      and fail-closed ProofGate v3 gate soundness (including Issue-13615 forged .olean)
-- Zero external imports, zero custom axioms, zero incomplete proofs, zero chr(36), zero chr(96).

set_option warningAsError true

namespace AlpLab.Konu3.ProofGateV3ReproBuild

/-- Binary factor level in the 2x2x2 reproducible build experiment. -/
inductive FactorLevel where
  | low
  | high
  deriving DecidableEq, Repr

/-- Visibility scope of a lake-manifest.json dependency revision change (Factor B). -/
inductive DepChangeScope where
  | none
  | privateProofOnly
  | publicSignature
  deriving DecidableEq, Repr

/-- Build configuration capturing all DR-KONU-PG-27 reproducibility factors. -/
structure ReproBuildConfig where
  workspaceRootHash  : Nat           -- Factor Y: absolute workspace path digest
  useRelRootFlag     : Bool          -- -R canonical relative root flag (true in D0..D7, false in Sonda-Y1b)
  toolchainVerHash   : Nat           -- Factor A: lean-toolchain SemVer digest
  toolchainGitHash   : Nat           -- Factor A sub-probe (Sonda-A1b / Issue-12681): Lean commit githash
  manifestPublicHash : Nat           -- Factor B: lake-manifest public interface revision digest
  manifestPrivHash   : Nat           -- Factor B sub-probe (Sonda-B1b): lake-manifest private proof digest
  privateLeakEqLemma : Bool          -- Issue-14986: private proof materializes public equation theorem
  moreLeanArgsHash   : Nat           -- Traced Lean arguments (included in Lake BuildTrace)
  moreLeancArgsHash  : Nat           -- Traced C compiler arguments (included in Lake BuildTrace)
  weakLeanArgsHash   : Nat           -- Untraced weakLeanArgs (omitted by Lake BuildTrace)
  weakLeancArgsHash  : Nat           -- Untraced weakLeancArgs (omitted by Lake BuildTrace)
  sourceTreeHash     : Nat           -- Canonical LF-normalized source tree digest
  deriving DecidableEq, Repr

/-- Canonical 2x2x2 factorial coordinate (Y, A, B). -/
structure FactorialCell where
  yPath      : FactorLevel
  aToolchain : FactorLevel
  bManifest  : FactorLevel
  deriving DecidableEq, Repr

/-- Enumeration of all 8 cells of the 2x2x2 full factorial matrix (D0..D7). -/
def allFactorialCells : List FactorialCell :=
  [ { yPath := .low,  aToolchain := .low,  bManifest := .low  }
  , { yPath := .high, aToolchain := .low,  bManifest := .low  }
  , { yPath := .low,  aToolchain := .high, bManifest := .low  }
  , { yPath := .high, aToolchain := .high, bManifest := .low  }
  , { yPath := .low,  aToolchain := .low,  bManifest := .high }
  , { yPath := .high, aToolchain := .low,  bManifest := .high }
  , { yPath := .low,  aToolchain := .high, bManifest := .high }
  , { yPath := .high, aToolchain := .high, bManifest := .high }
  ]

/-- Identifiers for the complete 12-run DR-KONU-PG-27 factor isolation schedule. -/
inductive ExperimentRunId where
  | D0
  | D1
  | D2
  | D3
  | D4
  | D5
  | D6
  | D7
  | D0Tekrar
  | SondaY1b
  | SondaA1b
  | SondaB1b
  deriving DecidableEq, Repr

/-- Complete 12-run schedule: 2x2x2 factorial (8) + repeatability D0_tekrar (1) + 3 probes (3). -/
def full12RunSchedule : List ExperimentRunId :=
  [ .D0, .D1, .D2, .D3, .D4, .D5, .D6, .D7, .D0Tekrar, .SondaY1b, .SondaA1b, .SondaB1b ]

/-- Abstract collision-resistant hash algebra for build artifacts and traces. -/
structure ArtifactHashAlg where
  h2 : Nat → Nat → Nat
  h4 : Nat → Nat → Nat → Nat → Nat
  h6 : Nat → Nat → Nat → Nat → Nat → Nat → Nat

/-- Injectivity (collision resistance) of the artifact hash combinators. -/
def ArtifactHashAlg.Injective (alg : ArtifactHashAlg) : Prop :=
  (∀ a1 b1 a2 b2, alg.h2 a1 b1 = alg.h2 a2 b2 → a1 = a2 ∧ b1 = b2) ∧
  (∀ a1 b1 c1 d1 a2 b2 c2 d2,
    alg.h4 a1 b1 c1 d1 = alg.h4 a2 b2 c2 d2 → a1 = a2 ∧ b1 = b2 ∧ c1 = c2 ∧ d1 = d2) ∧
  (∀ a1 b1 c1 d1 e1 f1 a2 b2 c2 d2 e2 f2,
    alg.h6 a1 b1 c1 d1 e1 f1 = alg.h6 a2 b2 c2 d2 e2 f2 →
    a1 = a2 ∧ b1 = b2 ∧ c1 = c2 ∧ d1 = d2 ∧ e1 = e2 ∧ f1 = f2)

/-- Effective root digest embedded into .olean when -R is disabled (0 when -R is active). -/
def effectiveOleanRootTag (cfg : ReproBuildConfig) : Nat :=
  if cfg.useRelRootFlag then 0 else cfg.workspaceRootHash

/-- Effective manifest digest impacting public .olean interface (models Issue-14986 leak). -/
def effectivePublicManifestTag (cfg : ReproBuildConfig) : Nat :=
  if cfg.privateLeakEqLemma then
    cfg.manifestPublicHash + cfg.manifestPrivHash + 1
  else
    cfg.manifestPublicHash

/-- Lake standard BuildTrace: includes toolchain, manifest, moreLeanArgs, moreLeancArgs, source;
    crucially OMITS workspaceRootHash (path-free) AND OMITS weakLeanArgs / weakLeancArgs. -/
def lakeBuildTrace (alg : ArtifactHashAlg) (cfg : ReproBuildConfig) : Nat :=
  alg.h6
    (alg.h2 cfg.toolchainVerHash cfg.toolchainGitHash)
    (alg.h2 cfg.manifestPublicHash cfg.manifestPrivHash)
    cfg.moreLeanArgsHash
    cfg.moreLeancArgsHash
    cfg.sourceTreeHash
    1

/-- ProofGate v3 strict audited trace: extends Lake BuildTrace with weakLeanArgs, weakLeancArgs,
    -R canonicalization bit, and workspace cleanliness bit to eliminate trace blindness. -/
def v3StrictAuditedTrace (alg : ArtifactHashAlg) (cfg : ReproBuildConfig) (cleanWs : Bool) : Nat :=
  alg.h6
    (lakeBuildTrace alg cfg)
    cfg.weakLeanArgsHash
    cfg.weakLeancArgsHash
    (if cfg.useRelRootFlag then 1 else 0)
    (if cleanWs then 1 else 0)
    2

/-- Public .olean artifact digest: sensitive to toolchain, public manifest (or Issue-14986 leak),
    all lean args (more + weak), source tree, and workspace root ONLY if -R is disabled. -/
def oleanPublicDigest (alg : ArtifactHashAlg) (cfg : ReproBuildConfig) : Nat :=
  alg.h6
    (alg.h2 cfg.toolchainVerHash cfg.toolchainGitHash)
    (effectivePublicManifestTag cfg)
    (alg.h2 cfg.moreLeanArgsHash cfg.weakLeanArgsHash)
    cfg.sourceTreeHash
    (effectiveOleanRootTag cfg)
    3

/-- Private .olean.private artifact digest: sensitive to both public and private manifest revs. -/
def oleanPrivateDigest (alg : ArtifactHashAlg) (cfg : ReproBuildConfig) : Nat :=
  alg.h6
    (alg.h2 cfg.toolchainVerHash cfg.toolchainGitHash)
    (alg.h2 cfg.manifestPublicHash cfg.manifestPrivHash)
    (alg.h2 cfg.moreLeanArgsHash cfg.weakLeanArgsHash)
    cfg.sourceTreeHash
    (effectiveOleanRootTag cfg)
    4

/-- Native object .c.o artifact digest: sensitive to both moreLeancArgs and weakLeancArgs. -/
def nativeObjectDigest (alg : ArtifactHashAlg) (cfg : ReproBuildConfig) : Nat :=
  alg.h6
    (alg.h2 cfg.toolchainVerHash cfg.toolchainGitHash)
    (alg.h2 cfg.manifestPublicHash cfg.manifestPrivHash)
    (alg.h2 cfg.moreLeanArgsHash cfg.weakLeanArgsHash)
    (alg.h2 cfg.moreLeancArgsHash cfg.weakLeancArgsHash)
    cfg.sourceTreeHash
    5

/-- Per-module .setup.json digest (Issue-16658): ALWAYS embeds absolute workspace root path
    together with transitive import paths, toolchain, manifest, and args. -/
def setupJsonDigest (alg : ArtifactHashAlg) (cfg : ReproBuildConfig) (transitiveImportCount : Nat) : Nat :=
  alg.h6
    cfg.workspaceRootHash
    (alg.h2 cfg.toolchainVerHash cfg.toolchainGitHash)
    (alg.h2 cfg.manifestPublicHash cfg.manifestPrivHash)
    cfg.moreLeanArgsHash
    transitiveImportCount
    6

-- ============================================================================
-- Issue-16591: Stale .olean Residue & Clean Workspace Enforcement
-- ============================================================================

/-- Stale .olean files present on disk that do not belong to any active declared module. -/
def staleOleanResidues (declaredModules diskOleans : List Nat) : List Nat :=
  diskOleans.filter (fun m => !(declaredModules.contains m))

/-- Clean workspace predicate: zero stale .olean residues from removed libraries (Issue-16591). -/
def isCleanWorkspace (declaredModules diskOleans : List Nat) : Bool :=
  (staleOleanResidues declaredModules diskOleans).isEmpty

/-- Deterministic workspace sanitizer removing all undeclared stale .olean artifacts. -/
def purgeStaleOleans (declaredModules diskOleans : List Nat) : List Nat :=
  diskOleans.filter (fun m => declaredModules.contains m)

-- ============================================================================
-- Issue-16658: Quadratic setup.json Transitive Path Surface vs Flat -R .olean
-- ============================================================================

/-- Cumulative transitive import path entries written across all per-module .setup.json files
    in a linear dependency chain of n modules: 1 + 2 + ... + n. -/
def sumSetupJsonPathEntries : Nat → Nat
  | 0 => 0
  | n + 1 => sumSetupJsonPathEntries n + (n + 1)

/-- Workspace-absolute path entries embedded in flat .olean files when -R is active (0)
    versus when -R is disabled (n). -/
def oleanWorkspacePathEntries (n : Nat) (useRelRoot : Bool) : Nat :=
  if useRelRoot then 0 else n

-- ============================================================================
-- Semantic Equivalence Plane & Unified ProofGate v3 Gate
-- ============================================================================

/-- Two-plane reproducibility and semantic verification evidence record. -/
structure SemanticEquivalenceEvidence where
  byteOleanEqual            : Bool
  byteSetupJsonEqual        : Bool
  lakeTraceEqual            : Bool
  leancheckerFresh1ThreadOk : Bool  -- leanchecker --fresh --threads=1 passed
  lakeComparatorOk          : Bool  -- lake comparator confirmed identical exported defs/theorems
  standardAxiomsOnly        : Bool  -- subset of {propext, Classical.choice, Quot.sound}
  zeroIncompleteProofs      : Bool  -- 0 incomplete proofs / 0 escape tokens
  cleanWorkspace            : Bool  -- Issue-16591: 0 stale .olean residues
  deriving DecidableEq, Repr

/-- Plane 2 semantic equivalence gate: resilient to benign byte divergence (e.g., setup.json
    path surface #16658 or parallel -j8 / sharing metadata #15498/#16647), fail-closed against
    forged .olean (#13615), stale residue (#16591), custom axioms, or incomplete proofs. -/
def verifySemanticEquivalence (ev : SemanticEquivalenceEvidence) : Bool :=
  ev.leancheckerFresh1ThreadOk &&
  ev.lakeComparatorOk &&
  ev.standardAxiomsOnly &&
  ev.zeroIncompleteProofs &&
  ev.cleanWorkspace

/-- Complete ProofGate v3 Reproducible Build Factor Lab receipt gate. -/
structure ProofGateV3ReceiptGate where
  runsCompleted            : Nat
  factorialCellsCovered    : Nat
  repeatabilityExact       : Bool
  probesCovered            : Nat
  weakArgsBlockedOrTraced  : Bool
  cleanWorkspaceEnforced   : Bool
  setupSurfaceSeparated    : Bool
  semanticEquivalencePass  : Bool
  customAxiomCount         : Nat
  incompleteProofCount     : Nat
  chr36Count               : Nat
  chr96Count               : Nat
  externalUrlCount         : Nat
  scriptTagCount           : Nat
  svgCount                 : Nat
  cspStyleHashValid        : Bool
  cspScriptNone            : Bool
  jcsReceiptValid          : Bool
  pbtTotal                 : Nat
  pbtPassed                : Nat
  adversarialTotal         : Nat
  adversarialPassed        : Nat
  deriving DecidableEq, Repr

/-- Fail-closed evaluator for ProofGate CI v3 reproducible build receipts. -/
def verifyProofGateV3Gate (g : ProofGateV3ReceiptGate) : Bool :=
  decide (g.runsCompleted = 12) &&
  decide (g.factorialCellsCovered = 8) &&
  g.repeatabilityExact &&
  decide (g.probesCovered = 3) &&
  g.weakArgsBlockedOrTraced &&
  g.cleanWorkspaceEnforced &&
  g.setupSurfaceSeparated &&
  g.semanticEquivalencePass &&
  decide (g.customAxiomCount = 0) &&
  decide (g.incompleteProofCount = 0) &&
  decide (g.chr36Count = 0) &&
  decide (g.chr96Count = 0) &&
  decide (g.externalUrlCount = 0) &&
  decide (g.scriptTagCount = 0) &&
  decide (2 ≤ g.svgCount) &&
  g.cspStyleHashValid &&
  g.cspScriptNone &&
  g.jcsReceiptValid &&
  decide (1500 ≤ g.pbtTotal) &&
  decide (g.pbtPassed = g.pbtTotal) &&
  decide (12 ≤ g.adversarialTotal) &&
  decide (g.adversarialPassed = g.adversarialTotal)

-- ============================================================================
-- Helper Lemmas
-- ============================================================================

private theorem list_filter_empty_iff {α : Type} (p : α → Bool) (xs : List α) :
    (xs.filter p).isEmpty = true ↔ ∀ x, x ∈ xs → p x = false := by
  induction xs with
  | nil =>
    simp
  | cons hd tl ih =>
    simp only [List.filter]
    cases hp : p hd with
    | false =>
      simp only [List.mem_cons, forall_eq_or_imp, hp, true_and]
      exact ih
    | true =>
      simp only [List.isEmpty_cons, Bool.false_eq_true, false_iff]
      intro hAll
      have hHd := hAll hd List.mem_cons_self
      rw [hp] at hHd
      exact Bool.noConfusion hHd

private theorem two_mul_sumSetupJsonPathEntries (n : Nat) :
    2 * sumSetupJsonPathEntries n = n * (n + 1) := by
  induction n with
  | zero => rfl
  | succ k ih =>
    simp only [sumSetupJsonPathEntries]
    have hDist : 2 * (sumSetupJsonPathEntries k + (k + 1)) = 2 * sumSetupJsonPathEntries k + 2 * (k + 1) := by
      omega
    rw [hDist, ih]
    have hAlg : k * (k + 1) + 2 * (k + 1) = (k + 1) * (k + 1 + 1) := by
      calc
        k * (k + 1) + 2 * (k + 1) = (k + 2) * (k + 1) := (Nat.add_mul k 2 (k + 1)).symm
        _ = (k + 1) * (k + 2) := Nat.mul_comm (k + 2) (k + 1)
        _ = (k + 1) * (k + 1 + 1) := rfl
    exact hAlg

-- ============================================================================
-- Main Theorems (22 formally proved theorems, 0 incomplete proofs, 0 axioms)
-- ============================================================================

/-- Theorem 01: The 2x2x2 factorial design has exactly 8 distinct cells and the complete
    DR-KONU-PG-27 schedule has exactly 12 distinct runs (8 + 1 D0_tekrar + 3 probes). -/
theorem thm01_factorial_2x2x2_and_12run_schedule_complete :
    allFactorialCells.length = 8 ∧
    allFactorialCells.Nodup ∧
    full12RunSchedule.length = 12 ∧
    full12RunSchedule.Nodup := by
  decide

/-- Theorem 02: Every possible (Y, A, B) triple appears in the 2x2x2 full factorial matrix. -/
theorem thm02_factorial_2x2x2_exhaustive (c : FactorialCell) :
    c ∈ allFactorialCells := by
  rcases c with ⟨y, a, b⟩
  cases y <;> cases a <;> cases b <;> decide

/-- Theorem 03: Factor Y isolation with -R active: changing workspaceRootHash alone leaves
    oleanPublicDigest, oleanPrivateDigest, and lakeBuildTrace invariant, while strictly
    mutating setupJsonDigest (Issue-16658 path-surface separation). -/
theorem thm03_factor_y_with_rel_root_isolates_setup_from_olean
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newRoot tcCount : Nat)
    (hRel : cfg.useRelRootFlag = true)
    (hDiffRoot : newRoot ≠ cfg.workspaceRootHash) :
    let cfgY := { cfg with workspaceRootHash := newRoot }
    oleanPublicDigest alg cfgY = oleanPublicDigest alg cfg ∧
    oleanPrivateDigest alg cfgY = oleanPrivateDigest alg cfg ∧
    lakeBuildTrace alg cfgY = lakeBuildTrace alg cfg ∧
    setupJsonDigest alg cfgY tcCount ≠ setupJsonDigest alg cfg tcCount := by
  dsimp only
  refine ⟨?_, ?_, ?_, ?_⟩
  · unfold oleanPublicDigest effectiveOleanRootTag effectivePublicManifestTag
    simp [hRel]
  · unfold oleanPrivateDigest effectiveOleanRootTag
    simp [hRel]
  · rfl
  · intro hEq
    unfold setupJsonDigest at hEq
    have hParts := hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq
    exact hDiffRoot hParts.1

/-- Theorem 04: Probe Sonda-Y1b (-R disabled): omitting -R causes workspaceRootHash drift
    to directly mutate oleanPublicDigest and oleanPrivateDigest while lakeBuildTrace stays blind. -/
theorem thm04_sonda_y1b_without_rel_root_leaks_path_into_olean
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newRoot : Nat)
    (hNoRel : cfg.useRelRootFlag = false)
    (hDiffRoot : newRoot ≠ cfg.workspaceRootHash) :
    let cfgY := { cfg with workspaceRootHash := newRoot }
    oleanPublicDigest alg cfgY ≠ oleanPublicDigest alg cfg ∧
    oleanPrivateDigest alg cfgY ≠ oleanPrivateDigest alg cfg ∧
    lakeBuildTrace alg cfgY = lakeBuildTrace alg cfg := by
  dsimp only
  refine ⟨?_, ?_, rfl⟩
  · intro hEq
    unfold oleanPublicDigest effectiveOleanRootTag at hEq
    simp only [hNoRel, Bool.false_eq_true, ↓reduceIte] at hEq
    have hParts := hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq
    exact hDiffRoot hParts.2.2.2.2.1
  · intro hEq
    unfold oleanPrivateDigest effectiveOleanRootTag at hEq
    simp only [hNoRel, Bool.false_eq_true, ↓reduceIte] at hEq
    have hParts := hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq
    exact hDiffRoot hParts.2.2.2.2.1

/-- Theorem 05: Factor A (lean-toolchain version change) strictly mutates oleanPublicDigest,
    oleanPrivateDigest, setupJsonDigest, and lakeBuildTrace simultaneously. -/
theorem thm05_factor_a_toolchain_version_mutates_all_artifacts
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newVer tcCount : Nat)
    (hDiffVer : newVer ≠ cfg.toolchainVerHash) :
    let cfgA := { cfg with toolchainVerHash := newVer }
    oleanPublicDigest alg cfgA ≠ oleanPublicDigest alg cfg ∧
    oleanPrivateDigest alg cfgA ≠ oleanPrivateDigest alg cfg ∧
    setupJsonDigest alg cfgA tcCount ≠ setupJsonDigest alg cfg tcCount ∧
    lakeBuildTrace alg cfgA ≠ lakeBuildTrace alg cfg := by
  dsimp only
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro hEq
    unfold oleanPublicDigest at hEq
    have h1 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).1
    exact hDiffVer (hInj.1 _ _ _ _ h1).1
  · intro hEq
    unfold oleanPrivateDigest at hEq
    have h1 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).1
    exact hDiffVer (hInj.1 _ _ _ _ h1).1
  · intro hEq
    unfold setupJsonDigest at hEq
    have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
    exact hDiffVer (hInj.1 _ _ _ _ h2).1
  · intro hEq
    unfold lakeBuildTrace at hEq
    have h1 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).1
    exact hDiffVer (hInj.1 _ _ _ _ h1).1

/-- Theorem 06: Probe Sonda-A1b (Issue-12681 githash-only drift under identical SemVer):
    changing toolchainGitHash alone still mutates .olean, .setup.json, and BuildTrace. -/
theorem thm06_sonda_a1b_toolchain_githash_only_mutates_all_artifacts
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newGit tcCount : Nat)
    (hDiffGit : newGit ≠ cfg.toolchainGitHash) :
    let cfgA1b := { cfg with toolchainGitHash := newGit }
    oleanPublicDigest alg cfgA1b ≠ oleanPublicDigest alg cfg ∧
    setupJsonDigest alg cfgA1b tcCount ≠ setupJsonDigest alg cfg tcCount ∧
    lakeBuildTrace alg cfgA1b ≠ lakeBuildTrace alg cfg := by
  dsimp only
  refine ⟨?_, ?_, ?_⟩
  · intro hEq
    unfold oleanPublicDigest at hEq
    have h1 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).1
    exact hDiffGit (hInj.1 _ _ _ _ h1).2
  · intro hEq
    unfold setupJsonDigest at hEq
    have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
    exact hDiffGit (hInj.1 _ _ _ _ h2).2
  · intro hEq
    unfold lakeBuildTrace at hEq
    have h1 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).1
    exact hDiffGit (hInj.1 _ _ _ _ h1).2

/-- Theorem 07: Factor B public signature revision change strictly mutates oleanPublicDigest,
    oleanPrivateDigest, setupJsonDigest, and lakeBuildTrace. -/
theorem thm07_factor_b_public_manifest_rev_mutates_public_and_private
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newPub tcCount : Nat)
    (hNoLeak : cfg.privateLeakEqLemma = false)
    (hDiffPub : newPub ≠ cfg.manifestPublicHash) :
    let cfgB := { cfg with manifestPublicHash := newPub }
    oleanPublicDigest alg cfgB ≠ oleanPublicDigest alg cfg ∧
    oleanPrivateDigest alg cfgB ≠ oleanPrivateDigest alg cfg ∧
    setupJsonDigest alg cfgB tcCount ≠ setupJsonDigest alg cfg tcCount ∧
    lakeBuildTrace alg cfgB ≠ lakeBuildTrace alg cfg := by
  dsimp only
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro hEq
    unfold oleanPublicDigest effectivePublicManifestTag at hEq
    simp only [hNoLeak, Bool.false_eq_true, ↓reduceIte] at hEq
    have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
    exact hDiffPub h2
  · intro hEq
    unfold oleanPrivateDigest at hEq
    have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
    exact hDiffPub (hInj.1 _ _ _ _ h2).1
  · intro hEq
    unfold setupJsonDigest at hEq
    have h3 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.2.1
    exact hDiffPub (hInj.1 _ _ _ _ h3).1
  · intro hEq
    unfold lakeBuildTrace at hEq
    have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
    exact hDiffPub (hInj.1 _ _ _ _ h2).1

/-- Theorem 08: Probe Sonda-B1b (private-only lake-manifest rev change without Issue-14986 leak):
    oleanPublicDigest stays invariant while oleanPrivateDigest and lakeBuildTrace strictly mutate. -/
theorem thm08_sonda_b1b_private_manifest_rev_preserves_public_olean
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newPriv : Nat)
    (hNoLeak : cfg.privateLeakEqLemma = false)
    (hDiffPriv : newPriv ≠ cfg.manifestPrivHash) :
    let cfgB1b := { cfg with manifestPrivHash := newPriv }
    oleanPublicDigest alg cfgB1b = oleanPublicDigest alg cfg ∧
    oleanPrivateDigest alg cfgB1b ≠ oleanPrivateDigest alg cfg ∧
    lakeBuildTrace alg cfgB1b ≠ lakeBuildTrace alg cfg := by
  dsimp only
  refine ⟨?_, ?_, ?_⟩
  · unfold oleanPublicDigest effectivePublicManifestTag effectiveOleanRootTag
    simp [hNoLeak]
  · intro hEq
    unfold oleanPrivateDigest at hEq
    have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
    exact hDiffPriv (hInj.1 _ _ _ _ h2).2
  · intro hEq
    unfold lakeBuildTrace at hEq
    have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
    exact hDiffPriv (hInj.1 _ _ _ _ h2).2

/-- Theorem 09: Issue-14986 private-to-public equation-theorem leak breaks Sonda-B1b public
    invariance, causing a private manifest rev change to mutate oleanPublicDigest. -/
theorem thm09_issue14986_private_eq_leak_mutates_public_olean
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newPriv : Nat)
    (hLeak : cfg.privateLeakEqLemma = true)
    (hDiffPriv : newPriv ≠ cfg.manifestPrivHash) :
    let cfgLeak := { cfg with manifestPrivHash := newPriv }
    oleanPublicDigest alg cfgLeak ≠ oleanPublicDigest alg cfg := by
  dsimp only
  intro hEq
  unfold oleanPublicDigest effectivePublicManifestTag at hEq
  simp only [hLeak, ↓reduceIte] at hEq
  have h2 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.1
  omega

/-- Theorem 10: Lake weakLeanArgs trace blindness — mutating weakLeanArgs leaves Lake
    BuildTrace identical while strictly diverging oleanPublicDigest and nativeObjectDigest. -/
theorem thm10_lake_weakLeanArgs_trace_blindness
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newWeakLean : Nat)
    (hDiffWeak : newWeakLean ≠ cfg.weakLeanArgsHash) :
    let cfgWeak := { cfg with weakLeanArgsHash := newWeakLean }
    lakeBuildTrace alg cfgWeak = lakeBuildTrace alg cfg ∧
    oleanPublicDigest alg cfgWeak ≠ oleanPublicDigest alg cfg ∧
    nativeObjectDigest alg cfgWeak ≠ nativeObjectDigest alg cfg := by
  dsimp only
  refine ⟨rfl, ?_, ?_⟩
  · intro hEq
    unfold oleanPublicDigest at hEq
    have h3 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.2.1
    exact hDiffWeak (hInj.1 _ _ _ _ h3).2
  · intro hEq
    unfold nativeObjectDigest at hEq
    have h3 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.2.1
    exact hDiffWeak (hInj.1 _ _ _ _ h3).2

/-- Theorem 11: Lake weakLeancArgs trace blindness — mutating weakLeancArgs leaves Lake
    BuildTrace identical while strictly diverging nativeObjectDigest (.c.o binary). -/
theorem thm11_lake_weakLeancArgs_trace_blindness
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newWeakLeanc : Nat)
    (hDiffWeakC : newWeakLeanc ≠ cfg.weakLeancArgsHash) :
    let cfgWeakC := { cfg with weakLeancArgsHash := newWeakLeanc }
    lakeBuildTrace alg cfgWeakC = lakeBuildTrace alg cfg ∧
    nativeObjectDigest alg cfgWeakC ≠ nativeObjectDigest alg cfg := by
  dsimp only
  refine ⟨rfl, ?_⟩
  intro hEq
  unfold nativeObjectDigest at hEq
  have h4 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.2.2.1
  exact hDiffWeakC (hInj.1 _ _ _ _ h4).2

/-- Theorem 12: Lake moreLeanArgs and moreLeancArgs provide full BuildTrace coverage —
    any mutation strictly alters lakeBuildTrace (zero silent cache reuse). -/
theorem thm12_moreLeanArgs_and_moreLeancArgs_full_trace_coverage
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (cfg : ReproBuildConfig) (newMoreLean newMoreLeanc : Nat)
    (hDiffL : newMoreLean ≠ cfg.moreLeanArgsHash)
    (hDiffC : newMoreLeanc ≠ cfg.moreLeancArgsHash) :
    lakeBuildTrace alg { cfg with moreLeanArgsHash := newMoreLean } ≠ lakeBuildTrace alg cfg ∧
    lakeBuildTrace alg { cfg with moreLeancArgsHash := newMoreLeanc } ≠ lakeBuildTrace alg cfg := by
  refine ⟨?_, ?_⟩
  · intro hEq
    unfold lakeBuildTrace at hEq
    have h3 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.2.1
    exact hDiffL h3
  · intro hEq
    unfold lakeBuildTrace at hEq
    have h4 := (hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hEq).2.2.2.1
    exact hDiffC h4

/-- Theorem 13: ProofGate v3 strict audited trace completely closes weakLeanArgs and
    weakLeancArgs trace blindness: equal v3 traces force identical .olean and .c.o digests
    under canonical -R mode. -/
theorem thm13_v3_strict_trace_eliminates_weak_arg_blindness
    (alg : ArtifactHashAlg) (hInj : alg.Injective)
    (c1 c2 : ReproBuildConfig) (ws1 ws2 : Bool)
    (hRel1 : c1.useRelRootFlag = true)
    (hNoLeak1 : c1.privateLeakEqLemma = false)
    (hNoLeak2 : c2.privateLeakEqLemma = false)
    (hV3Eq : v3StrictAuditedTrace alg c1 ws1 = v3StrictAuditedTrace alg c2 ws2) :
    oleanPublicDigest alg c1 = oleanPublicDigest alg c2 ∧
    oleanPrivateDigest alg c1 = oleanPrivateDigest alg c2 ∧
    nativeObjectDigest alg c1 = nativeObjectDigest alg c2 := by
  unfold v3StrictAuditedTrace at hV3Eq
  have hOuter := hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hV3Eq
  have hLakeEq : lakeBuildTrace alg c1 = lakeBuildTrace alg c2 := hOuter.1
  have hWeakLEq : c1.weakLeanArgsHash = c2.weakLeanArgsHash := hOuter.2.1
  have hWeakCEq : c1.weakLeancArgsHash = c2.weakLeancArgsHash := hOuter.2.2.1
  have hRelBitEq : (if c1.useRelRootFlag then 1 else 0) = (if c2.useRelRootFlag then 1 else 0) :=
    hOuter.2.2.2.1
  have hRel2 : c2.useRelRootFlag = true := by
    cases h : c2.useRelRootFlag
    · simp [hRel1, h] at hRelBitEq
    · rfl
  unfold lakeBuildTrace at hLakeEq
  have hInner := hInj.2.2 _ _ _ _ _ _ _ _ _ _ _ _ hLakeEq
  have hTcEq := hInj.1 _ _ _ _ hInner.1
  have hManEq := hInj.1 _ _ _ _ hInner.2.1
  have hMoreLEq : c1.moreLeanArgsHash = c2.moreLeanArgsHash := hInner.2.2.1
  have hMoreCEq : c1.moreLeancArgsHash = c2.moreLeancArgsHash := hInner.2.2.2.1
  have hSrcEq : c1.sourceTreeHash = c2.sourceTreeHash := hInner.2.2.2.2.1
  refine ⟨?_, ?_, ?_⟩
  · unfold oleanPublicDigest effectivePublicManifestTag effectiveOleanRootTag
    simp [hRel1, hRel2, hNoLeak1, hNoLeak2, hTcEq.1, hTcEq.2, hManEq.1, hMoreLEq, hWeakLEq, hSrcEq]
  · unfold oleanPrivateDigest effectiveOleanRootTag
    simp [hRel1, hRel2, hTcEq.1, hTcEq.2, hManEq.1, hManEq.2, hMoreLEq, hWeakLEq, hSrcEq]
  · unfold nativeObjectDigest
    simp [hTcEq.1, hTcEq.2, hManEq.1, hManEq.2, hMoreLEq, hWeakLEq, hMoreCEq, hWeakCEq, hSrcEq]

/-- Theorem 14: Issue-16591 stale .olean residue rejection — if any deleted library leaves
    an undeclared .olean on disk, isCleanWorkspace fails closed with non-empty residue list. -/
theorem thm14_issue16591_stale_olean_residue_rejected
    (declared disk : List Nat) (staleMod : Nat)
    (hOnDisk : staleMod ∈ disk)
    (hNotDecl : declared.contains staleMod = false) :
    isCleanWorkspace declared disk = false ∧
    staleMod ∈ staleOleanResidues declared disk := by
  have hInRes : staleMod ∈ staleOleanResidues declared disk := by
    unfold staleOleanResidues
    rw [List.mem_filter]
    exact ⟨hOnDisk, by rw [hNotDecl]; rfl⟩
  refine ⟨?_, hInRes⟩
  unfold isCleanWorkspace
  cases hList : staleOleanResidues declared disk with
  | nil =>
    rw [hList] at hInRes
    cases hInRes
  | cons _ _ =>
    rfl

/-- Theorem 15: Clean workspace soundness characterization — isCleanWorkspace holds if and
    only if every .olean artifact on disk belongs to an active declared library. -/
theorem thm15_clean_workspace_iff_all_disk_oleans_declared
    (declared disk : List Nat) :
    isCleanWorkspace declared disk = true ↔
    ∀ m, m ∈ disk → declared.contains m = true := by
  unfold isCleanWorkspace staleOleanResidues
  rw [list_filter_empty_iff]
  constructor
  · intro h m hm
    have hNot := h m hm
    cases hc : declared.contains m with
    | true => rfl
    | false =>
      rw [hc] at hNot
      cases hNot
  · intro h m hm
    rw [h m hm]
    rfl

/-- Theorem 16: Purging stale .olean residues always yields a clean workspace and is idempotent. -/
theorem thm16_purge_stale_oleans_restores_clean_workspace_and_idempotent
    (declared disk : List Nat) :
    isCleanWorkspace declared (purgeStaleOleans declared disk) = true ∧
    purgeStaleOleans declared (purgeStaleOleans declared disk) = purgeStaleOleans declared disk := by
  refine ⟨?_, ?_⟩
  · rw [thm15_clean_workspace_iff_all_disk_oleans_declared]
    intro m hm
    unfold purgeStaleOleans at hm
    exact (List.mem_filter.mp hm).2
  · unfold purgeStaleOleans
    induction disk with
    | nil => rfl
    | cons hd tl ih =>
      simp only [List.filter]
      cases hc : declared.contains hd with
      | false => exact ih
      | true =>
        simp only [List.filter, hc, ih]

/-- Theorem 17: Issue-16658 exact quadratic scaling of per-module .setup.json transitive path
    surface: sumSetupJsonPathEntries n = n * (n + 1) / 2. -/
theorem thm17_issue16658_setup_json_quadratic_exact_closed_form (n : Nat) :
    sumSetupJsonPathEntries n = n * (n + 1) / 2 := by
  have h2 := two_mul_sumSetupJsonPathEntries n
  omega

/-- Theorem 18: Issue-16658 strict quadratic dominance over flat .olean count and zero-path
    canonical -R .olean surface for all module chains of length n >= 2. -/
theorem thm18_issue16658_setup_json_dominates_flat_olean (n : Nat) (hn : 2 ≤ n) :
    n < sumSetupJsonPathEntries n ∧
    oleanWorkspacePathEntries n true = 0 ∧
    oleanWorkspacePathEntries n true < sumSetupJsonPathEntries n := by
  have h2 := two_mul_sumSetupJsonPathEntries n
  have h1 : 3 ≤ n + 1 := by omega
  have h3n : n * 3 ≤ n * (n + 1) := Nat.mul_le_mul_left n h1
  have h2n : 2 * n < n * 3 := by omega
  have hMul : 2 * n < n * (n + 1) := Nat.lt_of_lt_of_le h2n h3n
  refine ⟨by omega, rfl, ?_⟩
  unfold oleanWorkspacePathEntries
  simp only [↓reduceIte]
  omega

/-- Theorem 19: Semantic equivalence resilience — when leanchecker --fresh --threads=1,
    lake comparator, standard axioms, zero incomplete proofs, and clean workspace all hold,
    Plane 2 certifies semantic proof equivalence even under benign byte divergence
    (e.g. Issue-16658 setup.json path diff or Issue-15498/16647 metadata jitter). -/
theorem thm19_semantic_equivalence_resilient_to_benign_byte_divergence
    (ev : SemanticEquivalenceEvidence)
    (hLc : ev.leancheckerFresh1ThreadOk = true)
    (hComp : ev.lakeComparatorOk = true)
    (hAx : ev.standardAxiomsOnly = true)
    (hInc : ev.zeroIncompleteProofs = true)
    (hClean : ev.cleanWorkspace = true) :
    verifySemanticEquivalence ev = true := by
  unfold verifySemanticEquivalence
  simp [hLc, hComp, hAx, hInc, hClean]

/-- Theorem 20: Issue-13615 forged .olean fail-closed rejection — even if all byte hashes
    match, failing leanchecker --fresh --threads=1, lake comparator, standard axioms,
    incomplete-proof freedom, or clean workspace strictly rejects semantic equivalence. -/
theorem thm20_issue13615_forged_olean_fails_closed_even_if_bytes_match
    (ev : SemanticEquivalenceEvidence)
    (hBad : ev.leancheckerFresh1ThreadOk = false ∨
            ev.lakeComparatorOk = false ∨
            ev.standardAxiomsOnly = false ∨
            ev.zeroIncompleteProofs = false ∨
            ev.cleanWorkspace = false) :
    verifySemanticEquivalence ev = false := by
  unfold verifySemanticEquivalence
  rcases hBad with h1 | h2 | h3 | h4 | h5
  · simp [h1]
  · simp [h2]
  · simp [h3]
  · simp [h4]
  · simp [h5]

/-- Theorem 21: Unified ProofGate v3 gate soundness and fail-closed completeness — PASS
    implies all 22 reproducible-build, clean-workspace, semantic, hygiene, and CSP3 invariants,
    and violating any core gate immediately yields FAIL. -/
theorem thm21_proofgate_v3_gate_soundness_and_fail_closed (g : ProofGateV3ReceiptGate) :
    (verifyProofGateV3Gate g = true →
      g.runsCompleted = 12 ∧
      g.factorialCellsCovered = 8 ∧
      g.repeatabilityExact = true ∧
      g.probesCovered = 3 ∧
      g.weakArgsBlockedOrTraced = true ∧
      g.cleanWorkspaceEnforced = true ∧
      g.setupSurfaceSeparated = true ∧
      g.semanticEquivalencePass = true ∧
      g.customAxiomCount = 0 ∧
      g.incompleteProofCount = 0 ∧
      g.chr36Count = 0 ∧
      g.chr96Count = 0 ∧
      g.externalUrlCount = 0 ∧
      g.scriptTagCount = 0 ∧
      2 ≤ g.svgCount ∧
      g.cspStyleHashValid = true ∧
      g.cspScriptNone = true ∧
      g.jcsReceiptValid = true ∧
      1500 ≤ g.pbtTotal ∧
      g.pbtPassed = g.pbtTotal ∧
      12 ≤ g.adversarialTotal ∧
      g.adversarialPassed = g.adversarialTotal) ∧
    ((g.runsCompleted ≠ 12 ∨
      g.weakArgsBlockedOrTraced = false ∨
      g.cleanWorkspaceEnforced = false ∨
      g.semanticEquivalencePass = false ∨
      0 < g.chr36Count ∨
      0 < g.chr96Count ∨
      g.pbtTotal < 1500 ∨
      g.adversarialTotal < 12) →
      verifyProofGateV3Gate g = false) := by
  constructor
  · intro hPass
    rcases g with ⟨rc, fc, rep, pr, wa, cw, ss, se, ca, inc, c36, c96, eu, sc, sv, sh, sn, jr, pt, pp, atot, ap⟩
    unfold verifyProofGateV3Gate at hPass
    simp only [Bool.and_eq_true, decide_eq_true_eq] at hPass
    exact ⟨hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
           hPass.1.1.1.1.1.1.1.1.1.1.1.1.1.1.2,
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
    unfold verifyProofGateV3Gate
    rcases hBad with h1 | h2 | h3 | h4 | h5 | h6 | h7 | h8
    · simp [h1]
    · simp [h2]
    · simp [h3]
    · simp [h4]
    · simp [Nat.ne_of_gt h5]
    · simp [Nat.ne_of_gt h6]
    · have hNot : ¬ (1500 ≤ g.pbtTotal) := Nat.not_le_of_gt h7
      simp [hNot]
    · have hNot : ¬ (12 ≤ g.adversarialTotal) := Nat.not_le_of_gt h8
      simp [hNot]

-- Concrete decidable witness definitions for Theorem 22
private def demoAlg : ArtifactHashAlg :=
  { h2 := fun a b => a * 1009 + b * 37 + 7
  , h4 := fun a b c d => a * 100003 + b * 1009 + c * 37 + d + 11
  , h6 := fun a b c d e f => a * 10000019 + b * 100003 + c * 1009 + d * 131 + e * 17 + f
  }

private def demoD0 : ReproBuildConfig :=
  { workspaceRootHash := 101
  , useRelRootFlag := true
  , toolchainVerHash := 4360
  , toolchainGitHash := 6111
  , manifestPublicHash := 7001
  , manifestPrivHash := 8001
  , privateLeakEqLemma := false
  , moreLeanArgsHash := 501
  , moreLeancArgsHash := 601
  , weakLeanArgsHash := 0
  , weakLeancArgsHash := 0
  , sourceTreeHash := 9001
  }

private def demoD1PathShift : ReproBuildConfig :=
  { demoD0 with workspaceRootHash := 202 }

private def demoWeakInject : ReproBuildConfig :=
  { demoD0 with weakLeanArgsHash := 999 }

private def demoSondaB1b : ReproBuildConfig :=
  { demoD0 with manifestPrivHash := 8002 }

private def demoV3GatePass : ProofGateV3ReceiptGate :=
  { runsCompleted := 12
  , factorialCellsCovered := 8
  , repeatabilityExact := true
  , probesCovered := 3
  , weakArgsBlockedOrTraced := true
  , cleanWorkspaceEnforced := true
  , setupSurfaceSeparated := true
  , semanticEquivalencePass := true
  , customAxiomCount := 0
  , incompleteProofCount := 0
  , chr36Count := 0
  , chr96Count := 0
  , externalUrlCount := 0
  , scriptTagCount := 0
  , svgCount := 3
  , cspStyleHashValid := true
  , cspScriptNone := true
  , jcsReceiptValid := true
  , pbtTotal := 1600
  , pbtPassed := 1600
  , adversarialTotal := 14
  , adversarialPassed := 14
  }

private def demoV3GateStaleFail : ProofGateV3ReceiptGate :=
  { demoV3GatePass with cleanWorkspaceEnforced := false }

/-- Theorem 22: Concrete decidable end-to-end witness certifying D0/D1 path separation,
    weakLeanArgs trace blindness vs v3 strict trace catch, Sonda-B1b private invariance,
    Issue-16591 stale residue purge, Issue-16658 quadratic table, and v3 gate verdict. -/
theorem thm22_canonical_proofgate_v3_end_to_end_witness :
    oleanPublicDigest demoAlg demoD1PathShift = oleanPublicDigest demoAlg demoD0 ∧
    setupJsonDigest demoAlg demoD1PathShift 10 ≠ setupJsonDigest demoAlg demoD0 10 ∧
    lakeBuildTrace demoAlg demoWeakInject = lakeBuildTrace demoAlg demoD0 ∧
    oleanPublicDigest demoAlg demoWeakInject ≠ oleanPublicDigest demoAlg demoD0 ∧
    v3StrictAuditedTrace demoAlg demoWeakInject true ≠ v3StrictAuditedTrace demoAlg demoD0 true ∧
    oleanPublicDigest demoAlg demoSondaB1b = oleanPublicDigest demoAlg demoD0 ∧
    oleanPrivateDigest demoAlg demoSondaB1b ≠ oleanPrivateDigest demoAlg demoD0 ∧
    isCleanWorkspace [1, 2, 3] [1, 2, 3, 99] = false ∧
    isCleanWorkspace [1, 2, 3] (purgeStaleOleans [1, 2, 3] [1, 2, 3, 99]) = true ∧
    sumSetupJsonPathEntries 16 = 136 ∧
    oleanWorkspacePathEntries 16 true = 0 ∧
    verifyProofGateV3Gate demoV3GatePass = true ∧
    verifyProofGateV3Gate demoV3GateStaleFail = false := by
  decide

#print axioms thm01_factorial_2x2x2_and_12run_schedule_complete
#print axioms thm02_factorial_2x2x2_exhaustive
#print axioms thm03_factor_y_with_rel_root_isolates_setup_from_olean
#print axioms thm04_sonda_y1b_without_rel_root_leaks_path_into_olean
#print axioms thm05_factor_a_toolchain_version_mutates_all_artifacts
#print axioms thm06_sonda_a1b_toolchain_githash_only_mutates_all_artifacts
#print axioms thm07_factor_b_public_manifest_rev_mutates_public_and_private
#print axioms thm08_sonda_b1b_private_manifest_rev_preserves_public_olean
#print axioms thm09_issue14986_private_eq_leak_mutates_public_olean
#print axioms thm10_lake_weakLeanArgs_trace_blindness
#print axioms thm11_lake_weakLeancArgs_trace_blindness
#print axioms thm12_moreLeanArgs_and_moreLeancArgs_full_trace_coverage
#print axioms thm13_v3_strict_trace_eliminates_weak_arg_blindness
#print axioms thm14_issue16591_stale_olean_residue_rejected
#print axioms thm15_clean_workspace_iff_all_disk_oleans_declared
#print axioms thm16_purge_stale_oleans_restores_clean_workspace_and_idempotent
#print axioms thm17_issue16658_setup_json_quadratic_exact_closed_form
#print axioms thm18_issue16658_setup_json_dominates_flat_olean
#print axioms thm19_semantic_equivalence_resilient_to_benign_byte_divergence
#print axioms thm20_issue13615_forged_olean_fails_closed_even_if_bytes_match
#print axioms thm21_proofgate_v3_gate_soundness_and_fail_closed
#print axioms thm22_canonical_proofgate_v3_end_to_end_witness

end AlpLab.Konu3.ProofGateV3ReproBuild
