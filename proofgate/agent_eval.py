"""Multi-agent trajectory evaluator with lexicographic 4-gate/6-tier lattice, Wilson LCB, and Page-CUSUM."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime as _dt
import math
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

WILSON_Z_95: float = 1.959963984540054


def _is_strict_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def wilson_ci_bps(successes: int, total: int, z: float = WILSON_Z_95) -> Tuple[int, int]:
    """Compute two-sided Wilson score (lower_bps, upper_bps) in [0, 10000]."""
    if not _is_strict_int(successes) or not _is_strict_int(total):
        raise TypeError("successes and total must be integers")
    if total <= 0:
        return 0, 0
    if successes < 0 or successes > total:
        raise ValueError(f"successes ({successes}) must satisfy 0 <= successes <= total ({total})")
    if z < 0.0 or not math.isfinite(z):
        raise ValueError("z must be finite and non-negative")

    n = float(total)
    p = float(successes) / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = p + z2 / (2.0 * n)
    margin = z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)
    low = max(0.0, (center - margin) / denom)
    high = min(1.0, (center + margin) / denom)
    return int(math.floor(low * 10_000.0 + 1e-12)), int(math.ceil(high * 10_000.0 - 1e-12))


def wilson_lcb_bps(successes: int, total: int, z: float = WILSON_Z_95) -> int:
    """Return the Wilson 95% lower confidence bound in basis points [0, 10000]."""
    lcb, _ = wilson_ci_bps(successes, total, z=z)
    return lcb


@dataclass(frozen=True)
class CusumStepResult:
    step: int
    value: float
    cusum: float
    quarantined: bool
    peak_cusum: float


class PageCusumDetector:
    """One-sided sequential Page-CUSUM drift detector for fail-closed fleet quarantine."""

    def __init__(self, *, target: float = 0.05, slack: float = 0.05, threshold: float = 1.5) -> None:
        if target < 0.0 or slack < 0.0 or threshold <= 0.0:
            raise ValueError("PageCusumDetector requires target >= 0, slack >= 0, threshold > 0")
        self.target = float(target)
        self.slack = float(slack)
        self.threshold = float(threshold)
        self.reset()

    def reset(self) -> None:
        self._step = 0
        self._cusum = 0.0
        self._peak = 0.0
        self._quarantined = False
        self._first_alarm_step: Optional[int] = None

    @property
    def cusum(self) -> float:
        return self._cusum

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    @property
    def first_alarm_step(self) -> Optional[int]:
        return self._first_alarm_step

    def update(self, value: float) -> CusumStepResult:
        if not math.isfinite(value):
            raise ValueError("CUSUM observation must be finite")
        self._step += 1
        self._cusum = max(0.0, self._cusum + float(value) - self.target - self.slack)
        if self._cusum > self._peak:
            self._peak = self._cusum
        if self._cusum >= self.threshold:
            self._quarantined = True
            if self._first_alarm_step is None:
                self._first_alarm_step = self._step
        return CusumStepResult(
            step=self._step,
            value=float(value),
            cusum=round(self._cusum, 6),
            quarantined=self._quarantined,
            peak_cusum=round(self._peak, 6),
        )

    def evaluate_series(self, values: Sequence[float]) -> Dict[str, Any]:
        self.reset()
        steps = [asdict(self.update(v)) for v in values]
        return {
            "quarantined": self._quarantined,
            "first_alarm_step": self._first_alarm_step,
            "final_cusum": round(self._cusum, 6),
            "peak_cusum": round(self._peak, 6),
            "threshold": self.threshold,
            "steps": steps,
        }


def lexicographic_4gate_bps(
    *,
    p0_fake_commit: int = 0,
    p0_trivial_proof: int = 0,
    p0_missing_file: int = 0,
    p0_axiom_bypass: int = 0,
    p0_copy_output: int = 0,
    p1_mode_mismatch: int = 0,
    p1_no_mode_proof: int = 0,
    p1_short_output: int = 0,
    p1_instant_duration: int = 0,
    git_sha_present: bool = True,
    roots_synced: bool = True,
    lean_zero_sorry: bool = True,
    lean_axioms_clean: bool = True,
    referee_reachable: bool = True,
    referee_distinct_family: bool = True,
    referee_approved: bool = True,
    quality_bps: int = 10_000,
) -> int:
    """Non-compensatory 4-gate lexicographic score in basis points (Tier -6..Tier 0)."""
    ints = (
        p0_fake_commit, p0_trivial_proof, p0_missing_file, p0_axiom_bypass, p0_copy_output,
        p1_mode_mismatch, p1_no_mode_proof, p1_short_output, p1_instant_duration, quality_bps,
    )
    bools = (
        git_sha_present, roots_synced, lean_zero_sorry, lean_axioms_clean,
        referee_reachable, referee_distinct_family, referee_approved,
    )
    if any(not _is_strict_int(x) or x < 0 for x in ints) or quality_bps > 10_000 or any(not isinstance(b, bool) for b in bools):
        return -26_000

    p0_total = p0_fake_commit + p0_trivial_proof + p0_missing_file + p0_axiom_bypass + p0_copy_output
    if p0_total > 0:
        return -25_000
    if not (git_sha_present and roots_synced and lean_zero_sorry and lean_axioms_clean):
        return -24_000
    if not (referee_reachable and referee_distinct_family):
        return -23_000
    if not referee_approved:
        return -22_000

    penalty = (
        200 * p1_mode_mismatch
        + 500 * p1_no_mode_proof
        + 3000 * p1_short_output
        + 2000 * p1_instant_duration
    )
    return max(0, quality_bps - penalty)


def lexicographic_6tier_score(
    *,
    workspace_ok: bool,
    capability_ok: bool,
    provenance_ok: bool,
    liveness_ok: bool,
    budget_ok: bool,
    p1_total: int,
    quality_bps: int,
) -> int:
    """Non-compensatory 6-tier INV-13 score: hard gate fail <= 10004 < 10005 <= clean PASS."""
    if not workspace_ok:
        return 0
    if not capability_ok:
        return 1
    if not provenance_ok:
        return 2
    if not liveness_ok:
        return 3
    q_clamped = max(0, min(10_000, int(quality_bps)))
    if (not budget_ok) or p1_total > 0:
        return 4 + q_clamped
    return 10_005 + q_clamped


def evaluate_agent_run(
    run: Mapping[str, Any],
    *,
    pass_threshold_bps: int = 7500,
) -> Dict[str, Any]:
    """Evaluate a single multi-agent trajectory run under both 4-gate and 6-tier lattices."""
    run_id = str(run.get("run_id") or run.get("id") or "run-unknown")
    agent_name = str(run.get("agent") or run.get("provider") or "agent")

    p0_fake = int(run.get("p0_fake_commit", 0))
    p0_triv = int(run.get("p0_trivial_proof", 0))
    p0_miss = int(run.get("p0_missing_file", 0))
    p0_ax = int(run.get("p0_axiom_bypass", 0))
    p0_copy = int(run.get("p0_copy_output", 0))
    p0_extra = int(run.get("p0_defects", 0))
    p0_total = p0_fake + p0_triv + p0_miss + p0_ax + p0_copy + p0_extra

    p1_mode = int(run.get("p1_mode_mismatch", 0))
    p1_noproof = int(run.get("p1_no_mode_proof", 0))
    p1_short = int(run.get("p1_short_output", 0))
    p1_inst = int(run.get("p1_instant_duration", 0))
    p1_extra = int(run.get("p1_defects", 0))
    p1_total = p1_mode + p1_noproof + p1_short + p1_inst + p1_extra

    git_ok = bool(run.get("git_sha_present", True))
    roots_ok = bool(run.get("roots_synced", True))
    lean_sorry_ok = bool(run.get("lean_zero_sorry", True))
    lean_ax_ok = bool(run.get("lean_axioms_clean", True))
    ref_reach = bool(run.get("referee_reachable", True))
    ref_diff_fam = bool(run.get("referee_distinct_family", True))
    ref_approved = bool(run.get("referee_approved", True))

    ws_ok = bool(run.get("workspace_ok", p0_miss == 0))
    cap_ok = bool(run.get("capability_ok", True))
    live_ok = bool(run.get("liveness_ok", ref_reach and ref_diff_fam))
    bud_ok = bool(run.get("budget_ok", True))
    quality_bps = int(run.get("quality_bps", 10_000))
    duration_sec = float(run.get("duration_sec", 0.1))

    score_4g = lexicographic_4gate_bps(
        p0_fake_commit=p0_fake + p0_extra,
        p0_trivial_proof=p0_triv,
        p0_missing_file=p0_miss,
        p0_axiom_bypass=p0_ax,
        p0_copy_output=p0_copy,
        p1_mode_mismatch=p1_mode + p1_extra,
        p1_no_mode_proof=p1_noproof,
        p1_short_output=p1_short,
        p1_instant_duration=p1_inst,
        git_sha_present=git_ok,
        roots_synced=roots_ok,
        lean_zero_sorry=lean_sorry_ok,
        lean_axioms_clean=lean_ax_ok,
        referee_reachable=ref_reach,
        referee_distinct_family=ref_diff_fam,
        referee_approved=ref_approved,
        quality_bps=quality_bps,
    )
    prov_ok = git_ok and roots_ok and lean_sorry_ok and lean_ax_ok and (p0_total == 0)
    score_6t = lexicographic_6tier_score(
        workspace_ok=ws_ok,
        capability_ok=cap_ok,
        provenance_ok=prov_ok,
        liveness_ok=live_ok and ref_approved,
        budget_ok=bud_ok,
        p1_total=p1_total,
        quality_bps=quality_bps,
    )

    # Legacy additive linear baseline (demonstrates Linear Compensation Paradox)
    linear_pts = max(
        0,
        round(max(0, min(10_000, quality_bps)) / 100.0)
        - 15 * p0_miss
        - 20 * p0_triv
        - 40 * p0_copy
        - 25 * (p0_fake + p0_ax + p0_extra)
        - 20 * p1_inst
        - 30 * p1_short
        - 5 * p1_noproof
        - 2 * p1_mode,
    )
    linear_passed = linear_pts >= 75

    violations: List[str] = []
    if p0_total > 0 or score_4g == -25_000 or not ws_ok or not cap_ok:
        violations.append("REJECT_EVAL_P0_INTEGRITY")
    if not (git_ok and roots_ok and lean_sorry_ok and lean_ax_ok):
        violations.append("REJECT_EVAL_PROVENANCE")
    if not (ref_reach and ref_diff_fam and ref_approved and live_ok):
        violations.append("REJECT_EVAL_REFEREE")

    passed = (score_4g >= pass_threshold_bps) and (score_6t >= 10_005 or (p1_total > 0 and score_4g >= pass_threshold_bps and ws_ok and cap_ok and prov_ok and live_ok and ref_approved and bud_ok))
    if score_4g < 0:
        passed = False
    if not ws_ok or not cap_ok or not prov_ok or not live_ok or not ref_approved or not bud_ok:
        passed = False

    if not passed and not violations:
        violations.append("REJECT_EVAL_P0_INTEGRITY")

    verdict = "PASS" if passed else ("QUARANTINE" if score_4g == -23_000 else "FAIL")
    return {
        "run_id": run_id,
        "agent": agent_name,
        "verdict": verdict,
        "passed": passed,
        "score_4gate_bps": score_4g,
        "score_6tier": score_6t,
        "linear_baseline_score": linear_pts,
        "linear_baseline_passed": linear_passed,
        "linear_compensation_leak": bool(linear_passed and not passed),
        "violations": sorted(set(violations)),
        "duration_sec": duration_sec,
    }


def evaluate_fleet_runs(
    runs: Sequence[Mapping[str, Any]],
    *,
    pass_threshold_bps: int = 7500,
    min_wilson_lcb_bps: int = 7000,
    cusum_target: float = 0.05,
    cusum_slack: float = 0.05,
    cusum_threshold: float = 1.5,
) -> Dict[str, Any]:
    """Evaluate a sequence of multi-agent runs with lexicographic gating, Wilson LCB, and Page-CUSUM."""
    evaluated = [evaluate_agent_run(r, pass_threshold_bps=pass_threshold_bps) for r in runs]
    total = len(evaluated)
    passed_count = sum(1 for r in evaluated if r["passed"])
    failed_count = total - passed_count
    linear_leaks = sum(1 for r in evaluated if r["linear_compensation_leak"])

    lcb_bps, ucb_bps = wilson_ci_bps(passed_count, total) if total > 0 else (0, 0)
    cusum = PageCusumDetector(target=cusum_target, slack=cusum_slack, threshold=cusum_threshold)
    cusum_report = cusum.evaluate_series([0.0 if r["passed"] else 1.0 for r in evaluated])

    violations: List[str] = []
    findings: List[Dict[str, Any]] = []
    for idx, r in enumerate(evaluated, start=1):
        for v in r["violations"]:
            violations.append(v)
            findings.append({
                "code": v,
                "message": f"Run '{r['run_id']}' ({r['agent']}) failed gate with 4-gate={r['score_4gate_bps']} bps, 6-tier={r['score_6tier']}",
                "line": idx,
                "column": 1,
                "snippet": f"{r['run_id']}: verdict={r['verdict']}",
            })

    if total == 0 or lcb_bps < min_wilson_lcb_bps:
        violations.append("REJECT_EVAL_WILSON_LCB")
        findings.append({
            "code": "REJECT_EVAL_WILSON_LCB",
            "message": f"Fleet Wilson 95% LCB {lcb_bps} bps is below threshold {min_wilson_lcb_bps} bps ({passed_count}/{total})",
            "line": 1,
            "column": 1,
        })
    if cusum_report["quarantined"]:
        violations.append("REJECT_EVAL_CUSUM_QUARANTINE")
        findings.append({
            "code": "REJECT_EVAL_CUSUM_QUARANTINE",
            "message": f"Page-CUSUM drift quarantine triggered at step {cusum_report['first_alarm_step']} (peak={cusum_report['peak_cusum']})",
            "line": int(cusum_report["first_alarm_step"] or 1),
            "column": 1,
        })

    unique_v = sorted(set(violations))
    verdict = "ACCEPT" if (total > 0 and failed_count == 0 and not unique_v) else "REJECT"
    primary_code = "FLEET_EVAL_ACCEPT" if verdict == "ACCEPT" else unique_v[0]

    return {
        "verdict": verdict,
        "primary_code": primary_code,
        "violations": unique_v,
        "total_runs": total,
        "passed_runs": passed_count,
        "failed_runs": failed_count,
        "linear_compensation_leaks": linear_leaks,
        "wilson_lcb_bps": lcb_bps,
        "wilson_ucb_bps": ucb_bps,
        "min_wilson_lcb_bps": min_wilson_lcb_bps,
        "cusum_quarantined": bool(cusum_report["quarantined"]),
        "cusum_peak": cusum_report["peak_cusum"],
        "cusum_first_alarm_step": cusum_report["first_alarm_step"],
        "runs": evaluated,
        "findings": findings,
    }


def export_junit_xml(report: Mapping[str, Any], *, suite_name: str = "ProofGate.OmniGate") -> str:
    """Export an AgentEval fleet report (or gate result) as valid JUnit XML."""
    runs = report.get("runs")
    if isinstance(runs, list):
        testsuites = ET.Element("testsuites")
        failed_n = sum(1 for r in runs if not r.get("passed"))
        total_time = sum(float(r.get("duration_sec", 0.0)) for r in runs)
        ts = ET.SubElement(
            testsuites,
            "testsuite",
            name=suite_name,
            tests=str(len(runs)),
            failures=str(failed_n),
            errors="0",
            skipped="0",
            time=f"{total_time:.4f}",
        )
        props = ET.SubElement(ts, "properties")
        ET.SubElement(props, "property", name="wilson_lcb_bps", value=str(report.get("wilson_lcb_bps", 0)))
        ET.SubElement(props, "property", name="cusum_quarantined", value=str(report.get("cusum_quarantined", False)).lower())

        for r in runs:
            tc = ET.SubElement(
                ts,
                "testcase",
                classname=f"{suite_name}.{r.get('agent', 'agent')}",
                name=str(r.get("run_id", "run")),
                time=f"{float(r.get('duration_sec', 0.0)):.4f}",
            )
            if not r.get("passed"):
                viols = ",".join(r.get("violations") or [str(r.get("verdict", "FAIL"))])
                fail_el = ET.SubElement(
                    tc,
                    "failure",
                    message=f"Verdict={r.get('verdict')} score_4gate_bps={r.get('score_4gate_bps')} score_6tier={r.get('score_6tier')}",
                    type=viols,
                )
                fail_el.text = viols
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(testsuites, encoding="unicode")

    # Fallback for single-file check-lean / check-ast / diff-lean gate outputs
    verdict = str(report.get("verdict", "REJECT"))
    violations = list(report.get("violations") or [])
    testsuites = ET.Element("testsuites")
    ts = ET.SubElement(
        testsuites,
        "testsuite",
        name=suite_name,
        tests="1",
        failures="0" if verdict == "ACCEPT" else "1",
        errors="0",
        skipped="0",
    )
    tc = ET.SubElement(ts, "testcase", classname=suite_name, name=str(report.get("primary_code", "gate")))
    if verdict != "ACCEPT":
        fail_el = ET.SubElement(tc, "failure", message=str(report.get("primary_code", "REJECT")), type=",".join(violations))
        fail_el.text = "\n".join(violations)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(testsuites, encoding="unicode")


def export_promptfoo_json(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Export an AgentEval fleet report in Promptfoo v3 compatible JSON format."""
    runs = list(report.get("runs") or [])
    ts_iso = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    pf_results: List[Dict[str, Any]] = []
    successes = 0
    failures = 0
    for idx, r in enumerate(runs):
        ok = bool(r.get("passed"))
        if ok:
            successes += 1
        else:
            failures += 1
        norm_score = max(0.0, float(r.get("score_4gate_bps", 0))) / 10_000.0
        pf_results.append({
            "promptIdx": 0,
            "testIdx": idx,
            "provider": {"id": f"proofgate:{r.get('agent', 'agent')}"},
            "success": ok,
            "score": round(norm_score, 4),
            "namedScores": {
                "lexicographic_4gate_bps": r.get("score_4gate_bps", 0),
                "lexicographic_6tier": r.get("score_6tier", 0),
                "linear_baseline_score": r.get("linear_baseline_score", 0),
            },
            "gradingResult": {
                "pass": ok,
                "score": round(norm_score, 4),
                "reason": "PASS" if ok else ",".join(r.get("violations") or [str(r.get("verdict", "FAIL"))]),
                "componentResults": [
                    {
                        "pass": ok,
                        "score": round(norm_score, 4),
                        "reason": str(r.get("verdict", "FAIL")),
                    }
                ],
            },
            "metadata": {
                "run_id": r.get("run_id"),
                "linear_compensation_leak": r.get("linear_compensation_leak", False),
            },
        })

    return {
        "evalId": f"proofgate-{report.get('primary_code', 'eval').lower()}",
        "results": {
            "version": 3,
            "timestamp": ts_iso,
            "results": pf_results,
            "stats": {
                "successes": successes,
                "failures": failures,
                "errors": 0,
            },
        },
        "proofgateSummary": {
            "verdict": report.get("verdict"),
            "wilson_lcb_bps": report.get("wilson_lcb_bps", 0),
            "cusum_quarantined": report.get("cusum_quarantined", False),
            "linear_compensation_leaks": report.get("linear_compensation_leaks", 0),
        },
    }
