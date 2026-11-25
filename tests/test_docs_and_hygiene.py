"""Repository-wide hygiene, KURAL-3 chr(36)==0, Strict-CSP3 docs/index.html, and formal Lean hygiene tests."""
from __future__ import annotations

import base64
import hashlib
import pathlib
import re
import unittest

import proofgate

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestDocsAndHygiene(unittest.TestCase):
    def test_package_version_and_pyproject_v1(self) -> None:
        self.assertEqual(proofgate.__version__, "1.1.0")
        pyproj = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "1.1.0"', pyproj)

    def test_repo_wide_zero_chr36_kural3_compliance(self) -> None:
        violations = []
        for path in sorted(REPO_ROOT.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            if rel.startswith(".git/") or "__pycache__/" in rel or ".egg-info/" in rel:
                continue
            cnt = path.read_bytes().count(36)
            if cnt:
                violations.append((rel, cnt))
        self.assertEqual(violations, [], f"Found literal chr(36) in repo files: {violations}")

    def test_docs_index_html_strict_csp3_hashes_and_zero_external_urls(self) -> None:
        html_text = (REPO_ROOT / "docs" / "index.html").read_text(encoding="utf-8")

        self.assertNotIn(chr(36), html_text)
        self.assertNotIn(chr(96), html_text)
        self.assertNotIn("unsafe-inline", html_text.lower())
        self.assertNotIn("http://", html_text.lower())
        self.assertNotIn("https://", html_text.lower())

        m_csp = re.search(
            r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"',
            html_text,
        )
        self.assertIsNotNone(m_csp)
        csp = m_csp.group(1)
        for req in ("default-src 'none'", "connect-src 'none'", "object-src 'none'", "form-action 'none'", "base-uri 'none'"):
            self.assertIn(req, csp)

        m_style = re.search(r"<style>([\s\S]*?)</style>", html_text)
        m_script = re.search(r"<script>([\s\S]*?)</script>", html_text)
        self.assertIsNotNone(m_style)
        self.assertIsNotNone(m_script)

        style_b64 = base64.b64encode(hashlib.sha256(m_style.group(1).encode("utf-8")).digest()).decode("ascii")
        script_b64 = base64.b64encode(hashlib.sha256(m_script.group(1).encode("utf-8")).digest()).decode("ascii")

        self.assertIn(f"style-src 'sha256-{style_b64}'", csp)
        self.assertIn(f"script-src 'sha256-{script_b64}'", csp)

        # Ensure no inline style="..." or on*= attributes exist outside <script>
        html_no_script = re.sub(r"<script>[\s\S]*?</script>", "", html_text)
        self.assertIsNone(re.search(r'\sstyle\s*=', html_no_script, re.I))
        self.assertIsNone(re.search(r'\son[a-z]+\s*=', html_no_script, re.I))

    def test_docs_index_html_studio_sections_present(self) -> None:
        html_text = (REPO_ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        for marker in (
            "ProofGate v1.0 Omni-Gate",
            "panelLean",
            "panelAst",
            "panelCrypto",
            "panelEval",
            "panelMatrix",
            "<svg",
        ):
            self.assertIn(marker, html_text)

    def test_formal_omnigate_soundness_lean_hygiene(self) -> None:
        lean_text = (REPO_ROOT / "formal" / "ProofGateV1OmniGateSoundness.lean").read_text(encoding="utf-8")
        self.assertNotIn("sorry", lean_text.lower())
        self.assertIn("set_option autoImplicit false", lean_text)
        self.assertIn("set_option warningAsError true", lean_text)
        pub_theorems = re.findall(r"(?m)^theorem\s+([A-Za-z0-9_]+)\b", lean_text)
        self.assertGreaterEqual(len(pub_theorems), 14)
        for thm in pub_theorems:
            self.assertIn(f"#print axioms {thm}", lean_text)


if __name__ == "__main__":
    unittest.main()
