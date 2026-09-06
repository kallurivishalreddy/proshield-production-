"""
Frontend UI/UX regression tests (V2 FRONTEND / UI-UX UPGRADE pass).

These are static contract tests over ``frontend/`` that lock in the
fixes shipped in the analyst-UI quality upgrade:

1. RAW-MARKUP ROOT CAUSE — ``PSFmt.badge`` / ``PSFmt.pill`` must build
   real DOM elements. The old implementation returned HTML *strings*;
   ``PSUI.el()`` renders string children as text nodes, so every badge
   passed as an el() child printed literal ``<span class="pill
   medium">medium</span>`` markup on screen.
2. HUMAN-READABLE DISPLAY IDS — the ``ids.js`` registry must exist,
   must be loaded by every analyst page, and must be append-only /
   persisted (no renumbering).
3. WIRE-CONTRACT TRUTHFULNESS — components must not read response
   fields the backend never emits (the decorative columns that
   rendered "—"/fake values), and must not call operations that are
   not in the proxy's ALLOWED_OPERATIONS.
4. PAGE WIRING — every analyst page loads api.js → format.js →
   ids.js → layout.js → its component, in that order.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND = REPO_ROOT / "frontend"
JS = FRONTEND / "js"
COMPONENTS = JS / "components"
PROXY_PY = REPO_ROOT / "app" / "proxy" / "proxy.py"

PAGES = {
    "index.html": "overview.js",
    "cases.html": "cases.js",
    "case.html": "case.js",
    "detections.html": "detections.js",
    "correlations.html": "correlations.js",
    "timeline.html": "timeline.js",
    "sources.html": "sources.js",
    "rules.html": "rules.js",
    "health.html": "health.js",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. raw-markup root cause
# ---------------------------------------------------------------------------

def test_badge_and_pill_build_real_elements() -> None:
    src = read(COMPONENTS / "format.js")
    for fn in ("badge", "pill"):
        m = re.search(
            r"function %s\([^)]*\)\s*\{(.*?)\n    \}" % fn, src, re.S)
        assert m, f"format.js: {fn}() not found"
        body = m.group(1)
        assert "document.createElement" in body, (
            f"{fn}() must build a DOM element (raw-markup root cause)"
        )
        assert "return `<" not in body and "return \"<" not in body, (
            f"{fn}() must not return an HTML string"
        )


def test_no_component_returns_html_string_helpers() -> None:
    """No shared helper may hand HTML strings to the text-node builder."""
    for js in COMPONENTS.glob("*.js"):
        src = read(js)
        # template literals that open with a tag and are returned
        assert not re.search(r"return\s+`<(?:span|div|button|tr|td)\b", src), (
            f"{js.name} returns an HTML string (would render as raw markup)"
        )


def test_el_builder_still_flattens_arrays() -> None:
    """N-1 regression guard: el() must flatten nested child arrays."""
    src = read(COMPONENTS / "layout.js")
    assert "Array.isArray(c)" in src
    assert "c.nodeType ? c : document.createTextNode(String(c))" in src


def test_toasts_use_text_content_not_markup() -> None:
    src = read(COMPONENTS / "format.js")
    toast = re.search(r"function toast\(.*?\n    \}", src, re.S)
    assert toast, "format.js: toast() not found"
    assert "textContent" in toast.group(0)
    assert "innerHTML" not in toast.group(0)


# ---------------------------------------------------------------------------
# 2. human-readable display IDs
# ---------------------------------------------------------------------------

def test_ids_registry_exists_and_is_persisted() -> None:
    src = read(COMPONENTS / "ids.js")
    assert "PSIds" in src
    assert "registerAll" in src and "display" in src
    assert "localStorage" in src, "display ids must persist across reloads"
    # append-only: registering a known id keeps its number
    assert "known.has(id)" in src


def test_every_analyst_page_loads_ids_registry() -> None:
    for page in PAGES:
        html = read(FRONTEND / page)
        assert '/static/js/components/ids.js' in html, (
            f"{page} must load the display-id registry"
        )


def test_display_id_prefixes_are_deterministic_labels() -> None:
    src = read(COMPONENTS / "ids.js")
    for prefix in ("CASE", "DET", "CORR", "SRC", "RULE"):
        assert prefix in src


def test_components_never_headline_raw_uuids() -> None:
    """Case/detection/correlation tables must lead with the display id;
    the technical id is secondary (muted/mono or the tech panel)."""
    for name in ("cases.js", "case.js", "detections.js",
                 "correlations.js", "sources.js"):
        src = read(COMPONENTS / name)
        assert 'class: "display-id"' in src or 'display-id' in src, (
            f"{name} must render display ids"
        )


# ---------------------------------------------------------------------------
# 3. wire-contract truthfulness
# ---------------------------------------------------------------------------

def _decorative_fields_absent(component: str, fields: list[str]) -> None:
    """Assert the component never *accesses* the given field. Matching
    is done on accessor patterns (``.field`` / ``?.field``) so prose in
    docstrings that documents the removed fields does not trip it."""
    src = _strip_js_comments(read(COMPONENTS / component))
    for f in fields:
        assert not re.search(r"[?.\[]%s\b" % re.escape(f), src), (
            f"{component} reads '{f}', a field the backend never emits"
        )


def _strip_js_comments(src: str) -> str:
    """Remove /* */ blocks and full-line // comments so documentation
    prose never masquerades as code accessors."""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"(?m)^\s*//.*$", "", src)
    return src


def test_overview_reads_only_real_summary_fields() -> None:
    _decorative_fields_absent("overview.js", [
        "high_severity_open_cases",
        "critical_severity_open_cases",
        "high_confidence_count",
        "recent_detection_count",
    ])
    src = read(COMPONENTS / "overview.js")
    for real in ("open_case_count", "detection_count", "correlation_count"):
        assert real in src


def test_case_list_renders_only_incident_fields() -> None:
    _decorative_fields_absent("cases.js", [
        "correlation_kind", "asset_id", "last_activity_at",
        "source_id", "source_type",
    ])


def test_timeline_reads_the_real_contract() -> None:
    src = read(COMPONENTS / "timeline.js")
    # items at the top level, real TimelineItem fields
    assert "d.items" in src or "Array.isArray(d.items)" in src
    assert "occurred_at" in src
    assert "timeline_item_id" in src
    # fields the backend never emits
    for bad in ("d.timeline", "ev.timestamp", "ev.title", "ev.event_id"):
        assert bad not in src


def test_rules_uses_name_not_title_or_provider() -> None:
    _decorative_fields_absent("rules.js", ["r.title", "r.provider"])
    src = read(COMPONENTS / "rules.js")
    assert "r.name" in src


def test_sources_uses_health_not_fabricated_fields() -> None:
    _decorative_fields_absent("sources.js", [
        "last_event_at", "connector_type",
    ])
    src = read(COMPONENTS / "sources.js")
    assert "health" in src and "last_received_at" in src


def test_case_page_uses_incident_scoped_ops() -> None:
    src = read(COMPONENTS / "case.js")
    assert "detection.list_for_incident" in src
    assert "correlation.list_for_incident" in src
    assert "timeline.build_for_incident" in src


def test_case_page_does_not_call_unpromoted_ops() -> None:
    src = read(COMPONENTS / "case.js")
    for bad in ("case.acknowledge", "case.assign", "case.add_note",
                "case.add_recommendation"):
        assert bad not in src, (
            f"case.js fires '{bad}', which is not an ALLOWED_OPERATION"
        )


def test_frontend_ops_are_real_proxy_operations() -> None:
    """Every dotted operation name referenced by the frontend must be
    declared in app/proxy/proxy.py (single source of truth)."""
    proxy_src = read(PROXY_PY)
    declared = set(re.findall(r'OP_[A-Z0-9_]+\s*=\s*"([a-z][a-z0-9_.]+)"',
                              proxy_src))
    assert "case.get" in declared  # sanity: parser actually found ops
    op_re = re.compile(r'"([a-z]+(?:\.[a-z_0-9]+)+)"')
    # proxy operation namespaces (excludes JS selectors like main.main)
    ns_re = re.compile(
        r"^(auth|case|correlation|detection|event|health|overview|"
        r"report|routing|rule|source|timeline)\.")
    for js in list(COMPONENTS.glob("*.js")) + [JS / "services" / "api.js"]:
        src = read(js)
        for op in op_re.findall(src):
            if not ns_re.match(op):
                continue
            if op.endswith((".html", ".css", ".js", ".json")):
                continue
            assert op in declared, (
                f"{js.name} references unknown proxy operation '{op}'"
            )


# ---------------------------------------------------------------------------
# 4. page wiring
# ---------------------------------------------------------------------------

def test_page_script_order() -> None:
    for page, component in PAGES.items():
        html = read(FRONTEND / page)
        scripts = re.findall(r'src="(/static/js/[^"]+)"', html)
        expect = [
            "/static/js/services/api.js",
            "/static/js/components/format.js",
            "/static/js/components/ids.js",
            "/static/js/components/layout.js",
            f"/static/js/components/{component}",
        ]
        assert scripts == expect, f"{page} script order wrong: {scripts}"


def test_shell_groups_navigation() -> None:
    src = read(COMPONENTS / "layout.js")
    assert "NAV_GROUPS" in src
    for label in ("Operations", "Configuration", "System"):
        assert label in src


# ---------------------------------------------------------------------------
# optional: real syntax check when node is available
# ---------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("node") is None,
                    reason="node not installed")
@pytest.mark.parametrize("js", sorted(COMPONENTS.glob("*.js")))
def test_js_syntax_valid(js: Path) -> None:
    r = subprocess.run(
        ["node", "--check", str(js)],
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, f"{js.name}: {r.stderr}"
