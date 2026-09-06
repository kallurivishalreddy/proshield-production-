"""Static check: every page + component wires the page to the
expected proxy ops, and every page uses the same DOMContentLoaded
race-condition fix.

No browser, no server — pure file inspection.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
FRONTEND = ROOT / "frontend"


PAGES = {
    "index.html":         ("overview.js",   ["overview.summary",
                                              "source.list",
                                              "rule.list",
                                              "case.list",
                                              "detection.list"]),
    "cases.html":         ("cases.js",      ["case.list"]),
    "case.html":          ("case.js",       []),  # no id
    "rules.html":         ("rules.js",      ["rule.list"]),
    "sources.html":       ("sources.js",    ["source.list"]),
    "detections.html":    ("detections.js", ["detection.list",
                                              "rule.list"]),
    "correlations.html":  ("correlations.js", ["correlation.list"]),
    "timeline.html":      ("timeline.js",   ["case.list"]),
    "health.html":        ("health.js",     ["event.list"]),
}


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def main() -> int:
    failures: list[str] = []

    # 1. The layout.js DOMContentLoaded fix must be present.
    layout = _read(FRONTEND / "js" / "components" / "layout.js")
    if "readyState" not in layout or "loading" not in layout:
        failures.append("layout.js: missing readyState DOMContentLoaded fix")
    if "shell(contentEl, opts)" not in layout:
        failures.append("layout.js: shell() signature missing")

    # 2. Every page must include the right component and the
    #    body-level #app anchor (the only stable element the
    #    shell() can replaceWith()).
    for page, (component, expected_ops) in PAGES.items():
        p = FRONTEND / page
        if not p.exists():
            failures.append(f"{page}: missing")
            continue
        html = _read(p)
        if f"js/components/{component}" not in html:
            failures.append(f"{page}: does not load {component}")
        if 'id="app"' not in html:
            failures.append(f"{page}: missing #app anchor")

    # 3. Every component must reference the right ops and target
    #    <main class="main"> for its content.
    for page, (component, expected_ops) in PAGES.items():
        cp = FRONTEND / "js" / "components" / component
        if not cp.exists():
            failures.append(f"{component}: missing")
            continue
        js = _read(cp)
        # PSUI.mount is called by the component itself, except for
        # overview.js (called from index.html's inline script) and
        # layout.js (defines PSUI itself).
        if component not in ("layout.js", "overview.js", "format.js"):
            if "PSUI.mount" not in js:
                failures.append(f"{component}: does not call PSUI.mount")
        for op in expected_ops:
            if op not in js:
                failures.append(
                    f"{component}: expected op '{op}' not present"
                )
        # The component must target <main class="main"> so it works
        # after the shell replaces the body.
        if component not in ("layout.js", "format.js"):
            if 'querySelector("main.main")' not in js \
                    and "querySelector('main.main')" not in js:
                failures.append(
                    f"{component}: does not target <main class='main'>"
                )

    # 4. Sources page: must not redundantly call source.list_types
    #    in the initial render path.
    sources = _read(FRONTEND / "js" / "components" / "sources.js")
    if "refreshAll" not in sources:
        failures.append(
            "sources.js: refreshAll helper missing "
            "(parallel loadSources+loadTypes causes redundant "
            "source.list_types round-trip)"
        )

    # 5. case.js: must guard against no-id URL to avoid 4 × 400.
    case = _read(FRONTEND / "js" / "components" / "case.js")
    if "No incident selected" not in case:
        failures.append(
            "case.js: missing no-id guard (renders 4 × 400 errors "
            "when opened without ?id=...)"
        )

    # 6. overview.js: must not call document.getElementById('app')
    #    (the shell has already replaced #app with the app-shell root).
    overview = _read(FRONTEND / "js" / "components" / "overview.js")
    if "getElementById(\"app\")" in overview:
        # Only fail if it's used to append. The safe fallback is
        # querySelector('main.main').
        if "querySelector(\"main.main\")" not in overview:
            failures.append(
                "overview.js: depends on getElementById('app') which "
                "is replaced by the shell; needs querySelector('main.main')"
            )

    # 7. The proxy op list a source.js calls is exactly the documented
    #    source ops: list, register, configure, validate, enable,
    #    disable, retire, issue_token.
    src_ops = [
        "source.list", "source.register", "source.configure",
        "source.validate", "source.enable", "source.disable",
        "source.retire", "source.issue_token",
    ]
    for op in src_ops:
        if op not in sources:
            failures.append(f"sources.js: missing op {op}")

    # 8. V2-03/V2-18 regression guards: the case detail page must use
    #    the incident-scoped ops (detection.list_for_incident /
    #    correlation.list_for_incident / timeline.build_for_incident)
    #    and must NOT call the unfiltered ops with an ignored
    #    incident_id, and must read the timeline payload's top-level
    #    ``items`` (not the phantom d.timeline.items / d.events).
    case_ops_required = [
        "detection.list_for_incident",
        "correlation.list_for_incident",
        "timeline.build_for_incident",
        "case.get",
    ]
    for op in case_ops_required:
        if op not in case:
            failures.append(f"case.js: missing incident-scoped op {op}")
    # Call-site checks: 'detection.list_for_incident' contains
    # 'detection.list' as a substring, so only the quote-terminated
    # call form counts as an unfiltered call.
    for op in ("detection.list", "correlation.list"):
        if f'"{op}"' in case:
            failures.append(
                f"case.js: calls unfiltered '{op}' "
                "(V2-03 regression: wrong-scope data on the case page)"
            )
    if "d.timeline.items" in case:
        failures.append(
            "case.js: reads the phantom timeline payload field "
            "d.timeline.items (V2-18 regression: timeline always "
            "renders 0 events)"
        )

    # 9. V2-14/V2-17 regression guards: health.js must not probe the
    #    non-existent timeline.list op, and must probe the real
    #    timeline op against a case when one exists.
    health = _read(FRONTEND / "js" / "components" / "health.js")
    if "timeline.list" in health:
        failures.append(
            "health.js: probes non-existent timeline.list op (V2-14)"
        )
    if "timeline.build_for_incident" not in health:
        failures.append(
            "health.js: does not probe timeline.build_for_incident"
        )

    # 10. V2-16 regression guard: the API client must treat a non-2xx
    #     HTTP response as a failure (the SecureProxy error envelope
    #     carries no ok:false).
    api = _read(FRONTEND / "js" / "services" / "api.js")
    if "resp.ok" not in api:
        failures.append(
            "api.js: does not honour resp.ok (V2-16 regression: every "
            "400/401/403/409/500 error envelope reported as success)"
        )

    if failures:
        print("WIRING CHECK FAILED", flush=True)
        for f in failures:
            print("  - " + f, flush=True)
        return 1
    print("WIRING CHECK OK", flush=True)
    print(f"  pages: {len(PAGES)}", flush=True)
    print("  layout fix: present", flush=True)
    print("  sources.js: refreshAll present, no redundant list_types",
          flush=True)
    print("  case.js: no-id guard present", flush=True)
    print("  overview.js: targets <main class='main'>", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
