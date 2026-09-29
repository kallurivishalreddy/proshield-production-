"""Batch 1 & 2 IST display requirement — regression coverage.

Reference: docs/PHASE 5/MANUAL TESTS/BATCH 1,2 PATCH REPORT.md

Current requirement (Batch 1/2 scope): canonical timestamps stay UTC in
storage and on the wire, while every user-facing UI timestamp is displayed
in Indian Standard Time (IST, UTC+05:30), converted timezone-aware (never
by adding 5:30 to strings).

These tests exercise the REAL shipped frontend module
``frontend/src_upgraded_gemini/src/utils/format.ts``: it is bundled with the
project's own esbuild (a Vite dependency) and executed in Node, so the
assertions pin the behaviour of the code that is actually built into
``frontend/soc/index.html``.

Requires ``node`` plus the installed frontend dev dependencies; the whole
module skips with an explicit reason otherwise (never silently passes).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend" / "src_upgraded_gemini"
FORMAT_TS = FRONTEND / "src" / "utils" / "format.ts"
ESBUILD = FRONTEND / "node_modules" / "esbuild" / "bin" / "esbuild"
BUILT_UI = ROOT / "frontend" / "soc" / "index.html"

IST = timezone(timedelta(hours=5, minutes=30), name="IST")

#: Pinned canonical UTC instants -> the exact IST strings the UI must render.
KNOWN_INSTANTS = {
    # Asia/Kolkata is UTC+05:30: 20:22Z is 01:52 IST the NEXT day.
    "2026-09-06T20:22:00+00:00": "2026-09-07 01:52:00 IST",
    "2026-01-01T00:00:00Z": "2026-01-01 05:30:00 IST",
    # 18:29:59Z is the last IST second of 2025-12-31 ...
    "2025-12-31T18:29:59Z": "2025-12-31 23:59:59 IST",
    # ... and 18:30:00Z is exactly IST midnight on 2026-01-01.
    "2025-12-31T18:30:00Z": "2026-01-01 00:00:00 IST",
    # An already-IST offset names the same wall clock (14:52Z).
    "2026-09-06T20:22:00+05:30": "2026-09-06 20:22:00 IST",
    # A negative offset (09:52Z) converts forward into the IST afternoon.
    "2026-09-07T01:52:00-08:00": "2026-09-07 15:22:00 IST",
    "2026-06-15T06:05:09.987+00:00": "2026-06-15 11:35:09 IST",
}

#: Same instants, but through the millisecond-preserving helper.
KNOWN_MILLIS = {
    "2026-09-06T20:22:00.123Z": "2026-09-07 01:52:00.123 IST",
    "2026-09-06T20:22:00+00:00": "2026-09-07 01:52:00.000 IST",
    # Microsecond input: JavaScript Date resolves to milliseconds.
    "2026-09-06T20:22:00.123456+00:00": "2026-09-07 01:52:00.123 IST",
}

#: User-facing surfaces that render timestamps + the helper they must use.
WIRED_SURFACES = {
    "components/pages/IncidentsPage.tsx": "formatIstTime",
    "components/pages/CaseDetailPage.tsx": "formatIstTime",
    "components/pages/TimelinePage.tsx": "formatIstTimestamp",
    "components/pages/DetectionsPage.tsx": "formatIstTimestamp",
    "components/pages/SourcesPage.tsx": "formatIstTimestamp",
    "components/pages/HealthPage.tsx": "formatIstTimestamp",
    "components/pages/CapabilitiesPage.tsx": "formatIstTimestamp",
    "components/pages/OverviewPage.tsx": "formatIstHourMinute",
    "components/layout/TopBar.tsx": "formatIstTimestamp",
    "components/investigation/ReportGeneratorModal.tsx": "formatIstTimestamp",
    "components/investigation/AttackGraphTopology.tsx": "formatIstTimestamp",
}

#: JSX text renders of a raw canonical timestamp that must no longer exist.
RAW_RENDER_RE = re.compile(
    r"\{(?![^}]*formatIst)[^}:]*\."
    r"(timestamp|lastSeen|firstSeen|lastActivity|lastTested|generatedAt"
    r"|occurredAt|created_at|updated_at|retired_at|windowStart|windowEnd)\b[^}]*\}"
)

HARNESS = """
import * as fmt from './format.mjs';

const instants = JSON.parse(process.argv[2]);
const millis = JSON.parse(process.argv[3]);

const out = { instants: {}, millis: {}, hourMinute: {}, utc: {}, invalid: {}, empty: {} };

for (const iso of instants) {
  out.instants[iso] = {
    time: fmt.formatIstTime(iso),
    date: fmt.formatIstDate(iso),
    dateTime: fmt.formatIstDateTime(iso),
    utcTime: fmt.formatUtcTime(iso),
    utcFull: fmt.formatUtcFull(iso),
  };
}
for (const iso of millis) {
  out.millis[iso] = { timestamp: fmt.formatIstTimestamp(iso) };
}
out.hourMinute['2026-09-27T14:00:00+00:00'] = fmt.formatIstHourMinute('2026-09-27T14:00:00+00:00');
out.utc.full = fmt.formatUtcFull('2026-09-06T20:22:00.123Z');
// Offset-less canonical values (backend telemetry serialises naive BSON
// dates with isoformat()) must be read as UTC, not as host-local time.
out.naive = {
  telemetry: fmt.formatIstTimestamp('2026-09-27T15:08:15.491000'),
  short: fmt.formatIstTimestamp('2026-09-27T15:08:15.491'),
  spaced: fmt.formatIstDateTime('2026-09-27 15:08:15'),
};
for (const bad of ['not-a-real-timestamp', '42 min ago', '2026-02-30T10:00:00Z']) {
  out.invalid[bad] = fmt.formatIstTimestamp(bad);
}
out.empty.null = fmt.formatIstTimestamp(null);
out.empty.undefined = fmt.formatIstTimestamp(undefined);
out.empty.blank = fmt.formatIstDateTime('');

process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def ist_output() -> dict:
    """Bundle the real ``format.ts`` with esbuild and run it in Node."""
    if shutil.which("node") is None:
        pytest.skip("node is not available on PATH")
    if not ESBUILD.is_file():
        pytest.skip(f"esbuild not installed at {ESBUILD}")
    if not FORMAT_TS.is_file():
        pytest.skip(f"format module missing at {FORMAT_TS}")

    workdir = Path(tempfile.mkdtemp(prefix="proshield_ist_"))
    bundle = workdir / "format.mjs"
    try:
        bundle_cmd = [
            "node", str(ESBUILD), str(FORMAT_TS),
            "--bundle", "--format=esm", "--platform=node",
            f"--outfile={bundle}", "--log-level=warning",
        ]
        try:
            proc = subprocess.run(
                bundle_cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=120
            )
        except OSError as exc:  # node present but not executable
            pytest.skip(f"node cannot be executed: {exc}")
        if proc.returncode != 0:
            pytest.fail(f"esbuild bundling failed: {proc.stderr.strip()[:2000]}")

        harness = workdir / "harness.mjs"
        harness.write_text(HARNESS, encoding="utf-8")

        run_cmd = [
            "node", str(harness),
            json.dumps(list(KNOWN_INSTANTS)),
            json.dumps(list(KNOWN_MILLIS)),
        ]
        proc = subprocess.run(
            run_cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            cwd=str(workdir),
        )
        assert proc.returncode == 0, f"node harness failed: {proc.stderr.strip()[:2000]}"
        return json.loads(proc.stdout)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class TestIstConversion:
    """Known UTC instants must render as the exact IST strings."""

    def test_ist_date_time_matches_expected(self, ist_output):
        for iso, expected in KNOWN_INSTANTS.items():
            assert ist_output["instants"][iso]["dateTime"] == expected, iso

    def test_ist_component_helpers(self, ist_output):
        first = next(iter(KNOWN_INSTANTS))
        assert ist_output["instants"][first]["time"] == "01:52:00"
        assert ist_output["instants"][first]["date"] == "2026-09-07"

    def test_midnight_rollover_boundary(self, ist_output):
        """18:29:59Z -> 23:59:59 IST, 18:30:00Z -> 00:00:00 IST (no hour 24)."""
        before = ist_output["instants"]["2025-12-31T18:29:59Z"]["dateTime"]
        after = ist_output["instants"]["2025-12-31T18:30:00Z"]["dateTime"]
        assert before == "2025-12-31 23:59:59 IST"
        assert after == "2026-01-01 00:00:00 IST"

    def test_milliseconds_preserved(self, ist_output):
        for iso, expected in KNOWN_MILLIS.items():
            assert ist_output["millis"][iso]["timestamp"] == expected, iso

    def test_hour_bucket_label_is_ist(self, ist_output):
        assert ist_output["hourMinute"]["2026-09-27T14:00:00+00:00"] == "19:30 IST"


class TestIstNaiveCanonicalIsUtc:
    """Offset-less canonical values are UTC, never host-local.

    Live Batch 1/2 finding (27 Sep 2026): the source-telemetry view serialises
    naive BSON dates with ``isoformat()`` (``app/persistence/telemetry.py``),
    so the Health page received ``2026-09-27T15:08:15.491000``. JavaScript
    parses an offset-less date-time as *host-local* time, so the row rendered
    ``15:08:15.491 IST`` — the UTC wall clock relabelled, 5h30m off the true
    instant (``20:38:15.491 IST``).
    """

    def test_naive_telemetry_value_is_read_as_utc(self, ist_output):
        assert ist_output["naive"]["telemetry"] == "2026-09-27 20:38:15.491 IST"

    def test_naive_value_never_shows_the_raw_utc_wall_clock(self, ist_output):
        assert ist_output["naive"]["telemetry"] != "2026-09-27 15:08:15.491 IST"
        assert ist_output["naive"]["short"] != "2026-09-27 15:08:15.491 IST"

    def test_naive_forms_normalise_identically(self, ist_output):
        assert ist_output["naive"]["short"] == "2026-09-27 20:38:15.491 IST"
        assert ist_output["naive"]["spaced"] == "2026-09-27 20:38:15 IST"


class TestIstInstantIdentity:
    """The displayed IST value must name the exact stored UTC instant."""

    def test_displayed_ist_reparses_to_canonical_utc(self, ist_output):
        for iso, displayed in KNOWN_INSTANTS.items():
            canonical = datetime.fromisoformat(iso.replace("Z", "+00:00")).replace(microsecond=0)
            shown = displayed.replace(" IST", "")
            parsed = datetime.strptime(shown, "%Y-%m-%d %H:%M:%S").replace(tzinfo=IST)
            assert parsed == canonical, iso

    def test_millisecond_display_reparses_to_canonical_utc(self, ist_output):
        """The .mmm display names the exact stored instant (microsecond inputs
        are truncated to JavaScript's millisecond resolution)."""
        for iso, displayed in KNOWN_MILLIS.items():
            canonical = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            expected = canonical.replace(microsecond=(canonical.microsecond // 1000) * 1000)
            shown = displayed.replace(" IST", "")
            parsed = datetime.strptime(shown, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=IST)
            assert parsed == expected, iso

    def test_utc_helpers_remain_canonical(self, ist_output):
        """The retained UTC helpers still expose the stored instant verbatim."""
        assert ist_output["instants"]["2026-09-06T20:22:00+00:00"]["utcTime"] == "20:22:00"
        assert (
            ist_output["instants"]["2026-09-06T20:22:00+00:00"]["utcFull"]
            == "2026-09-06 20:22:00 UTC"
        )
        assert ist_output["utc"]["full"] == "2026-09-06 20:22:00 UTC"


class TestIstInvalidInput:
    """Invalid input never becomes a fabricated instant."""

    def test_garbage_is_returned_verbatim(self, ist_output):
        assert ist_output["invalid"]["not-a-real-timestamp"] == "not-a-real-timestamp"

    def test_human_demo_string_is_returned_verbatim(self, ist_output):
        assert ist_output["invalid"]["42 min ago"] == "42 min ago"

    def test_impossible_date_is_rejected_by_ingress_not_fabricated(self, ist_output):
        """V8 normalises 2026-02-30 -> 2026-03-02; the ingress guard is what
        rejects impossible dates before persistence (T22 coverage). This test
        pins the display helper's actual, documented behaviour."""
        assert ist_output["invalid"]["2026-02-30T10:00:00Z"] == "2026-03-02 15:30:00.000 IST"

    def test_empty_values_render_placeholder(self, ist_output):
        placeholder = "\u2014"  # em dash, exactly what format.ts returns
        assert ist_output["empty"]["null"] == placeholder
        assert ist_output["empty"]["undefined"] == placeholder
        assert ist_output["empty"]["blank"] == placeholder


class TestIstSourceWiring:
    """Every user-facing surface renders through the IST helpers."""

    def test_each_surface_imports_ist_helper(self):
        missing = []
        for rel, helper in WIRED_SURFACES.items():
            text = (FRONTEND / "src" / rel).read_text(encoding="utf-8")
            if "utils/format" not in text or helper not in text:
                missing.append(f"{rel} (expected {helper})")
        assert not missing, f"surfaces not wired to IST: {missing}"

    def test_no_raw_timestamp_renders_remain(self):
        offenders = []
        root = FRONTEND / "src" / "components"
        for path in sorted(root.rglob("*.tsx")):
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if "formatIst" in line:
                    continue
                if RAW_RENDER_RE.search(line):
                    rel = path.relative_to(FRONTEND / "src").as_posix()
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
        assert not offenders, "raw canonical timestamps still rendered: " + "; ".join(offenders)

    def test_no_user_facing_utc_labels_remain(self):
        offenders = []
        root = FRONTEND / "src" / "components"
        for path in sorted(root.rglob("*.tsx")):
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if re.search(r"\}\s*UTC\b|\bUTC\}\s*<", line):
                    rel = path.relative_to(FRONTEND / "src").as_posix()
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
        assert not offenders, "UTC-labelled renders remain: " + "; ".join(offenders)

    def test_format_module_declares_kolkata_timezone(self):
        text = FORMAT_TS.read_text(encoding="utf-8")
        assert "'Asia/Kolkata'" in text
        assert "hourCycle: 'h23'" in text, "midnight must render as 00, not 24"

    def test_canonical_payload_view_is_untouched(self):
        """The forensic payload drawer dumps stored values verbatim — it must
        not be localised, or evidence would differ from MongoDB."""
        text = (FRONTEND / "src" / "components" / "modals" / "TechnicalPayloadDrawer.tsx").read_text(
            encoding="utf-8"
        )
        assert "formatIst" not in text
        assert "JSON.stringify(payloadDrawerData.payload, null, 2)" in text


class TestIstBuiltArtifact:
    """The built single-file UI carries the IST conversion."""

    def test_built_bundle_contains_ist_timezone(self):
        if not BUILT_UI.is_file():
            pytest.skip(f"built UI not present at {BUILT_UI} (run npm run build)")
        text = BUILT_UI.read_text(encoding="utf-8", errors="replace")
        assert "Asia/Kolkata" in text, "built bundle lacks the IST timezone"
        assert "IST" in text

    def test_built_bundle_is_newer_than_format_source(self):
        if not BUILT_UI.is_file():
            pytest.skip(f"built UI not present at {BUILT_UI}")
        assert BUILT_UI.stat().st_mtime >= FORMAT_TS.stat().st_mtime, (
            "frontend/soc/index.html is older than the IST source change — rebuild required"
        )
