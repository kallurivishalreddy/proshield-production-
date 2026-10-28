import assert from "node:assert/strict";
import { test } from "node:test";

import type { RawDetection } from "./backend";
import { buildDetectionViews } from "./adapters";

const EVENT_ID = "01a183f6-d82f-79da-b432-1cdbde43cd53";
const DETECTION_ID = "det-01a183f6-d8e7-73ff-8961-44fefe274683";

function rawDetection(overrides: Partial<RawDetection> = {}): RawDetection {
  return {
    detection_id: DETECTION_ID,
    human_id: "DET-000082",
    rule_id: "NGINX-AUTH-BRUTEFORCE-001",
    rule_version: 1,
    category: "source_specific",
    event_id: EVENT_ID,
    evidence_refs: [EVENT_ID],
    reasoning: "nginx HTTP 401 on /api/login",
    severity: "low",
    source_instance_id: "src-primary",
    capability_id: "cap-nginx",
    detected_at: "2026-10-28T19:22:35.111000+00:00",
    extra: {},
    ...overrides,
  };
}

const refs = {
  humanIdByDetectionId: new Map<string, string>(),
  caseOfDetection: new Map<string, string>(),
};

test("adapter preserves event and capability provenance", () => {
  const [view] = buildDetectionViews([rawDetection()], refs);

  assert.equal(view.eventId, EVENT_ID);
  assert.equal(view.capabilityId, "cap-nginx");
  assert.equal(view.sourceId, "src-primary");
  assert.equal(view.ruleId, "NGINX-AUTH-BRUTEFORCE-001");
  assert.equal(view.rawPayload.event_id, EVENT_ID);
  assert.equal(view.rawPayload.capability_id, "cap-nginx");
  assert.equal(view.rawPayload.source_instance_id, "src-primary");
  assert.deepEqual(view.rawPayload.evidence_refs, [EVENT_ID]);
});

test("adapter renders missing capability honestly instead of inventing one", () => {
  const [view] = buildDetectionViews(
    [rawDetection({ capability_id: null, source_instance_id: null })],
    refs
  );

  assert.equal(view.capabilityId, "");
  assert.equal(view.sourceId, "");
  assert.equal(view.rawPayload.capability_id, null);
});
