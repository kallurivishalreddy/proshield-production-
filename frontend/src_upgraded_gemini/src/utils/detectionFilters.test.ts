import assert from "node:assert/strict";
import { test } from "node:test";

import type { Detection } from "../types/soc";
import { filterDetections } from "./detectionFilters";

const TARGET_EVENT = "01a183f6-d82f-79da-b432-1cdbde43cd53";

function detection(overrides: Partial<Detection> = {}): Detection {
  return {
    humanId: "DET-000082",
    internalUuid: "det-000082",
    title: "nginx HTTP 401",
    ruleId: "NGINX-AUTH-BRUTEFORCE-001",
    ruleName: "NGINX-AUTH-BRUTEFORCE-001",
    eventId: TARGET_EVENT,
    capabilityId: "cap-nginx",
    sourceId: "src-primary",
    sourceName: "src-primary",
    severity: "LOW",
    timestamp: "2026-10-28T19:22:35.111000+00:00",
    firstSeen: "2026-10-28T19:22:35.111000+00:00",
    lastSeen: "2026-10-28T19:22:35.111000+00:00",
    evidenceSummary: "nginx HTTP 401 on /api/login",
    rawPayload: {},
    matchedFields: [],
    ...overrides,
  };
}

const targetRows = [
  detection(),
  detection({
    humanId: "DET-000083",
    internalUuid: "det-000083",
    ruleId: "NGINX-AUTH-FAILURE-001",
    ruleName: "NGINX-AUTH-FAILURE-001",
  }),
];
const otherRow = detection({
  humanId: "DET-000084",
  internalUuid: "det-000084",
  eventId: "01a183f6-other",
  capabilityId: "cap-simulator",
  sourceId: "src-simulator",
  severity: "MEDIUM",
});

test("event ID search isolates exactly the event's detections", () => {
  const rows = filterDetections([...targetRows, otherRow], {
    query: TARGET_EVENT,
    severity: "ALL",
    sourceId: "ALL",
  });

  assert.equal(rows.length, 2);
  assert.deepEqual(
    rows.map((row) => row.internalUuid),
    ["det-000082", "det-000083"]
  );
  assert.ok(rows.every((row) => row.eventId === TARGET_EVENT));
});

test("capability search is available without losing the event context", () => {
  const rows = filterDetections([...targetRows, otherRow], {
    query: "cap-nginx",
    severity: "ALL",
    sourceId: "ALL",
  });

  assert.equal(rows.length, 2);
  assert.ok(rows.every((row) => row.capabilityId === "cap-nginx"));
  assert.ok(rows.every((row) => row.eventId === TARGET_EVENT));
});

test("existing severity and source filters still compose with the search", () => {
  const rows = filterDetections([...targetRows, otherRow], {
    query: "",
    severity: "MEDIUM",
    sourceId: "src-simulator",
  });

  assert.deepEqual(rows.map((row) => row.humanId), ["DET-000084"]);
});

test("missing event or capability fields do not fabricate matches", () => {
  const missing = detection({
    humanId: "DET-000085",
    internalUuid: "det-000085",
    eventId: "",
    capabilityId: "",
  });

  assert.equal(
    filterDetections([missing], {
      query: "undefined",
      severity: "ALL",
      sourceId: "ALL",
    }).length,
    0
  );
  assert.equal(
    filterDetections([missing], {
      query: "",
      severity: "ALL",
      sourceId: "ALL",
    }).length,
    1
  );
});

test("global list count is not used as the filtered event count", () => {
  const rows = [...targetRows, otherRow];
  const filtered = filterDetections(rows, {
    query: TARGET_EVENT,
    severity: "ALL",
    sourceId: "ALL",
  });

  assert.equal(rows.length, 3);
  assert.equal(filtered.length, 2);
});
