import type { Detection, Severity } from "../types/soc";

export type DetectionSeverityFilter = Severity | "ALL";

export interface DetectionFilterState {
  query: string;
  severity: DetectionSeverityFilter;
  sourceId: string;
}

/**
 * J-02: the analyst must be able to isolate a canonical event from the
 * global detection list. Event and capability identifiers therefore
 * participate in the same search box as the existing human IDs, rule
 * names, evidence text and attacker IP. The returned array is also the
 * filtered count rendered by the page.
 */
export function filterDetections(
  detections: readonly Detection[],
  filters: DetectionFilterState
): Detection[] {
  const query = filters.query.toLowerCase().trim();

  return detections.filter((detection) => {
    const matchesSearch =
      !query ||
      detection.humanId.toLowerCase().includes(query) ||
      detection.title.toLowerCase().includes(query) ||
      detection.ruleId.toLowerCase().includes(query) ||
      detection.ruleName.toLowerCase().includes(query) ||
      detection.evidenceSummary.toLowerCase().includes(query) ||
      detection.eventId.toLowerCase().includes(query) ||
      detection.capabilityId.toLowerCase().includes(query) ||
      detection.sourceId.toLowerCase().includes(query) ||
      (!!detection.attackerIp &&
        detection.attackerIp.toLowerCase().includes(query));

    const matchesSeverity =
      filters.severity === "ALL" || detection.severity === filters.severity;
    const matchesSource =
      filters.sourceId === "ALL" || detection.sourceId === filters.sourceId;

    return matchesSearch && matchesSeverity && matchesSource;
  });
}
