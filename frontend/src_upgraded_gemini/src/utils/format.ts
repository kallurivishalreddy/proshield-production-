/**
 * Timestamp formatting for backend ISO-8601 values.
 *
 * Canonical storage stays UTC: backend datetimes arrive as ISO-8601 with an
 * explicit offset (e.g. `2026-09-06T20:22:00.123456+00:00`) and are never
 * rewritten by the UI. Values are only parsed, never re-serialised.
 *
 * User-facing display is Indian Standard Time (IST, UTC+05:30) per the
 * Batch 1/2 display requirement. Conversion is timezone-aware
 * (`Intl.DateTimeFormat` with `Asia/Kolkata`) — never a manual +05:30
 * arithmetic on strings, so calendar roll-over around midnight and
 * offset-carrying inputs both convert to the exact same instant.
 */
export const DISPLAY_TIME_ZONE = 'Asia/Kolkata';
export const DISPLAY_TIME_ZONE_LABEL = 'IST';

type DisplayParts = {
  year: string;
  month: string;
  day: string;
  hour: string;
  minute: string;
  second: string;
};

// `hourCycle: 'h23'` keeps midnight as `00` (some ICU builds render `24`
// for `hour12: false`).  `en-GB` is used only to obtain 2-digit numeric
// parts; the string layout is composed below, not locale-dependent.
const IST_FORMATTER = new Intl.DateTimeFormat('en-GB', {
  timeZone: DISPLAY_TIME_ZONE,
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

function istParts(d: Date): DisplayParts {
  const out: Record<string, string> = {};
  for (const part of IST_FORMATTER.formatToParts(d)) {
    if (part.type !== 'literal') out[part.type] = part.value;
  }
  return out as DisplayParts;
}

/**
 * Canonical timestamps are UTC. Offset-less ISO date-times (the backend
 * telemetry view serialises naive BSON dates with ``isoformat()``, e.g.
 * ``2026-09-27T15:08:15.491000``) must therefore be read as UTC — never as
 * host-local time, which would shift the instant by the machine's offset.
 */
const NAIVE_ISO_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;

function parse(iso: string | undefined | null): Date | null {
  if (!iso) return null;
  const text = String(iso);
  const normalized = NAIVE_ISO_RE.test(text)
    ? `${text.replace(' ', 'T')}Z`
    : text;
  const d = new Date(normalized);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** IST calendar date `YYYY-MM-DD`. */
export function formatIstDate(iso: string | undefined | null): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  const p = istParts(d);
  return `${p.year}-${p.month}-${p.day}`;
}

/** IST wall-clock time `HH:MM:SS`. */
export function formatIstTime(iso: string | undefined | null): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  const p = istParts(d);
  return `${p.hour}:${p.minute}:${p.second}`;
}

/**
 * IST date+time with milliseconds, for forensic surfaces that previously
 * rendered the raw canonical ISO value: `YYYY-MM-DD HH:MM:SS.mmm IST`.
 * Sub-millisecond precision (microseconds) exceeds the JavaScript `Date`
 * resolution and is therefore not part of any localised display.
 */
export function formatIstTimestamp(iso: string | undefined | null): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  const p = istParts(d);
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}.${pad3(d.getMilliseconds())} ${DISPLAY_TIME_ZONE_LABEL}`;
}

/**
 * IST hour:minute with the zone label, for hour-bucket labels:
 * `HH:MM IST`. The value is converted from the bucket's canonical UTC
 * instant, so the label names the same instant the backend aggregated.
 */
export function formatIstHourMinute(iso: string | undefined | null): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  const p = istParts(d);
  return `${p.hour}:${p.minute} ${DISPLAY_TIME_ZONE_LABEL}`;
}

/** IST date+time without milliseconds: `YYYY-MM-DD HH:MM:SS IST`. */
export function formatIstDateTime(iso: string | undefined | null): string {
  const d = parse(iso);
  if (!d) return iso ? String(iso) : '—';
  const p = istParts(d);
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second} ${DISPLAY_TIME_ZONE_LABEL}`;
}

/**
 * Canonical UTC helpers. Retained for technical/canonical views that must
 * show the stored instant verbatim (they are no longer used by the
 * user-facing surfaces, which render IST above).
 */
export function formatUtcTime(iso: string | undefined | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso; // show raw rather than "Invalid Date"
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

export function formatUtcDate(iso: string | undefined | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function formatUtcFull(iso: string | undefined | null): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${formatUtcDate(iso)} ${formatUtcTime(iso)} UTC`;
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : `${n}`;
}

function pad3(n: number): string {
  return n < 10 ? `00${n}` : n < 100 ? `0${n}` : `${n}`;
}
