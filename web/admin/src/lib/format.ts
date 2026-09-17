// Tabular absolute + relative date formatting (spec section 10: "tabular
// dates ... localized absolute dates and relative times").
export function formatDateTime(iso?: string): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function formatRelative(iso?: string): string {
  if (!iso) return "—";
  const target = new Date(iso).getTime();
  const diffMs = target - Date.now();
  const abs = Math.abs(diffMs);
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;

  let value: number;
  let unit: Intl.RelativeTimeFormatUnit;
  if (abs < hour) {
    value = Math.round(diffMs / minute);
    unit = "minute";
  } else if (abs < day) {
    value = Math.round(diffMs / hour);
    unit = "hour";
  } else {
    value = Math.round(diffMs / day);
    unit = "day";
  }
  return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(value, unit);
}
