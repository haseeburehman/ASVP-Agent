export function unwrapCollectorPayload(stored, collector) {
  if (!stored) return null;
  return stored.collector === collector && Object.hasOwn(stored, 'data') ? stored.data : stored;
}

export function applicationMetrics(apps) {
  const shownItems = apps?.applications?.items ?? [];
  return {
    totalDetected: apps?.summary?.totalDetected ?? apps?.applications?.totalDetected ?? shownItems.length,
    shown: shownItems.length,
    truncated: apps?.applications?.truncated ?? 0,
  };
}

export function describeCheck(check, valueFormatter = (value) => value) {
  if (!check) return 'not reported';
  if (check.status === 'check-failed' || check.status === 'failed') return `${check.status}: ${check.reason || 'no reason reported'}`;
  if (check.status === 'not-applicable') return `not applicable: ${check.reason || 'this check does not apply'}`;
  if (check.status && check.status !== 'checked') return check.reason ? `${check.status}: ${check.reason}` : check.status;
  const value = valueFormatter(check.value ?? check.active);
  return value == null ? (check.reason || check.status || 'not reported') : String(value);
}
