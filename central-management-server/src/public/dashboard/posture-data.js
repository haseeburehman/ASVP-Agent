export function unwrapCollectorPayload(stored, collector) {
  if (!stored) return null;
  return stored.collector === collector && Object.hasOwn(stored, 'data') ? stored.data : stored;
}

export function latestCollectorState(results, tasks, collector) {
  const result = results.find((item) => item.collector === collector) ?? null;
  const task = tasks.find((item) => (item.collector_name ?? item.collectorName) === collector) ?? null;

  if (result) {
    const embedded = result.data?.collector === collector && Object.hasOwn(result.data, 'data')
      ? result.data
      : null;
    const envelope = embedded ?? result;
    return {
      state: envelope.status ?? result.status ?? 'unknown',
      error: envelope.error ?? result.error ?? null,
      payload: unwrapCollectorPayload(result.data, collector),
      result,
      envelope,
      task,
    };
  }

  if (task?.status === 'pending' || task?.status === 'dispatched') {
    return { state: 'pending', error: null, payload: null, result: null, envelope: null, task };
  }
  if (task?.status === 'failed') {
    return { state: 'failed', error: task.error ?? null, payload: null, result: null, envelope: null, task };
  }
  return { state: task ? 'missing' : 'no task', error: null, payload: null, result: null, envelope: null, task };
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
