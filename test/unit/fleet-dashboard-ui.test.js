import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const dashboardRoot = new URL('../../central-management-server/src/public/dashboard/', import.meta.url);

async function asset(name) {
  return readFile(new URL(name, dashboardRoot), 'utf8');
}

test('fleet dashboard provides search, sorting, health visualization, and detail tabs', async () => {
  const [html, script, css] = await Promise.all([asset('index.html'), asset('app.js'), asset('app.css')]);
  assert.match(html, /id="agent-search"/);
  assert.match(html, /id="agent-sort"/);
  assert.match(script, /conic-gradient/);
  for (const tab of ['overview', 'posture', 'missing-patches', 'activity', 'results', 'raw']) {
    assert.match(script, new RegExp(`data-tab="${tab}"`));
  }
  assert.match(css, /\.status-badge\.online/);
  assert.match(css, /@media\(max-width:760px\)/);
  assert.match(css, /animation:pulse/);
  assert.match(css, /\.posture-card\.full-width/);
  assert.match(css, /\.security-pill\.danger/);
  assert.match(script, /Running services/);
  assert.match(script, /Process security/);
  assert.match(script, /attachPostureTableControls/);
  assert.match(script, /View raw JSON/);
});

test('activity log collapses routine noise and bounds meaningful events', async () => {
  const script = await asset('app.js');
  assert.match(script, /const eventPageSize = 25/);
  assert.match(script, /routineTypes = new Set\(\['heartbeat', 'poll'\]\)/);
  assert.match(script, /empty polls in the last hour/);
  assert.match(script, /slice\(0, viewState\.eventLimit\)/);
  assert.match(script, /Show older activity/);
  assert.match(script, /data-event-filter="heartbeat"/);
  assert.match(script, /data-event-filter="poll"/);
  assert.match(script, /data-event-filter="result"/);
  assert.match(script, /preserveState: true/);
  assert.match(script, /events\.slice\(0, 25\)/);
});
