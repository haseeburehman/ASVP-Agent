import assert from 'node:assert/strict';
import test from 'node:test';
import { parseAppleSecurityReleases, APPLE_SOURCE } from '../src/vulnerability/patch-feeds/apple.js';
import { parseDebianDsaRdf, DEBIAN_SOURCE } from '../src/vulnerability/patch-feeds/debian.js';
import { parseFedoraBodhi, FEDORA_SOURCE } from '../src/vulnerability/patch-feeds/fedora.js';
import { refreshOfficialPatchFeeds, OFFICIAL_PATCH_FEEDS } from '../src/vulnerability/patch-feeds/index.js';
import { parseRedHatCsaf, RED_HAT_SOURCE } from '../src/vulnerability/patch-feeds/redhat.js';
import { fetchUbuntuNotices, parseUbuntuNotices, UBUNTU_SOURCE } from '../src/vulnerability/patch-feeds/ubuntu.js';
import { parseMsrcCvrf, MSRC_SOURCE } from '../src/vulnerability/patch-feeds/windows-msrc.js';

const msrcFixture = { DocumentTitle: { Value: 'Security Update Guide' }, DocumentTracking: { Identification: { ID: '2026-Jul' }, InitialReleaseDate: '2026-07-14T00:00:00Z' },
  ProductTree: { FullProductName: [{ ProductID: 'p1', Value: 'Windows 11 Version 24H2' }] }, Vulnerability: [{ CVE: 'CVE-2026-1000', Title: { Value: 'Kernel issue' }, ProductStatuses: { KnownAffected: ['p1'] }, Threats: [{ Type: 'Severity', Description: { Value: 'Critical' } }] }] };
const ubuntuFixture = { notices: [{ id: 'USN-7000-1', title: 'Linux kernel vulnerabilities', severity: 'high', published: '2026-07-01', releases: [{ version: '24.04 LTS' }], url: 'https://ubuntu.com/security/notices/USN-7000-1' }] };
const debianFixture = `<?xml version="1.0"?><rdf:RDF><item><title>DSA-6000-1 openssl - security update</title><link>https://www.debian.org/security/2026/dsa-6000</link><dc:date>2026-07-02</dc:date><description>Important issue fixed in Debian 12</description></item></rdf:RDF>`;
const redHatFixture = { document: { title: 'RHSA kernel update', tracking: { id: 'RHSA-2026:1000', initial_release_date: '2026-07-03' }, aggregate_severity: { text: 'Important' } },
  product_tree: { branches: [{ name: 'Red Hat Enterprise Linux', branches: [{ name: '9', product: { product_id: 'rhel-9' } }] }] }, vulnerabilities: [{ cve: 'CVE-2026-2000', title: 'Kernel flaw', product_status: { known_affected: ['rhel-9'] }, scores: [{ cvss_v3: { baseSeverity: 'HIGH' } }] }] };
const fedoraFixture = { updates: [{ alias: 'FEDORA-2026-abcd', title: 'security update', severity: 'moderate', date_stable: '2026-07-04', release: { long_name: 'Fedora 42' } }] };
const appleFixture = `<table><tr><th>Name and information link</th><th>Available for</th><th>Release date</th></tr><tr><td><a href="/en-us/HT214000">macOS Sequoia 15.6</a></td><td>macOS Sequoia</td><td>July 5, 2026</td></tr></table>`;

function assertMinimum(item) {
  assert.equal(typeof item.advisoryId, 'string');
  assert.match(item.severity, /critical|high|medium|low|unknown/);
  assert.ok(item.affected[0].os);
  assert.ok(item.affected[0].versionRange);
  assert.ok(item.releaseDate);
  assert.ok(item.title);
  assert.ok(item.source.url.startsWith('https://'));
}

test('official source exports document real public URLs and actual formats', () => {
  assert.deepEqual(Object.values(OFFICIAL_PATCH_FEEDS), [MSRC_SOURCE, UBUNTU_SOURCE, DEBIAN_SOURCE, RED_HAT_SOURCE, FEDORA_SOURCE, APPLE_SOURCE]);
  for (const source of Object.values(OFFICIAL_PATCH_FEEDS)) {
    assert.match(source.url, /^https:\/\//);
    assert.match(source.format, /JSON|XML|HTML/);
  }
});

test('Windows MSRC CVRF JSON maps advisories and product ranges', () => {
  const [item] = parseMsrcCvrf(msrcFixture);
  assertMinimum(item);
  assert.equal(item.advisoryId, 'CVE-2026-1000');
  assert.equal(item.affected[0].versionRange, 'Windows 11 Version 24H2');
});

test('Ubuntu JSON and Debian RDF/XML remain explicit independent sources', () => {
  const ubuntu = parseUbuntuNotices(ubuntuFixture)[0];
  const debian = parseDebianDsaRdf(debianFixture)[0];
  assertMinimum(ubuntu); assertMinimum(debian);
  assert.equal(ubuntu.affected[0].os, 'Ubuntu');
  assert.equal(debian.advisoryId, 'DSA-6000-1');
});

test('Red Hat CSAF JSON and Fedora Bodhi JSON map independently', () => {
  const redHat = parseRedHatCsaf(redHatFixture)[0];
  const fedora = parseFedoraBodhi(fedoraFixture)[0];
  assertMinimum(redHat); assertMinimum(fedora);
  assert.match(redHat.affected[0].versionRange, /Red Hat Enterprise Linux 9/);
  assert.equal(fedora.affected[0].versionRange, 'Fedora 42');
});

test('Apple security releases HTML maps macOS rows', () => {
  const [item] = parseAppleSecurityReleases(appleFixture);
  assertMinimum(item);
  assert.equal(item.advisoryId, 'HT214000');
  assert.equal(item.affected[0].os, 'macOS');
});

test('built-in fetch is injectable and item/output bounds reject excess data', async () => {
  let calledUrl;
  const fetch = async (url) => { calledUrl = url; return { ok: true, status: 200, headers: new Headers(), text: async () => JSON.stringify(ubuntuFixture) }; };
  assert.equal((await fetchUbuntuNotices({ fetch, maxItems: 1 }))[0].advisoryId, 'USN-7000-1');
  assert.equal(calledUrl, UBUNTU_SOURCE.url);
  await assert.rejects(() => fetchUbuntuNotices({ fetch, maxBytes: 10 }), /exceeds 10 bytes/);
  assert.equal(parseUbuntuNotices({ notices: [...ubuntuFixture.notices, ...ubuntuFixture.notices] }, { maxItems: 1 }).length, 1);
});

test('aggregate refresh preserves successful feeds and reports per-feed errors', async () => {
  const result = await refreshOfficialPatchFeeds({ adapters: {
    good: async () => [parseUbuntuNotices(ubuntuFixture)[0]],
    bad: async () => { throw new Error('fixture failure'); },
  } });
  assert.equal(result.good.advisories.length, 1);
  assert.equal(result.good.error, null);
  assert.deepEqual(result.bad.advisories, []);
  assert.equal(result.bad.error.message, 'fixture failure');
});
