import { beforeEach, expect, it } from 'vitest';
import {
  Cookie,
  CookieDocument,
  CookieJar,
  MemoryCookieStore,
  ReceiveResult,
  cookieKey,
} from '../src/index.js';

// Manual clock: every ordering decision is reproducible, never wall-clock based.
let now: number;
const clock = () => now;

function ck(p: Partial<Cookie> & { name: string }): Cookie {
  return { value: 'v', domain: 'd.test', path: '/', secure: false, ...p };
}

function names(doc: CookieDocument): string[] {
  return doc.cookies.map((c) => c.name).sort();
}

function key(name: string, domain = 'd.test', path = '/'): string {
  return cookieKey(domain, path, name);
}

function open(
  store: MemoryCookieStore,
  opts: Parameters<typeof CookieJar.open>[0] = {},
): ReturnType<typeof CookieJar.open> {
  return CookieJar.open({ now: clock, flushThreshold: 1000, store, ...opts });
}

/** Quota invariants that must strictly hold after every committed mutation. */
function expectQuotas(doc: CookieDocument, perDomain: number, global: number) {
  const counts = new Map<string, number>();
  for (const c of doc.cookies) counts.set(c.domain, (counts.get(c.domain) ?? 0) + 1);
  for (const [, n] of counts) expect(n).toBeLessThanOrEqual(perDomain);
  expect(doc.cookies.length).toBeLessThanOrEqual(global);
}

/** Compact per-field view: [accepted, disposition/reason]. */
function fieldView(r: ReceiveResult) {
  return r.fields.map((f) => [f.accepted, f.accepted ? f.disposition : f.reason]);
}

beforeEach(() => {
  now = 1000;
});

it('receives a multi-field response as one commit with per-field diagnostics', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store, { maxCookieBytes: 12 });
  const v0 = store.snapshot().version;

  const r = await x.receiveSetCookies('http://www.example.com/app/page', [
    'sid=abc; Path=/app; HttpOnly', // stored under the URL default context
    'pref=dark; Domain=example.com', // parent domain attribute: allowed
    'no-equals-in-this-field', // rejected: missing pair
    '=anonymous', // rejected: empty name
    'evil=1; Domain=other.com', // rejected: foreign domain
    'fat=12345678901', // rejected: "fat=" + 11 bytes > 12
  ]);

  expect(r.accepted).toBe(2);
  expect(r.rejected).toBe(4);
  // Every decision maps to its raw field, in response order.
  expect(r.fields.map((f) => [f.index, f.accepted])).toEqual([
    [0, true],
    [1, true],
    [2, false],
    [3, false],
    [4, false],
    [5, false],
  ]);
  expect(r.fields[2]).toMatchObject({ field: 'no-equals-in-this-field', reason: 'missing-pair' });
  expect(r.fields[3]).toMatchObject({ reason: 'empty-name' });
  expect(r.fields[4]).toMatchObject({ reason: 'domain-mismatch' });
  expect(r.fields[5]).toMatchObject({ reason: 'oversize' });
  // Accepted fields expose the identity derived from the request URL.
  expect(r.fields[0]).toMatchObject({
    name: 'sid',
    domain: 'www.example.com',
    path: '/app',
    disposition: 'stored',
  });
  expect(r.fields[1]).toMatchObject({ name: 'pref', domain: 'example.com', path: '/app' });

  // One atomic commit: exactly one revision bump for the whole response.
  expect(r.rev).toBe(v0 + 1);
  expect(store.snapshot().version).toBe(v0 + 1);
  expect(names(store.snapshot())).toEqual(['pref', 'sid']);
  expectQuotas(store.snapshot(), 50, 3000);

  // The invalid fields never entered the jar; reads see the final state.
  expect((await x.get('www.example.com', '/app/page')).map((c) => c.name).sort()).toEqual([
    'pref',
    'sid',
  ]);
  // Default path "/app" does not match the parent path.
  expect(await x.get('www.example.com', '/')).toEqual([]);
  // The Domain attribute cookie is visible from a sibling subdomain.
  expect((await x.get('api.example.com', '/app/x')).map((c) => c.name)).toEqual(['pref']);
});

it('applies repeated writes and deletes of one identity in response order', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  await x.set(ck({ name: 'a', value: 'old', created: 1 }));
  await x.set(ck({ name: 'b', value: 'keep', created: 1 }));
  const v0 = store.snapshot().version;

  const r = await x.receiveSetCookies('http://d.test/', [
    'a=1; Path=/',
    'a=2; Path=/',
    'a=gone; Max-Age=0; Path=/', // delete what the previous fields wrote
    'a=3; Path=/', // ... and resurrect it
    'b=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/', // delete the persisted cookie
  ]);

  expect(fieldView(r)).toEqual([
    [true, 'stored'],
    [true, 'stored'],
    [true, 'removed'],
    [true, 'stored'],
    [true, 'removed'],
  ]);
  // All but the last write of "a" point at the effective field.
  expect(r.fields[0].supersededBy).toBe(3);
  expect(r.fields[1].supersededBy).toBe(3);
  expect(r.fields[2].supersededBy).toBe(3);
  expect(r.fields[3].supersededBy).toBeUndefined();

  // Deletion is not an empty-string write: the record is gone entirely.
  expect(r.expired).toEqual([key('b')]);
  const snap = store.snapshot();
  expect(snap.version).toBe(v0 + 1); // still a single commit
  expect(names(snap)).toEqual(['a']);
  const a = snap.cookies.find((c) => c.name === 'a')!;
  expect(a.value).toBe('3'); // last write wins
  expect(a.rev).toBe(1); // deleted then re-created: a fresh record

  // get() sees exactly the final content determined by the receive.
  expect((await x.get('d.test', '/')).map((c) => c.name)).toEqual(['a']);
});

it('resolves domain and path from the request URL, consistent with get()', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);

  const r = await x.receiveSetCookies('http://sub.example.com/a/b/c?x=1', [
    'naked=1', // host + default path from the URL
    'dot=2; Domain=.example.com', // leading dot stripped
    'up=3; Path=/', // explicit root path
    'rel=4; Path=relative', // non-absolute Path: default path instead
    'empty=5; Path=', // empty Path: default path
    'deep=6; Domain=sub.example.com', // exact host: allowed
    'below=7; Domain=deep.sub.example.com', // host is not under the attribute
  ]);

  expect(fieldView(r)).toEqual([
    [true, 'stored'],
    [true, 'stored'],
    [true, 'stored'],
    [true, 'stored'],
    [true, 'stored'],
    [true, 'stored'],
    [false, 'domain-mismatch'],
  ]);
  expect(r.fields[0]).toMatchObject({ domain: 'sub.example.com', path: '/a/b' });
  expect(r.fields[1]).toMatchObject({ domain: 'example.com', path: '/a/b' });
  expect(r.fields[3]).toMatchObject({ path: '/a/b' });
  expect(r.fields[4]).toMatchObject({ path: '/a/b' });

  // Default-path cookies match exactly what get() would return for the URL.
  expect((await x.get('sub.example.com', '/a/b/c')).map((c) => c.name).sort()).toEqual([
    'deep',
    'dot',
    'empty',
    'naked',
    'rel',
    'up',
  ]);
  expect((await x.get('sub.example.com', '/')).map((c) => c.name).sort()).toEqual(['up']);
  // The parent-domain cookie is stored once and matches subdomains per get().
  expect((await x.get('other.example.com', '/a/b')).map((c) => c.name)).toEqual(['dot']);
});

it('parses Expires and Max-Age; expiry deletes instead of storing', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  now = Date.UTC(2015, 9, 21, 7, 28, 0); // 2015-10-21T07:28:00Z

  const r = await x.receiveSetCookies('http://d.test/', [
    'sess=1', // no expiry: session cookie
    'exp=2; Expires=Wed, 21 Oct 2015 07:28:00 GMT', // expires exactly now
    'fut=3; Expires=Wed, 21 Oct 2015 07:28:10 GMT', // 10s in the future
    'ma=4; Max-Age=60', // now + 60s
    'both=5; Expires=Wed, 21 Oct 2015 07:28:10 GMT; Max-Age=120', // Max-Age wins
    'bad=6; Expires=not-a-date', // unparseable: attribute ignored
  ]);
  expect(r.accepted).toBe(6);
  expect(fieldView(r)).toEqual([
    [true, 'stored'],
    [true, 'removed'], // expires <= now: delete semantics, nothing stored
    [true, 'stored'],
    [true, 'stored'],
    [true, 'stored'],
    [true, 'stored'],
  ]);

  const snap = store.snapshot();
  expect(names(snap)).toEqual(['bad', 'both', 'fut', 'ma', 'sess']);
  const by = (n: string) => snap.cookies.find((c) => c.name === n)!;
  expect(by('sess').expires).toBeUndefined();
  expect(by('fut').expires).toBe(Date.UTC(2015, 9, 21, 7, 28, 10));
  expect(by('ma').expires).toBe(now + 60_000);
  expect(by('both').expires).toBe(now + 120_000); // Max-Age precedence
  expect(by('bad').expires).toBeUndefined(); // bad date ignored, not rejected

  // Time travel: the persistent cookies expire on schedule, session survives.
  now = Date.UTC(2015, 9, 21, 7, 29, 30);
  expect((await x.get('d.test', '/')).map((c) => c.name).sort()).toEqual(['bad', 'both', 'sess']);
});

it('secure cookies are hidden from insecure reads, like set()', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  await x.receiveSetCookies('https://d.test/', ['s=1; Secure', 'o=2']);
  expect((await x.get('d.test', '/', true)).map((c) => c.name).sort()).toEqual(['o', 's']);
  expect((await x.get('d.test', '/', false)).map((c) => c.name)).toEqual(['o']);
});

it('enforces quotas on the final state of the whole response, in one commit', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store, { perDomainQuota: 2 });
  await x.set(ck({ name: 'old', created: 1 }));
  const v0 = store.snapshot().version;

  // Three valid fields for the same domain in one response.
  const r = await x.receiveSetCookies('http://d.test/', ['n1=1', 'n2=2', 'n3=3']);
  expect(r.accepted).toBe(3);
  expect(r.rev).toBe(v0 + 1);
  expect(store.snapshot().version).toBe(v0 + 1); // one commit, not three
  // Quota decided by the final state: 4 cookies on d.test -> 2 survive.
  // All medium/session, lastAccess = created: old=1 < n*=1000 -> old, then
  // canonical key order among the equal newcomers: n1 goes second.
  // (The evicted list itself is sorted canonically.)
  expect(r.evicted).toEqual([key('n1'), key('old')]);
  expect(names(store.snapshot())).toEqual(['n2', 'n3']);
  expectQuotas(store.snapshot(), 2, 3000);
});

it('a response with no acceptable field leaves the jar untouched', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  await x.set(ck({ name: 'a', created: 1 }));
  now = 50;
  await x.get('d.test', '/'); // one pending access watermark entry
  const v0 = store.snapshot().version;

  const r = await x.receiveSetCookies('http://d.test/', ['garbage', '=x', 'e=1; Domain=no.pe']);
  expect(r.accepted).toBe(0);
  expect(r.rejected).toBe(3);
  expect(r.rev).toBe(v0);
  expect(r.expired).toEqual([]);
  expect(r.evicted).toEqual([]);
  expect(r.accessesFlushed).toBe(0);
  expect(store.snapshot().version).toBe(v0); // no commit happened
  expect(x.pendingAccesses).toBe(1); // watermark preserved for a later flush
});

it('folds the pending access watermark into the receive commit', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  await x.set(ck({ name: 'a', created: 1 }));
  await x.set(ck({ name: 'b', created: 2 }));
  now = 50;
  await x.get('d.test', '/'); // watermark {a,b}=50, unflushed
  expect(x.pendingAccesses).toBe(2);
  const v0 = store.snapshot().version;

  const r = await x.receiveSetCookies('http://d.test/', ['c=3', 'a=gone; Max-Age=0']);
  // b's read folds into the commit; a's watermark entry is discarded with
  // the deleted cookie itself (same rule as delete-via-set).
  expect(r.accessesFlushed).toBe(1);
  expect(r.rev).toBe(v0 + 1);
  expect(x.pendingAccesses).toBe(0);
  const snap = store.snapshot();
  expect(names(snap)).toEqual(['b', 'c']); // delete of "a" landed too
  expect(snap.cookies.find((c) => c.name === 'b')!.lastAccess).toBe(50);
});

it('external observers never see a half-applied response', async () => {
  const store = new MemoryCookieStore(undefined, 5); // slow commits
  const j1 = await open(store);
  const j2 = await open(store);
  await j1.set(ck({ name: 'base', created: 1 }));

  const receive = j1.receiveSetCookies('http://d.test/', ['x=1', 'y=2', 'z=3']);
  // While the commit is in flight, the other jar sees only the old state.
  expect((await j2.get('d.test', '/')).map((c) => c.name)).toEqual(['base']);
  expect(names(store.snapshot())).toEqual(['base']);

  const r = await receive;
  expect(r.accepted).toBe(3);
  // After the commit, the whole response is visible at once.
  expect(names(store.snapshot())).toEqual(['base', 'x', 'y', 'z']);
  expect((await j2.get('d.test', '/')).map((c) => c.name).sort()).toEqual([
    'base',
    'x',
    'y',
    'z',
  ]);
});

it('two jars receiving concurrently re-plan the whole response after conflict', async () => {
  const store = new MemoryCookieStore(undefined, 1); // deterministic CAS race
  const j1 = await open(store);
  const j2 = await open(store);
  const v0 = store.snapshot().version;

  const [r1, r2] = await Promise.all([
    j1.receiveSetCookies('http://d.test/', ['a=1', 'b=2']),
    j2.receiveSetCookies('http://d.test/', ['c=3', 'd=4']),
  ]);

  expect(store.rejectedCommits).toBeGreaterThanOrEqual(1);
  // The loser re-interpreted its ENTIRE response against the winner's
  // document: all four cookies landed, not just each response's last field.
  const snap = store.snapshot();
  expect(names(snap)).toEqual(['a', 'b', 'c', 'd']);
  expect(snap.version).toBe(v0 + 2);
  // Each result describes its own final commit, not a mix of intermediates.
  expect([r1.rev, r2.rev].sort()).toEqual([v0 + 1, v0 + 2]);
  expect(r1.accepted).toBe(2);
  expect(r2.accepted).toBe(2);
  expect(r1.fields.every((f) => f.disposition === 'stored')).toBe(true);
  expect(r2.fields.every((f) => f.disposition === 'stored')).toBe(true);
});

it('concurrent receives share quotas: the retried plan evicts from the merged state', async () => {
  const store = new MemoryCookieStore(undefined, 1);
  const j1 = await open(store, { perDomainQuota: 3 });
  const j2 = await open(store, { perDomainQuota: 3 });

  const [r1, r2] = await Promise.all([
    j1.receiveSetCookies('http://d.test/', ['a=1', 'b=2']),
    j2.receiveSetCookies('http://d.test/', ['c=3', 'd=4']),
  ]);

  // 4 cookies on one domain, quota 3: exactly one eviction across both
  // commits, decided on the final merged state (all equal rank/timestamps
  // -> canonical key order -> "a" is the victim).
  expect([...r1.evicted, ...r2.evicted]).toEqual([key('a')]);
  const snap = store.snapshot();
  expect(names(snap)).toEqual(['b', 'c', 'd']);
  expectQuotas(snap, 3, 3000);
  expect(store.rejectedCommits).toBeGreaterThanOrEqual(1);
});

it('receive vs concurrent access flush merges instead of losing updates', async () => {
  const store = new MemoryCookieStore(undefined, 1);
  const j1 = await open(store);
  const j2 = await open(store);
  await j1.set(ck({ name: 'a', created: 1 }));
  now = 50;
  await j1.get('d.test', '/'); // unflushed watermark {a}=50 in j1

  const [flushed, r] = await Promise.all([
    j1.flush(),
    j2.receiveSetCookies('http://d.test/', ['b=2']),
  ]);
  expect(flushed).toBeGreaterThanOrEqual(0);
  const snap = store.snapshot();
  expect(names(snap)).toEqual(['a', 'b']); // neither change lost
  expect(snap.cookies.find((c) => c.name === 'a')!.lastAccess).toBe(50);
  expect(store.rejectedCommits).toBeGreaterThanOrEqual(1);
});

it('received cookies survive reopening the jar on the same store', async () => {
  const store = new MemoryCookieStore();
  const j1 = await open(store);
  const r = await j1.receiveSetCookies('http://d.test/app/x', [
    'sid=abc; Path=/app',
    'gone=1',
    'gone=; Max-Age=0',
  ]);
  expect(r.rev).toBe(store.snapshot().version);

  // Simulate restart: a new jar opens the same persisted state.
  const j2 = await open(store);
  expect(j2.revision).toBe(r.rev);
  expect((await j2.get('d.test', '/app/x')).map((c) => c.name)).toEqual(['sid']);
  // The deleted cookie stays deleted after recovery.
  expect((await j2.get('d.test', '/')).map((c) => c.name)).toEqual([]);
  // Existing single-set / flush flows keep working on the reopened jar.
  await j2.set(ck({ name: 'later', created: 5 }));
  expect(names(store.snapshot())).toEqual(['later', 'sid']);
});

it('rejects invalid request URLs and non-string fields as programmer errors', async () => {
  const x = await open(new MemoryCookieStore());
  await expect(x.receiveSetCookies('not a url', ['a=1'])).rejects.toBeInstanceOf(TypeError);
  await expect(x.receiveSetCookies('http://d.test/', [1] as unknown as string[])).rejects.toBeInstanceOf(
    TypeError,
  );
  // A single string is accepted as one field.
  const r = await x.receiveSetCookies(new URL('http://d.test/'), 'a=1');
  expect(r.accepted).toBe(1);
});
