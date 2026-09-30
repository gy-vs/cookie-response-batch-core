import { beforeEach, expect, it } from 'vitest';
import {
  Cookie,
  CookieDocument,
  CookieJar,
  MemoryCookieStore,
  StoredCookie,
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

function stored(p: Partial<StoredCookie> & { name: string }): StoredCookie {
  return {
    value: 'v',
    domain: 'd.test',
    path: '/',
    secure: false,
    created: 1,
    lastAccess: 1,
    priority: 'medium',
    rev: 1,
    ...p,
  };
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

beforeEach(() => {
  now = 1000;
});

it('selects matching cookies (path + secure), longest path first', async () => {
  const x = await open(new MemoryCookieStore());
  await x.set(ck({ name: 'a', created: 1 }));
  await x.set(ck({ name: 's', created: 2, secure: true }));
  await x.set(ck({ name: 'p', path: '/x', created: 3 }));
  expect(await x.get('d.test', '/')).toHaveLength(2);
  expect(await x.get('d.test', '/x')).toEqual([
    expect.objectContaining({ name: 'p' }),
    expect.objectContaining({ name: 'a' }),
    expect.objectContaining({ name: 's' }),
  ]);
  // Insecure context cannot see Secure cookies.
  expect(await x.get('d.test', '/', false)).toEqual([
    expect.objectContaining({ name: 'a' }),
  ]);
  // Subdomain matching.
  expect(await x.get('sub.d.test', '/')).toHaveLength(2);
});

it('reads do not persist access times immediately; flush batches them', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  await x.set(ck({ name: 'a', created: 1 }));
  const v0 = store.snapshot().version;
  now = 50;
  await x.get('d.test', '/');
  await x.get('d.test', '/');
  expect(x.pendingAccesses).toBe(1); // one key, watermarked in memory
  expect(store.snapshot().version).toBe(v0); // no storage write
  expect(store.snapshot().cookies[0].lastAccess).toBe(1);
  const n = await x.flush();
  expect(n).toBe(1); // one key batched, not two per-read writes
  expect(x.pendingAccesses).toBe(0);
  expect(store.snapshot().cookies[0].lastAccess).toBe(50);
});

it('evicts by priority first; protected prefixes only nudge the sort', async () => {
  const s1 = new MemoryCookieStore();
  const x = await open(s1, { perDomainQuota: 3 });
  // Insert newest-first so FIFO alone would pick a different victim.
  await x.set(ck({ name: 'lo', priority: 'low', created: 40 }));
  await x.set(ck({ name: 'md', priority: 'medium', created: 10 }));
  await x.set(ck({ name: 'hi', priority: 'high', created: 20 }));
  const r = await x.set(ck({ name: 'md2', priority: 'medium', created: 30 }));
  expect(r.evicted).toEqual([key('lo')]); // low loses despite being newest

  // __Host- medium behaves like high; __Secure- low behaves like medium.
  const s2 = new MemoryCookieStore();
  const y = await open(s2, { globalQuota: 2, perDomainQuota: 10 });
  await y.set(ck({ name: '__Host-a', created: 1 })); // bumped to high
  await y.set(ck({ name: 'plain-hi', priority: 'high', created: 2 }));
  const r2 = await y.set(ck({ name: 'plain-lo', priority: 'low', created: 3 }));
  expect(r2.evicted).toEqual([key('plain-lo')]);
  expect(names(s2.snapshot())).toEqual(['__Host-a', 'plain-hi']);

  // Protected is not immune: two __Host- cookies at quota 1, oldest goes.
  const s3 = new MemoryCookieStore();
  const z = await open(s3, { globalQuota: 1 });
  await z.set(ck({ name: '__Host-x', created: 1 }));
  const r3 = await z.set(ck({ name: '__Host-y', created: 2 }));
  expect(r3.evicted).toEqual([key('__Host-x')]);
  expect(names(s3.snapshot())).toEqual(['__Host-y']);
});

it('per-domain quota then global quota, enforced together per commit', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store, { perDomainQuota: 2, globalQuota: 4 });
  await x.set(ck({ name: 'a', domain: 'd1', created: 1 }));
  await x.set(ck({ name: 'b', domain: 'd1', created: 2 }));
  await x.set(ck({ name: 'c', domain: 'd2', created: 3 }));
  await x.set(ck({ name: 'd', domain: 'd2', created: 4 }));
  // Third cookie on d2: domain quota 2 -> oldest on d2 (c) evicted.
  const r1 = await x.set(ck({ name: 'e', domain: 'd2', created: 5 }));
  expect(r1.evicted).toEqual([key('c', 'd2')]);
  // Third cookie on d1: oldest on d1 (a) evicted; global stays at 4.
  const r2 = await x.set(ck({ name: 'f', domain: 'd1', created: 6 }));
  expect(r2.evicted).toEqual([key('a', 'd1')]);
  // Fifth total cookie -> global quota evicts across domains (b oldest).
  const r3 = await x.set(ck({ name: 'g', domain: 'd3', created: 7 }));
  expect(r3.evicted).toEqual([key('b', 'd1')]);
  let snap = store.snapshot();
  expect(names(snap)).toEqual(['d', 'e', 'f', 'g']);
  expectQuotas(snap, 2, 4);

  // Global quota evicts across domains by the same total order.
  const g = new MemoryCookieStore();
  const y = await open(g, { perDomainQuota: 10, globalQuota: 2 });
  await y.set(ck({ name: 'lo1', domain: 'z1', priority: 'low', created: 1 }));
  await y.set(ck({ name: 'hi1', domain: 'z2', priority: 'high', created: 2 }));
  await y.set(ck({ name: 'hi2', domain: 'z3', priority: 'high', created: 3 }));
  snap = g.snapshot();
  expect(names(snap)).toEqual(['hi1', 'hi2']); // low cross-domain victim
  expectQuotas(snap, 10, 2);
});

it('simultaneous expiry purges together deterministically', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  now = 0;
  await x.set(ck({ name: 'a', expires: 100 }));
  await x.set(ck({ name: 'b', expires: 100 }));
  await x.set(ck({ name: 'c', expires: 100 }));
  await x.set(ck({ name: 'd', expires: 200 }));
  await x.set(ck({ name: 'e' })); // session cookie

  now = 150;
  // Reads hide expired entries but do not purge them yet.
  expect((await x.get('d.test', '/')).map((c) => c.name).sort()).toEqual(['d', 'e']);
  expect(store.snapshot().cookies).toHaveLength(5);

  const r = await x.set(ck({ name: 'f' }));
  expect(r.expired).toEqual([key('a'), key('b'), key('c')]); // sorted, simultaneous
  expect(names(store.snapshot())).toEqual(['d', 'e', 'f']);
  expectQuotas(store.snapshot(), 50, 3000);

  // Setting an already-expired cookie deletes an existing one.
  now = 250;
  const r2 = await x.set(ck({ name: 'd', expires: 200 }));
  expect(r2.stored).toBe(false);
  expect(r2.expired).toContain(key('d'));
  expect(names(store.snapshot())).toEqual(['e', 'f']);
});

it('earlier expiry (session kept last) precedes LRU/FIFO', async () => {
  const s1 = new MemoryCookieStore();
  const x = await open(s1, { globalQuota: 1 });
  await x.set(ck({ name: 'persist', expires: 9999, created: 1 }));
  await x.set(ck({ name: 'sess', created: 2 })); // no expiry -> kept
  expect(names(s1.snapshot())).toEqual(['sess']);

  const s2 = new MemoryCookieStore();
  const y = await open(s2, { globalQuota: 1 });
  await y.set(ck({ name: 'soon', expires: 2000, created: 1 }));
  await y.set(ck({ name: 'later', expires: 3000, created: 2 }));
  expect(names(s2.snapshot())).toEqual(['later']);
});

it('same timestamps resolve by FIFO then canonical key, independent of insert order', async () => {
  const run = async (order: string[]) => {
    const store = new MemoryCookieStore();
    const x = await open(store, { perDomainQuota: 2 });
    for (const name of order) await x.set(ck({ name, created: 10 }));
    return store.snapshot();
  };
  const s1 = await run(['c', 'a', 'b']);
  const s2 = await run(['b', 'c', 'a']);
  expect(names(s1)).toEqual(['b', 'c']); // 'a' lexicographically first
  expect(names(s2)).toEqual(['b', 'c']); // identical victim, any insert order

  // Same creation time tie falls through to the canonical key.
  const store = new MemoryCookieStore();
  const x = await open(store, { perDomainQuota: 2 });
  await x.set(ck({ name: 'a', created: 5 }));
  await x.set(ck({ name: 'b', created: 5 }));
  const r = await x.set(ck({ name: 'c', created: 5 }));
  expect(r.evicted).toEqual([key('a')]);
});

it('batch access watermark merges with persisted lastAccess at eviction', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store, { perDomainQuota: 3 });
  await x.set(ck({ name: 'a', created: 10 }));
  await x.set(ck({ name: 'b', created: 10 }));
  await x.set(ck({ name: 'c', created: 10 }));

  now = 20;
  await x.get('d.test', '/'); // a,b,c all read at 20
  expect(x.pendingAccesses).toBe(3);
  expect(store.snapshot().cookies.every((c) => c.lastAccess === 10)).toBe(true);

  now = 40;
  const r = await x.set(ck({ name: 'd', created: 40 }));
  // Eviction sees merged lastAccess (20) for all three, then falls through
  // created (10, equal) -> canonical key: 'a' is evicted.
  expect(r.evicted).toEqual([key('a')]);
  expect(r.accessesFlushed).toBeGreaterThanOrEqual(2);
  expect(x.pendingAccesses).toBe(0); // folded watermark reconciled away
  expectQuotas(store.snapshot(), 3, 3000);

  // One key with a strictly newer unflushed access is protected (merge wins).
  const s2 = new MemoryCookieStore();
  const y = await open(s2, { perDomainQuota: 3 });
  await y.set(ck({ name: 'a', path: '/a', created: 10 }));
  await y.set(ck({ name: 'b', path: '/b', created: 10 }));
  await y.set(ck({ name: 'c', path: '/c', created: 10 }));
  now = 20;
  await y.get('d.test', '/a'); // only a matches
  now = 30;
  await y.get('d.test', '/b'); // only b matches -> b is most recently used
  now = 40;
  const r2 = await y.set(ck({ name: 'd', path: '/', created: 40 })); // 4th cookie
  // Merged LRU: c=10 < a=20 < b=30 < d=40. Without merging, the canonical
  // key would evict a; the watermark protects a and c is evicted instead.
  expect(r2.evicted).toEqual([key('c', 'd.test', '/c')]);
  expect(names(s2.snapshot())).toEqual(['a', 'b', 'd']);
});

it('flushed access time lands in storage as one batch commit', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store);
  await x.set(ck({ name: 'a', created: 1 }));
  await x.set(ck({ name: 'b', created: 2 }));
  now = 40;
  await x.get('d.test', '/');
  const n = await x.flush();
  const snap = store.snapshot();
  expect(n).toBe(2);
  expect(snap.cookies.find((c) => c.name === 'a')!.lastAccess).toBe(40);
  expect(snap.cookies.find((c) => c.name === 'b')!.lastAccess).toBe(40);
});

it('auto-flushes once the watermark reaches the threshold', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store, { flushThreshold: 3 });
  for (const name of ['a', 'b', 'c', 'd']) await x.set(ck({ name, created: 1 }));
  expect(store.snapshot().version).toBe(4);
  await x.get('d.test', '/'); // 4 keys >= threshold 3 -> microtask batch flush
  expect(x.pendingAccesses).toBe(4); // scheduled, not yet run
  await x.drain();
  expect(x.pendingAccesses).toBe(0);
  expect(store.snapshot().version).toBe(5); // exactly one batched commit
});

it('survives process recovery; watermark is lost, stale expiry healed', async () => {
  const shared = new MemoryCookieStore();
  const jar1 = await open(shared);
  await jar1.set(ck({ name: 'a', created: 1 }));
  await jar1.set(ck({ name: 'b', created: 2 }));
  now = 50;
  await jar1.get('d.test', '/'); // watermark lives only in jar1 memory
  expect(shared.snapshot().cookies.every((c) => c.lastAccess === 1 || c.lastAccess === 2)).toBe(true);

  // Simulate restart: a new process opens the same persisted state.
  const jar2 = await open(shared);
  const got = await jar2.get('d.test', '/');
  expect(got.map((c) => c.name).sort()).toEqual(['a', 'b']);
  expect(jar2.pendingAccesses).toBe(2);

  // Persisted state may contain stale expired cookies (old process crashed).
  now = 1000;
  const seed: CookieDocument = {
    version: 7,
    cookies: [
      stored({ name: 'dead', expires: 500 }),
      stored({ name: 'live1', expires: 5000 }),
      stored({ name: 'live2' }),
    ],
  };
  const store2 = new MemoryCookieStore(seed);
  const jar3 = await open(store2);
  expect((await jar3.get('d.test', '/')).map((c) => c.name).sort()).toEqual(['live1', 'live2']);
  const n = await jar3.flush(); // heals expiry + persists batched reads
  expect(n).toBe(2);
  const snap = store2.snapshot();
  expect(snap.version).toBe(8);
  expect(names(snap)).toEqual(['live1', 'live2']);
});

it('concurrent overwrite in one jar: revision guard protects the just-updated item', async () => {
  const store = new MemoryCookieStore(undefined, 1); // delayed commits -> CAS race
  const x = await open(store, { perDomainQuota: 2 });
  await x.set(ck({ name: 'a', created: 1 }));
  await x.set(ck({ name: 'b', created: 2 }));

  const [r1, r2] = await Promise.all([
    x.set(ck({ name: 'a', value: 'v2', created: 3 })), // stale plans target a
    x.set(ck({ name: 'c', created: 4 })), // quota full -> oldest survivor goes
  ]);

  const snap = store.snapshot();
  expect(names(snap)).toEqual(['a', 'c']);
  const a = snap.cookies.find((c) => c.name === 'a')!;
  expect(a.value).toBe('v2');
  expect(a.rev).toBe(2); // overwrite bumped the per-cookie revision
  expect(a.created).toBe(3);
  // The stale insert plan (evicting old a) was rejected and rebuilt;
  // b, the genuinely oldest remaining cookie, is the deterministic victim.
  expect([...r1.evicted, ...r2.evicted]).toEqual([key('b')]);
  expect(store.rejectedCommits).toBeGreaterThanOrEqual(1);
  expectQuotas(snap, 2, 3000);
});

it('concurrent writers across jars cannot evict a freshly committed update', async () => {
  const store = new MemoryCookieStore(undefined, 1);
  const j1 = await open(store, { perDomainQuota: 2 });
  const j2 = await open(store, { perDomainQuota: 2 });
  await j1.set(ck({ name: 'a', created: 1 }));
  await j1.set(ck({ name: 'b', created: 2 }));

  await Promise.all([
    j1.set(ck({ name: 'a', value: 'fresh', created: 3 })),
    j2.set(ck({ name: 'c', created: 4 })),
  ]);

  const snap = store.snapshot();
  expect(names(snap)).toEqual(['a', 'c']); // either commit order, same outcome
  expect(snap.cookies.find((c) => c.name === 'a')!.value).toBe('fresh');
  expect(store.rejectedCommits).toBeGreaterThanOrEqual(1);
  expectQuotas(snap, 2, 3000);
});

it('concurrent set vs access flush merges instead of losing updates', async () => {
  const store = new MemoryCookieStore(undefined, 1);
  const j1 = await open(store, { globalQuota: 10 });
  const j2 = await open(store, { globalQuota: 10 });
  await j1.set(ck({ name: 'a', created: 1 }));
  await j1.set(ck({ name: 'b', created: 2 }));
  now = 50;
  await j1.get('d.test', '/'); // unflushed watermark {a,b}=50

  const flushed = await Promise.all([j1.flush(), j2.set(ck({ name: 'c', created: 60 }))]);
  expect(flushed[0]).toBeGreaterThanOrEqual(0);
  const snap = store.snapshot();
  expect(names(snap)).toEqual(['a', 'b', 'c']); // neither change lost
  expect(snap.cookies.find((c) => c.name === 'a')!.lastAccess).toBe(50);
  expect(store.rejectedCommits).toBeGreaterThanOrEqual(1);
});

it('rejects an oversized single cookie without mutating the jar', async () => {
  const store = new MemoryCookieStore();
  const x = await open(store, { maxCookieBytes: 8, globalQuota: 1 });
  // exactly at cap: "a=123456" = 8 bytes
  const at = await x.set(ck({ name: 'a', value: '123456' }));
  expect(at.stored).toBe(true);
  expect(at.oversize).toBe(false);
  const before = store.snapshot().version;
  const big = await x.set(ck({ name: 'a', value: '1234567' })); // 9 bytes
  expect(big.stored).toBe(false);
  expect(big.oversize).toBe(true);
  expect(store.snapshot().version).toBe(before); // no commit happened
  expect(store.snapshot().cookies[0].value).toBe('123456'); // old value intact

  // UTF-8 bytes, not UTF-16 code units: "x=" + 2 emoji (8 bytes) = 10.
  const y = await open(new MemoryCookieStore(), { maxCookieBytes: 6 });
  const r = await y.set(ck({ name: 'x', value: '🍪🍪' }));
  expect(r.oversize).toBe(true);
});

it('eviction is deterministic and quotas hold for a fixed mixed script', async () => {
  const script = async (order: string[]) => {
    const store = new MemoryCookieStore();
    const x = await open(store, { perDomainQuota: 3, globalQuota: 5 });
    const defs: Record<string, Cookie> = {
      a: ck({ name: 'a', domain: 'x', priority: 'low', created: 1000 }),
      b: ck({ name: 'b', domain: 'x', expires: 5000, created: 1000 }),
      c: ck({ name: 'c', domain: 'x', created: 1000 }),
      d: ck({ name: 'd', domain: 'x', created: 1000 }),
      e: ck({ name: 'e', domain: 'y', priority: 'low', created: 1000 }),
      f: ck({ name: 'f', domain: 'y', created: 1000 }),
      g: ck({ name: '__Secure-g', domain: 'y', priority: 'low', created: 1000 }),
      h: ck({ name: 'h', domain: 'y', priority: 'low', created: 1000 }),
    };
    for (const n of order) await x.set(defs[n]);
    return store.snapshot();
  };

  const s1 = await script(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']);
  const s2 = await script(['h', 'g', 'f', 'e', 'd', 'c', 'b', 'a']);
  // x domain: a(low) evicted. y domain: e,h low (g bumped to medium);
  //   e before h on key -> e evicted. Global (5 left): h low -> evicted.
  expect(names(s1)).toEqual(['__Secure-g', 'b', 'c', 'd', 'f']);
  expect(names(s2)).toEqual(['__Secure-g', 'b', 'c', 'd', 'f']);
  expectQuotas(s1, 3, 5);
  expectQuotas(s2, 3, 5);
});
