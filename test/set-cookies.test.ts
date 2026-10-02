import { beforeEach, expect, it } from 'vitest';
import {
  Cookie,
  CookieDocument,
  CookieJar,
  CookieStore,
  MemoryCookieStore,
  StoredCookie,
  cookieKey,
  parseCookieDate,
  parseSetCookieField,
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

/** A store that logs every successfully committed snapshot, by version. */
class LoggingStore implements CookieStore {
  readonly inner: MemoryCookieStore;
  readonly commits = new Map<number, CookieDocument>();
  versions: number[] = [];

  constructor(inner: MemoryCookieStore) {
    this.inner = inner;
  }

  load() {
    return this.inner.load();
  }

  async commit(next: CookieDocument, expected: number) {
    const r = await this.inner.commit(next, expected);
    this.commits.set(r.doc.version, r.doc);
    this.versions.push(r.doc.version);
    return r;
  }
}

beforeEach(() => {
  now = 1000;
});

it('applies a whole multi-field response in one atomic commit, in field order', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store);

  const result = await jar.setCookies(
    [
      'a=1; Path=/',
      'b=2; Path=/',
      // Same identity twice: the later assignment wins.
      'a=later; Path=/',
      // Expiry deletion landing between assignments to another identity.
      'c=first; Path=/',
      'c=gone; Max-Age=0; Path=/',
      'c=again; Path=/',
    ],
    'http://d.test/app/page',
  );

  expect(result.committed).toBe(true);
  expect(result.accepted).toEqual([0, 1, 2, 3, 4, 5]);
  expect(result.rejected).toEqual([]);
  expect(result.records.map((r) => [r.index, r.disposition])).toEqual([
    [0, 'stored'],
    [1, 'stored'],
    [2, 'replaced'],
    [3, 'stored'],
    [4, 'deleted'],
    [5, 'stored'],
  ]);

  // Exactly one document version bump for the whole response.
  expect(result.rev).toBe(1);
  expect(store.snapshot().version).toBe(1);
  const snap = store.snapshot();
  expect(names(snap)).toEqual(['a', 'b', 'c']);
  expect(snap.cookies.find((c) => c.name === 'a')!.value).toBe('later');
  expect(snap.cookies.find((c) => c.name === 'c')!.value).toBe('again');

  // Deletion is a real removal: a subsequent get never sees a blanked entry.
  const got = await jar.get('d.test', '/');
  expect(got.map((c) => c.name).sort()).toEqual(['a', 'b', 'c']);
  expect(got.every((c) => c.value !== '')).toBe(true);
});

it('one invalid field does not reject the others, and each verdict names its field', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store);

  const result = await jar.setCookies(
    [
      'good=1; Path=/',
      '=bad; Path=/', // missing name
      '', // empty field
      'novalue', // no '=' at all
      'also-good=2; Path=/;',
      123 as unknown as string, // not a string
      'bad name=x', // token character
      'ok=3; Max-Age=not-a-number', // malformed Max-Age rejects the field
      'fine=4; Expires=not-a-date; Path=/', // bad Expires is ignored -> session
    ],
    'http://d.test/',
  );

  expect(result.accepted).toEqual([0, 4, 8]);
  expect(result.rejected).toEqual([
    { index: 1, reason: 'missing-name' },
    { index: 2, reason: 'empty-field' },
    { index: 3, reason: 'missing-name' },
    { index: 5, reason: 'not-a-string' },
    { index: 6, reason: 'invalid-name' },
    { index: 7, reason: 'invalid-max-age' },
  ]);

  // Values carry no surrounding whitespace or CTLs (no silent trimming).
  const strict = await open(new MemoryCookieStore());
  const space = await strict.setCookies(['a= x; Path=/', 'b=x\t; Path=/'], 'http://d.test/');
  expect(space.rejected.map((r) => r.reason)).toEqual(['invalid-value', 'invalid-value']);
  // A DQUOTE-wrapped value is a legal cookie-octet sequence (no spaces inside).
  const quoted = await strict.setCookies(['q="abc"', 'q2=""'], 'http://d.test/');
  expect(quoted.accepted).toEqual([0, 1]);

  for (const r of result.records) {
    expect(r.raw).toBe(typeof r.raw === 'string' ? r.raw : String(r.raw));
    expect(r.index).toBe(result.records.indexOf(r));
  }
  expect(result.records[8].accepted).toBe(true);
  expect(result.records[8].disposition).toBe('stored');

  // Accepted cookies are live; no commit version splintering.
  expect(names(store.snapshot())).toEqual(['also-good', 'fine', 'good']);
  expect(store.snapshot().version).toBe(result.rev).toBe(1);

  // A response with no valid fields produces no commit at all.
  const nothing = await jar.setCookies(['=x', 'novalue'], 'http://d.test/');
  expect(nothing.committed).toBe(false);
  expect(nothing.records.map((r) => r.accepted)).toEqual([false, false]);
  expect(store.snapshot().version).toBe(1);
});

it('oversize fields are field-local rejections; the jar never commits them', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store, { maxCookieBytes: 8 });
  const result = await jar.setCookies(
    ['a=123456; Path=/', 'a=1234567; Path=/', 'b=z; Path=/'],
    'http://d.test/',
  );
  expect(result.rejected).toEqual([{ index: 1, reason: 'oversize' }]);
  expect(result.accepted).toEqual([0, 2]);
  expect(store.snapshot().cookies.find((c) => c.name === 'a')!.value).toBe('123456');
});

it('derives domain and path from the response context; Domain must match', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store);

  // Default path = directory of the request URI.
  await jar.setCookies(['x=1', 'y=2; Path=/api'], 'http://www.example.com/api/widgets/1');
  expect(
    (await jar.get('www.example.com', '/api/widgets/1')).map((c) => c.name).sort(),
  ).toEqual(['x', 'y']);
  expect(
    (await jar.get('www.example.com', '/api')).map((c) => c.name).sort(),
  ).toEqual(['y']);
  expect(await jar.get('www.example.com', '/')).toEqual([]);

  // Domain attribute domain-matches and is shared with subdomains.
  const r2 = await jar.setCookies(
    ['wide=1; Domain=example.com; Path=/'],
    'http://www.example.com/feed',
  );
  expect(r2.accepted).toEqual([0]);
  expect((await jar.get('example.com', '/')).map((c) => c.name)).toEqual(['wide']);
  expect((await jar.get('sub.example.com', '/')).map((c) => c.name)).toEqual(['wide']);

  // Non-matching Domain attribute is rejected, not applied to a foreign host.
  const r3 = await jar.setCookies(['evil=1; Domain=attacker.com; Path=/'], 'http://www.example.com/');
  expect(r3.rejected).toEqual([{ index: 0, reason: 'domain-mismatch' }]);
  expect(store.snapshot().cookies.some((c) => c.name === 'evil')).toBe(false);

  // IP-literal hosts reject Domain attributes and stay host-only.
  const r4 = await jar.setCookies(['ip=1; Domain=127.0.0.1'], 'http://127.0.0.1/');
  expect(r4.rejected[0].reason).toBe('host-only-domain');
  await jar.setCookies(['ip=1; Path=/'], 'http://127.0.0.1/');
  expect((await jar.get('127.0.0.1', '/'))[0].hostOnly).toBe(true);

  // IPv6 literals are stored bare (URL brackets are URI syntax); both bracket
  // styles on get resolve to the same host-only cookie.
  await jar.setCookies(['v6=1; Path=/'], 'http://[::1]/');
  expect(store.snapshot().cookies.find((c) => c.name === 'v6')!.domain).toBe('::1');
  expect((await jar.get('[::1]', '/'))[0].name).toBe('v6');
  expect((await jar.get('::1', '/'))[0].name).toBe('v6');

  // Host-only default: a cookie set on the host is not sent to a "parent".
  const hostOnly = store.snapshot().cookies.find((c) => c.name === 'x')!;
  expect(hostOnly.domain).toBe('www.example.com');
  expect(hostOnly.hostOnly).toBe(true);
});

it('host-only and domain cookies with the same name are distinct identities', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store);
  await jar.setCookies(
    ['n=host; Path=/', 'n=dom; Domain=d.test; Path=/'],
    'http://d.test/',
  );
  const snap = store.snapshot();
  expect(snap.cookies).toHaveLength(2);
  // Exact host sees both, longest-path/creation order, never collapsed.
  const got = await jar.get('d.test', '/');
  expect(got.map((c) => c.value).sort()).toEqual(['dom', 'host']);
  // Subdomain sees only the domain cookie.
  expect((await jar.get('sub.d.test', '/')).map((c) => c.value)).toEqual(['dom']);
});

it('enforces __Host- and __Secure- prefix rules at reception time', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store);
  const result = await jar.setCookies(
    [
      '__Host-a=1; Path=/; Secure', // ok
      '__Host-b=1; Path=/', // missing Secure
      '__Host-c=1; Path=/x; Secure', // wrong path
      '__Host-d=1; Path=/; Secure; Domain=d.test', // forbidden domain
      '__Secure-e=1; Secure; Path=/', // ok
      '__Secure-f=1; Path=/', // missing Secure
    ],
    'https://d.test/',
  );
  expect(result.accepted).toEqual([0, 4]);
  expect(result.rejected.map((r) => [r.index, r.reason])).toEqual([
    [1, 'bad-host-prefix'],
    [2, 'bad-host-prefix'],
    [3, 'bad-host-prefix'],
    [5, 'bad-host-prefix'],
  ]);
  expect(names(store.snapshot())).toEqual(['__Host-a', '__Secure-e']);
});

it('quota eviction is decided on the final reception state and attributed per field', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store, { perDomainQuota: 2 });

  const result = await jar.setCookies(
    [
      'a=1; Path=/',
      'b=2; Path=/',
      'c=3; Path=/', // quota 2 -> one must go; all created within this response
    ],
    'http://d.test/',
  );

  // All accepted fields are in one commit; one accepted field is reported evicted.
  expect(result.accepted).toHaveLength(3);
  const evictedField = result.records.find((r) => r.evicted)!;
  expect(result.evicted).toEqual([evictedField.key]);
  expect(evictedField.disposition).toBe('stored');
  expect(names(store.snapshot())).toHaveLength(2);

  // Field that deletes then re-creates its identity: eviction is attributed
  // to the surviving (last) field, and both records describe one revision.
  const store2 = new MemoryCookieStore();
  const jar2 = await open(store2, { perDomainQuota: 2 });
  await jar2.setCookies(['p=1; Path=/', 'q=2; Path=/'], 'http://d.test/');
  const r2 = await jar2.setCookies(
    ['p=x; Max-Age=0; Path=/', 'p=y; Path=/', 'r=3; Path=/'],
    'http://d.test/',
  );
  expect(r2.records[0].disposition).toBe('deleted');
  expect(r2.records[0].evicted).toBe(false);
  expect(r2.evicted).toHaveLength(1);
  // Final state of the same revision matches exactly what the records claim.
  const finalDoc = store2.snapshot();
  expect(finalDoc.version).toBe(r2.rev);
  for (const k of r2.evicted) {
    expect(finalDoc.cookies.some((c) => cookieKey(c.domain, c.path, c.name) === k)).toBe(false);
  }
  for (const r of r2.records) {
    if (r.accepted && !r.evicted && (r.disposition === 'stored' || r.disposition === 'replaced')) {
      expect(finalDoc.cookies.some((c) => cookieKey(c.domain, c.path, c.name) === r.key)).toBe(true);
    }
  }
});

it('concurrent multi-field receptions on two jars replay the whole batch, not the last field', async () => {
  const backing = new MemoryCookieStore(undefined, 1); // delayed commits -> CAS race
  const store1 = new LoggingStore(backing);
  const store2 = new LoggingStore(backing);
  const j1 = await open(store1, { perDomainQuota: 3 });
  const j2 = await open(store2, { perDomainQuota: 3 });

  // j1 owns a; its response deletes that a and adds two new cookies. A
  // last-field-only replay after losing the race would lose the deletion.
  await j1.setCookies(['a=old; Path=/'], 'http://d.test/');

  const [r1, r2] = await Promise.all([
    j1.setCookies(
      ['a=old; Max-Age=0; Path=/', 'm=1; Path=/', 'n=2; Path=/'],
      'http://d.test/',
    ),
    j2.setCookies(['b=1; Path=/', 'c=2; Path=/'], 'http://d.test/',
    ),
  ]);

  const snap = backing.snapshot();
  // Quota 3: b (created 1000) is the globally oldest cookie and is the
  // deterministic victim in either commit order; the essential property is
  // that 'a' is gone — a last-field-only replay would have left it behind.
  expect(names(snap)).toEqual(['c', 'm', 'n']);
  expect(snap.cookies.some((c) => c.name === 'a')).toBe(false);
  expect(backing.rejectedCommits).toBeGreaterThanOrEqual(1);

  // Each result's records, eviction list and revision describe one logged commit.
  for (const r of [r1, r2]) {
    const doc = store1.commits.get(r.rev) ?? store2.commits.get(r.rev);
    expect(doc).toBeDefined();
    const docKeys = new Set(doc!.cookies.map((c) => cookieKey(c.domain, c.path, c.name)));
    for (const rec of r.records) {
      if (rec.accepted && !rec.evicted && (rec.disposition === 'stored' || rec.disposition === 'replaced')) {
        expect(docKeys.has(rec.key!)).toBe(true);
      }
      if (rec.evicted) expect(docKeys.has(rec.key!)).toBe(false);
    }
    for (const k of r.evicted) expect(docKeys.has(k)).toBe(false);
  }

  // Every cookie surviving the final commit satisfies quotas.
  const counts = new Map<string, number>();
  for (const c of snap.cookies) counts.set(c.domain, (counts.get(c.domain) ?? 0) + 1);
  for (const [, n] of counts) expect(n).toBeLessThanOrEqual(3);
});

it('concurrent same-identity fields across jars converge to one coherent document', async () => {
  const store = new MemoryCookieStore(undefined, 1);
  const j1 = await open(store, { perDomainQuota: 1 });
  const j2 = await open(store, { perDomainQuota: 1 });
  await j1.setCookies(['z=seed; Path=/'], 'http://d.test/');

  const [r1, r2] = await Promise.all([
    j1.setCookies(['z=from-1-a; Path=/', 'z=from-1-b; Path=/'], 'http://d.test/'),
    j2.setCookies(['z=from-2; Path=/'], 'http://d.test/'),
  ]);

  const snap = store.snapshot();
  // Quota 1, one identity: exactly one live cookie, and both returned
  // revisions correspond to snapshots actually present in the store.
  expect(snap.cookies).toHaveLength(1);
  for (const r of [r1, r2]) {
    const rec = r.records.find((x) => x.disposition === 'replaced' || x.disposition === 'stored')!;
    expect(rec.key).toBe(key('z'));
  }
  expect([r1.rev, r2.rev]).toContain(snap.version);
  expect(snap.cookies[0].rev).toBeGreaterThanOrEqual(2);
});

it('batch reception folds the unflushed access watermark once and reconciles it', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store, { perDomainQuota: 4 });
  await jar.setCookies(['a=1; Path=/', 'b=2; Path=/', 'c=3; Path=/'], 'http://d.test/');

  now = 2000;
  await jar.get('d.test', '/'); // watermark {a,b,c}=2000, unflushed
  expect(store.snapshot().cookies.every((c) => c.lastAccess === c.created)).toBe(true);

  now = 4000;
  const r = await jar.setCookies(['d=4; Path=/'], 'http://d.test/');
  // The unflushed reads of the surviving cookies are folded into the single
  // reception commit; the watermark is reconciled, not left dangling.
  expect(r.accessesFlushed).toBeGreaterThanOrEqual(2);
  expect(jar.pendingAccesses).toBe(0);
  const byName = new Map(store.snapshot().cookies.map((c) => [c.name, c]));
  expect(byName.get('a')!.lastAccess).toBe(2000);
  expect(byName.get('d')!.lastAccess).toBe(4000); // reception time, not read time
});

it('a concurrent flush loses to the reception, then the whole batch replays cleanly', async () => {
  const backing = new MemoryCookieStore(undefined, 1);
  const j1Store = new LoggingStore(backing);
  const j1 = await open(j1Store, { globalQuota: 10 });
  const j2 = await open(backing, { globalQuota: 10 });
  await j1.setCookies(['a=1; Path=/', 'b=2; Path=/'], 'http://d.test/');
  now = 50;
  await j1.get('d.test', '/'); // j1-only unflushed watermark

  const [flushed, recv] = await Promise.all([
    j1.flush(),
    j2.setCookies(['c=3; Path=/', 'd=4; Path=/'], 'http://d.test/'),
  ]);
  expect(flushed).toBeGreaterThanOrEqual(0);
  const snap = backing.snapshot();
  expect(names(snap)).toEqual(['a', 'b', 'c', 'd']);
  // Replayed reception commit is coherent with its own records.
  const doc = j1Store.commits.get(recv.rev) ?? backing.snapshot();
  for (const rec of recv.records) {
    if (rec.accepted) {
      expect(doc.cookies.some((c) => cookieKey(c.domain, c.path, c.name) === rec.key)).toBe(true);
    }
  }
});

it('reopened jar reads the final atomic state after process recovery', async () => {
  const shared = new MemoryCookieStore();
  const j1 = await open(shared);
  await j1.setCookies(
    ['a=1; Path=/', 'b=2; Path=/', 'a=2; Path=/', 'c=3; Max-Age=0; Path=/'],
    'http://d.test/',
  );
  now = 5000;
  await j1.get('d.test', '/'); // watermark dies with the process

  const j2 = await open(shared);
  const got = await j2.get('d.test', '/');
  expect(got.map((c) => c.name).sort()).toEqual(['a', 'b']);
  expect(got.find((c) => c.name === 'a')!.value).toBe('2');

  // Stale expired records in a snapshot heal on the next reception.
  now = 10_000;
  const staleDoc: CookieDocument = {
    version: 9,
    cookies: [
      {
        name: 'dead', value: 'v', domain: 'd.test', path: '/', secure: false,
        hostOnly: true, created: 1, lastAccess: 1, priority: 'medium', rev: 1, expires: 5000,
      } satisfies StoredCookie,
      {
        name: 'live', value: 'v', domain: 'd.test', path: '/', secure: false,
        hostOnly: true, created: 1, lastAccess: 1, priority: 'medium', rev: 1,
      },
    ],
  };
  const store2 = new MemoryCookieStore(staleDoc);
  const j3 = await open(store2);
  const r = await j3.setCookies(['fresh=1; Path=/'], 'http://d.test/');
  expect(r.expired).toContain(key('dead'));
  expect(names(store2.snapshot())).toEqual(['fresh', 'live']);
});

it('repeated header fields preserve order and multiplicity for direct fetch-style input', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store);
  // getSetCookie() returns repeated fields, possibly with duplicated values.
  const fields = ['k=v1; Path=/', 'k=v2; Path=/', 'k=v2; Path=/'];
  const r = await jar.setCookies(fields, 'http://d.test/');
  expect(r.records).toHaveLength(3);
  expect(r.records.map((x) => x.disposition)).toEqual(['stored', 'replaced', 'replaced']);
  const c = store.snapshot().cookies.find((x) => x.name === 'k')!;
  expect(c.value).toBe('v2');
  expect(c.rev).toBe(3); // each assignment in the sequence bumped the key
});

it('rejects non-array fields and non-http(s) URLs with a TypeError', async () => {
  const jar = await open(new MemoryCookieStore());
  await expect(jar.setCookies(null as never, 'http://d.test/')).rejects.toBeInstanceOf(TypeError);
  await expect(jar.setCookies('a=1' as never, 'http://d.test/')).rejects.toBeInstanceOf(TypeError);
  await expect(jar.setCookies([], 'not a url')).rejects.toBeInstanceOf(TypeError);
  await expect(jar.setCookies([], 'ftp://d.test/')).rejects.toBeInstanceOf(TypeError);
});

it('within-response creation order is observable to eviction without future timestamps', async () => {
  const store = new MemoryCookieStore();
  const jar = await open(store, { perDomainQuota: 3, globalQuota: 3 });
  // Four brand-new cookies in one response: all other eviction keys tie, so
  // FIFO must evict the first field.
  const r = await jar.setCookies(
    ['a=1; Path=/', 'b=2; Path=/', 'c=3; Path=/', 'd=4; Path=/'],
    'http://d.test/',
  );
  expect(r.records.find((x) => x.evicted)?.index).toBe(0);
  expect(names(store.snapshot())).toEqual(['b', 'c', 'd']);

  // No committed timestamp lies about (or after) the reception instant:
  // within-response order is carried by an internal sequence mark, not by
  // fabricating future creation timestamps.
  const snap = store.snapshot();
  expect(snap.cookies.every((c) => c.created === now)).toBe(true);
  expect(snap.cookies.every((c) => c.lastAccess === now)).toBe(true);

  // An immediate read at the same clock time watermarks at the reception time.
  const got = await jar.get('d.test', '/');
  expect(got).toHaveLength(3);
  await jar.flush();
  expect(store.snapshot().cookies.every((c) => c.lastAccess === now)).toBe(true);
});

it('parses cookie dates per RFC 6265, with year and month handling', () => {  expect(parseCookieDate('Mon, 16 Oct 2023 10:30:45 GMT')).toBe(
    Date.UTC(2023, 9, 16, 10, 30, 45),
  );
  expect(parseCookieDate('16-Oct-2023 10:30:45 GMT')).toBe(
    Date.UTC(2023, 9, 16, 10, 30, 45),
  );
  expect(parseCookieDate('Sunday 06-Nov-1994 08:49:37 GMT')).toBe(
    Date.UTC(1994, 10, 6, 8, 49, 37),
  );
  expect(parseCookieDate('16 Oct 94 10:30:45 GMT')).toBe(Date.UTC(1994, 9, 16, 10, 30, 45));
  expect(parseCookieDate('16 Oct 49 10:30:45 GMT')).toBe(Date.UTC(2049, 9, 16, 10, 30, 45));
  expect(parseCookieDate('31 Feb 2023 10:30:45 GMT')).toBeNull(); // impossible day
  expect(parseCookieDate('not a date')).toBeNull();

  // First attribute occurrence wins; Expires older than now deletes, Max-Age
  // takes precedence.
  now = 5000;
  const del = parseSetCookieField('x=1; Expires=Mon, 16 Oct 2023 10:30:45 GMT; Path=/', new URL('http://d.test/'), 10_000_000_000_000);
  expect(del.outcome).toBe('ok');
  if (del.outcome === 'ok') expect(del.expires).toBeLessThan(10_000_000_000_000);
});
