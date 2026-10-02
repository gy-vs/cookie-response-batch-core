# HTTP Cookie Jar

A small TypeScript cookie jar with deterministic quota eviction, an
optimistic document revision (CAS), and atomic multi-`Set-Cookie` reception.

Run `npm install`, `npm test`, and `npm run build`. No external database is
required — the default `MemoryCookieStore` keeps everything in process.

## Receiving one response: `setCookies`

An HTTP response can carry multiple `Set-Cookie` header fields (e.g.
`response.headers.getSetCookie()`). `setCookies` takes the **raw, repeated
field values** of one response together with the request URL that produced it,
and applies the whole reception as **one atomic operation**:

```ts
const jar = await CookieJar.open({ store });
const result = await jar.setCookies(
  response.headers.getSetCookie(), // repeated, ordered fields
  response.url,
);
```

Properties:

- **Context-derived domain/path.** Each field is parsed against the response
  URL per RFC 6265 (default path, `Domain` suffix matching, host-only cookies,
  `Max-Age`/`Expires`, `__Host-`/`__Secure-` prefixes). A `Domain` attribute
  that does not match the response host is rejected; callers cannot inject a
  pre-built domain/path out of band.
- **Field order is significant.** Repeated assignments or deletions to the
  same identity (domain + path + name + host-only) take effect in response
  order. Expiry/deletion removes the record, it is never blanked.
- **Field-level diagnostics, batch atomicity.** One invalid field never
  invalidates the others. `result.records` reports, per raw field and aligned
  by index, whether it was `accepted`, its rejection `reason`, its
  `disposition` (`stored` / `replaced` / `deleted` / `expired`), its canonical
  `key`, and whether it was `evicted` by quota. Yet the whole response lands in
  a **single CAS commit**: an outside observer never sees a half-applied
  response, and quota eviction is decided on the final state.
- **Conflicts replay the whole reception.** When two jars share a store and a
  commit loses the revision race, the *entire* field sequence is re-planned
  against the fresh document — not just the last field. The returned `rev`,
  acceptance records and eviction records therefore all describe one final
  commit.
- **Watermarks stay coherent.** Unflushed read-access timestamps are folded
  into (or reconciled against) that same final commit.

`setCookies(fields, url)` result shape:

```ts
{
  url, committed, rev,
  records: [{ index, raw, accepted, reason?, key?, disposition?, evicted }],
  accepted: number[],                 // accepted field indexes
  rejected: [{ index, reason }],      // rejected field indexes + reasons
  expired: string[],                  // keys purged in the final commit
  evicted: string[],                  // keys evicted in the final commit
  accessesFlushed: number,
}
```

A response with no valid fields produces no commit (`committed: false`) and
leaves the jar untouched.

## Reading and the single-cookie API

- `get(host, path, secure?)` — matching cookies (longest path first),
  honoring host-only, path and `Secure`. Reads only accumulate an in-memory
  access watermark; they never write storage synchronously.
- `set(cookie)` / `flush()` / `drain()` / `CookieJar.open(store)` — the
  existing single-cookie, batched-flush and recovery forms remain available;
  `set` is a one-field special case of the same atomic planner.

## Eviction and persistence

- Per-domain and global count quotas, plus a per-cookie byte-size cap.
- Deterministic eviction order: effective priority (protected-prefix aware),
  earliest expiry (session cookies last), LRU with watermark merge, FIFO
  creation (with within-response field order), then canonical key.
- Stores implement `load()` + conditional `commit(next, expected)`.
  `MemoryCookieStore` works across jars to model concurrent writers and
  process recovery; a positive `commitDelayMs` deterministically reproduces
  CAS races in tests.
