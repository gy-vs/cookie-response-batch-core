# HTTP Cookie Jar

Run `npm install`, `npm test`, and `npm run build`.

## Receiving a whole HTTP response

`receiveSetCookies(requestUrl, fields)` parses all `Set-Cookie` fields of one
response against the URL that produced it and commits them as a single atomic
operation — no per-cookie `set` loop in every HTTP caller:

```ts
const jar = await CookieJar.open({ store });
const result = await jar.receiveSetCookies('https://example.com/app/login', [
  'sid=abc; Path=/app; HttpOnly',
  'pref=dark; Domain=example.com',
  'gone=x; Max-Age=0', // deletes the identity
]);

result.fields; // per-field outcome, aligned with the raw input order:
               // accepted + disposition ('stored' | 'removed'), or a
               // rejection reason ('missing-pair', 'domain-mismatch',
               // 'oversize', ...), plus supersededBy for repeated identities
result.rev;    // document revision of the single commit all records describe
result.evicted; // quota evictions decided on the final merged state
```

- Domain/path always derive from the request URL (Domain attribute must
  domain-match the request host; missing Path defaults from the URL path), so
  callers cannot inject precomputed identities.
- One invalid field never discards the valid ones; repeated writes/deletes of
  the same identity apply in response order and the last one wins.
- The whole response lands in one CAS-protected commit; on a revision
  conflict the entire response is re-planned against the fresh document, and
  the pending read-access watermark folds into the same commit.
- A response with no acceptable field leaves the jar untouched.

`set`, `get`, `flush`, `drain`, and reopening a jar from a persisted
`CookieDocument` snapshot work as before.
