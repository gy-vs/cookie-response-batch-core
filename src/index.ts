/**
 * HTTP Cookie Jar.
 *
 * Features:
 * - Per-domain and global count quotas plus a per-cookie byte-size cap.
 * - Deterministic eviction: priority (protected-prefix aware), expiry,
 *   least-recently-used, FIFO creation time, then a total key tie-break.
 * - Reads never write to storage immediately: access times accumulate in an
 *   in-memory watermark and are committed in batches. Eviction merges the
 *   persisted lastAccess with the unflushed watermark.
 * - Optimistic document revision (CAS) prevents a concurrent commit from
 *   evicting or overwriting an item another writer just updated.
 * - Whole-response receive: all Set-Cookie fields of one HTTP response are
 *   parsed against the request URL and committed as a single atomic
 *   operation with per-field diagnostics.
 */

/** Public cookie shape, as accepted by {@link CookieJar.set}. */
export interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  /** Creation timestamp (ms epoch). Defaults to the jar clock time. */
  created?: number;
  /** Absolute expiry timestamp (ms epoch). Omit for a session cookie. */
  expires?: number;
  /** Eviction priority. Defaults to "medium". */
  priority?: 'low' | 'medium' | 'high';
}

/** Stored record. {@link rev} is bumped on every successful write to the key. */
export interface StoredCookie extends Cookie {
  created: number;
  expires?: number;
  priority: 'low' | 'medium' | 'high';
  lastAccess: number;
  rev: number;
}

/** Whole-jar snapshot committed atomically to a {@link CookieStore}. */
export interface CookieDocument {
  /** Monotonic document revision used for compare-and-swap commits. */
  version: number;
  cookies: StoredCookie[];
}

/**
 * Persistence boundary. Any backing store (memory, file, database) only needs
 * to implement a snapshot read and a conditional commit.
 */
export interface CookieStore {
  load(): CookieDocument | Promise<CookieDocument>;
  /**
   * Commit `next` only when the stored version is still `expected`.
   * Returns the actual stored document (and commit stats); a version mismatch
   * rejects with {@link RevisionConflict}.
   */
  commit(
    next: CookieDocument,
    expected: number,
  ): Promise<{ doc: CookieDocument; stats: CommitStats }>;
}

export interface CommitStats {
  accepted: boolean;
  expected: number;
  actual: number;
}

/** Return value of {@link CookieJar.set}. */
export interface SetResult {
  stored: boolean;
  oversize: boolean;
  /** Keys of expired cookies purged during the commit. */
  expired: string[];
  /** Keys evicted to satisfy quotas during the commit. */
  evicted: string[];
  /** Access-watermark entries folded into this commit. */
  accessesFlushed: number;
  /** Document revision after the commit. */
  rev: number;
}

/** Why a single Set-Cookie field was rejected by {@link CookieJar.receiveSetCookies}. */
export type SetCookieRejectReason =
  /** No "=" in the name-value pair. */
  | 'missing-pair'
  /** Empty cookie name. */
  | 'empty-name'
  /** Name contains a CTL, whitespace, or a separator character. */
  | 'invalid-name'
  /** Value contains a control character. */
  | 'invalid-value'
  /** Domain attribute does not domain-match the request URL host. */
  | 'domain-mismatch'
  /** "name=value" exceeds the jar's maxCookieBytes cap. */
  | 'oversize';

/** What an accepted Set-Cookie field did in the final committed document. */
export type SetCookieDisposition =
  /** The cookie was written (inserted or replaced). */
  | 'stored'
  /** The field carried an already-expired date and deleted its identity. */
  | 'removed';

/** Per-field outcome of {@link CookieJar.receiveSetCookies}, in response order. */
export interface ReceivedSetCookie {
  /** Position of the raw field in the input. */
  index: number;
  /** The raw Set-Cookie field value, as received. */
  field: string;
  /** Whether the field was parsed and applied by the receive operation. */
  accepted: boolean;
  /** Parsed cookie name (accepted fields only). */
  name?: string;
  /** Canonical cookie domain derived from the request URL (accepted only). */
  domain?: string;
  /** Cookie path: the Path attribute or the request URL's default path. */
  path?: string;
  /** Canonical identity key (accepted fields only). */
  key?: string;
  /**
   * Final effect of this field in the committed document. Reported from the
   * winning plan, so it always describes the same commit as {@link ReceiveResult.rev}.
   */
  disposition?: SetCookieDisposition;
  /**
   * Index of the later accepted field with the same identity that overrode
   * this one within the same response. Absent on the effective (last) field.
   */
  supersededBy?: number;
  /** Why the field was rejected (rejected fields only). */
  reason?: SetCookieRejectReason;
}

/** Return value of {@link CookieJar.receiveSetCookies}. */
export interface ReceiveResult {
  /** Per-field outcomes, aligned with the input order. */
  fields: ReceivedSetCookie[];
  /** How many fields were accepted into the receive operation. */
  accepted: number;
  /** How many fields were rejected (never entered the jar). */
  rejected: number;
  /** Keys of expired cookies purged during the commit. */
  expired: string[];
  /** Keys evicted to satisfy quotas during the commit. */
  evicted: string[];
  /** Access-watermark entries folded into this commit. */
  accessesFlushed: number;
  /**
   * Document revision after the commit. When no field was acceptable the jar
   * is left untouched and this is the last observed revision.
   */
  rev: number;
}

export interface CookieJarOptions {
  store?: CookieStore;
  /** Max live cookies per canonical domain. Default 50. */
  perDomainQuota?: number;
  /** Max live cookies in the whole jar. Default 3000. */
  globalQuota?: number;
  /** Max size in bytes of one cookie (UTF-8 length of name + "=" + value). */
  maxCookieBytes?: number;
  /** Auto-flush the access watermark once it reaches this many entries. */
  flushThreshold?: number;
  /** Injectable clock (ms epoch). Defaults to Date.now. */
  now?: () => number;
}

export class RevisionConflict extends Error {
  constructor(
    readonly expected: number,
    readonly actual: number,
  ) {
    super(`cookie document revision conflict: expected ${expected}, found ${actual}`);
    this.name = 'RevisionConflict';
  }
}

const PRIORITY_RANK = { low: 0, medium: 1, high: 2 } as const;

/** Canonical, fully deterministic cookie identity. */
export function cookieKey(domain: string, path: string, name: string): string {
  return `${domain}\u0000${path}\u0000${name}`;
}

/**
 * Effective eviction rank. Protected prefixes only nudge the sort order;
 * they never grant immunity from eviction.
 */
function evictionRank(c: StoredCookie): number {
  let rank: number = PRIORITY_RANK[c.priority];
  if (c.name.startsWith('__Host-')) rank = Math.max(rank, PRIORITY_RANK.high);
  else if (c.name.startsWith('__Secure-')) rank = Math.max(rank, PRIORITY_RANK.medium);
  return rank;
}

/**
 * Eviction order, ascending (the first element is evicted first):
 *   1. lower effective priority
 *   2. earlier expiry; session cookies (no expiry) are kept last
 *   3. least recently accessed (LRU), persisted time merged with the
 *      unflushed access watermark by the caller
 *   4. oldest creation (FIFO)
 *   5. canonical key, lexicographic — guarantees a total, insertion-agnostic
 *      order so ties are resolved deterministically
 */
function evictionCompare(
  a: StoredCookie,
  b: StoredCookie,
  pending: ReadonlyMap<string, number>,
): number {
  const pa = evictionRank(a);
  const pb = evictionRank(b);
  if (pa !== pb) return pa - pb;
  const ea = a.expires ?? Number.POSITIVE_INFINITY;
  const eb = b.expires ?? Number.POSITIVE_INFINITY;
  if (ea !== eb) return ea < eb ? -1 : 1;
  const la = Math.max(a.lastAccess, pending.get(cookieKey(a.domain, a.path, a.name)) ?? 0);
  const lb = Math.max(b.lastAccess, pending.get(cookieKey(b.domain, b.path, b.name)) ?? 0);
  if (la !== lb) return la - lb;
  if (a.created !== b.created) return a.created - b.created;
  const ka = cookieKey(a.domain, a.path, a.name);
  const kb = cookieKey(b.domain, b.path, b.name);
  return ka < kb ? -1 : ka > kb ? 1 : 0;
}

/** Cookie size per RFC 6265: byte length of "name=value". */
export function cookieBytes(c: Pick<Cookie, 'name' | 'value'>): number {
  return new TextEncoder().encode(`${c.name}=${c.value}`).length;
}

/**
 * A validated cookie write, planned against one loaded document. Whether it
 * stores or deletes is decided at plan time (expires vs. the plan clock), so
 * a retried plan re-evaluates the decision against the fresh state.
 */
interface PlannedCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  created: number;
  expires?: number;
  priority: 'low' | 'medium' | 'high';
}

interface Plan {
  doc: CookieDocument;
  expired: string[];
  evicted: string[];
  accessesFlushed: number;
  /** Per-op effect ('stored' | 'removed'), aligned with the input ops. */
  outcomes: SetCookieDisposition[];
}

/* ------------------------------------------------------------------ *
 * Set-Cookie field parsing (RFC 6265 §5.1–§5.3, pragmatic subset).
 * ------------------------------------------------------------------ */

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

/**
 * HTTP cookie-date parser (RFC 6265 §5.1.1). Tolerates the historical date
 * formats by scanning delimiter-separated tokens for time, day, month, year.
 * Returns ms epoch, or undefined when no valid calendar date is present.
 */
function parseCookieDate(value: string): number | undefined {
  const tokens = value.split(/[\t\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+/);
  let hour = -1;
  let minute = -1;
  let second = -1;
  let day = -1;
  let month = -1;
  let year = -1;
  for (const tok of tokens) {
    let m: RegExpExecArray | null;
    if (second < 0 && (m = /^(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\D.*)?$/.exec(tok))) {
      hour = +m[1];
      minute = +m[2];
      second = +m[3];
    } else if (day < 0 && (m = /^(\d{1,2})(?:\D.*)?$/.exec(tok))) {
      day = +m[1];
    } else if (month < 0 && (m = /^([a-zA-Z]{3})/.exec(tok))) {
      const i = MONTHS.indexOf(m[1].toLowerCase());
      if (i >= 0) month = i;
    } else if (year < 0 && (m = /^(\d{2,4})(?:\D.*)?$/.exec(tok))) {
      year = +m[1];
    }
  }
  if (year >= 70 && year <= 99) year += 1900;
  else if (year >= 0 && year <= 69) year += 2000;
  if (
    second < 0 ||
    day < 1 ||
    day > 31 ||
    month < 0 ||
    year < 1601 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return undefined;
  }
  return Date.UTC(year, month, day, hour, minute, second);
}

/** Default cookie path for a request URL path (RFC 6265 §5.1.4). */
function defaultCookiePath(urlPath: string): string {
  if (!urlPath.startsWith('/')) return '/';
  const lastSlash = urlPath.lastIndexOf('/');
  if (lastSlash === 0) return '/';
  return urlPath.slice(0, lastSlash);
}

/**
 * Parse one raw Set-Cookie field in the context of the request URL that
 * produced it. Domain and path are always resolved against that URL — the
 * caller cannot inject a precomputed identity — so an accepted cookie is
 * exactly one the jar's own get() matching rules would return for this
 * origin. Attribute duplicates: the first occurrence wins; Max-Age takes
 * precedence over Expires; unknown attributes (HttpOnly, SameSite, …) are
 * parsed and ignored.
 */
function parseSetCookieField(
  field: string,
  host: string,
  urlPath: string,
  now: number,
  maxCookieBytes: number,
): { ok: true; cookie: PlannedCookie } | { ok: false; reason: SetCookieRejectReason } {
  const semi = field.indexOf(';');
  const pairStr = semi < 0 ? field : field.slice(0, semi);
  const attrStr = semi < 0 ? '' : field.slice(semi + 1);

  const eq = pairStr.indexOf('=');
  if (eq < 0) return { ok: false, reason: 'missing-pair' };
  const name = pairStr.slice(0, eq).trim();
  let value = pairStr.slice(eq + 1).trim();
  if (name === '') return { ok: false, reason: 'empty-name' };
  // Name must be a token: no CTLs, whitespace, or separators.
  if (/[\x00-\x20\x7f()<>@,;:\\"/\[\]?={}]/.test(name)) return { ok: false, reason: 'invalid-name' };
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    value = value.slice(1, -1);
  }
  if (/[\x00-\x1f\x7f]/.test(value)) return { ok: false, reason: 'invalid-value' };

  let expiresAt: number | undefined;
  let maxAge: number | undefined;
  let domainAttr: string | undefined;
  let pathAttr: string | undefined;
  let secure = false;
  const seen = new Set<string>();
  for (const raw of attrStr.split(';')) {
    const av = raw.trim();
    if (av === '') continue;
    const aeq = av.indexOf('=');
    const an = (aeq < 0 ? av : av.slice(0, aeq)).trim().toLowerCase();
    const avv = aeq < 0 ? '' : av.slice(aeq + 1).trim();
    if (seen.has(an)) continue;
    seen.add(an);
    switch (an) {
      case 'expires': {
        const t = parseCookieDate(avv);
        if (t !== undefined) expiresAt = t; // unparseable date: attribute ignored
        break;
      }
      case 'max-age': {
        if (/^-?\d+$/.test(avv)) maxAge = parseInt(avv, 10);
        break;
      }
      case 'domain': {
        const d = (avv.startsWith('.') ? avv.slice(1) : avv).toLowerCase();
        if (d !== '') domainAttr = d;
        break;
      }
      case 'path': {
        if (avv.startsWith('/')) pathAttr = avv; // otherwise: default path
        break;
      }
      case 'secure':
        secure = true;
        break;
      default:
        break; // httponly, samesite, extensions: no jar-level effect
    }
  }

  let expires: number | undefined;
  if (maxAge !== undefined) expires = now + maxAge * 1000;
  else if (expiresAt !== undefined) expires = expiresAt;

  // The Domain attribute must domain-match the request host, mirroring the
  // jar's get() rule (exact host or parent suffix). IP hosts match exactly.
  let domain: string;
  if (domainAttr !== undefined) {
    const isIp = host.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const matches = isIp
      ? host === domainAttr
      : host === domainAttr || host.endsWith('.' + domainAttr);
    if (!matches) return { ok: false, reason: 'domain-mismatch' };
    domain = domainAttr;
  } else {
    domain = host;
  }

  const cookie: PlannedCookie = {
    name,
    value,
    domain,
    path: pathAttr ?? defaultCookiePath(urlPath),
    secure,
    created: now,
    expires,
    priority: 'medium',
  };
  if (cookieBytes(cookie) > maxCookieBytes) return { ok: false, reason: 'oversize' };
  return { ok: true, cookie };
}

/**
 * Default in-memory store, also usable across multiple jars to simulate
 * process recovery. With commitDelayMs > 0, load happens synchronously and
 * commit after a macrotask, producing a deterministic CAS conflict for two
 * concurrent writers (both load before either commits).
 */
export class MemoryCookieStore implements CookieStore {
  #doc: CookieDocument;
  #commitDelayMs: number;
  rejectedCommits = 0;

  constructor(initial?: CookieDocument, commitDelayMs = 0) {
    this.#doc = initial
      ? { version: initial.version, cookies: initial.cookies.map((c) => ({ ...c })) }
      : { version: 0, cookies: [] };
    this.#commitDelayMs = commitDelayMs;
  }

  load(): CookieDocument {
    return { version: this.#doc.version, cookies: this.#doc.cookies.map((c) => ({ ...c })) };
  }

  async commit(next: CookieDocument, expected: number) {
    if (this.#commitDelayMs > 0) {
      await new Promise((r) => setTimeout(r, this.#commitDelayMs));
    }
    if (this.#doc.version !== expected) {
      this.rejectedCommits++;
      throw new RevisionConflict(expected, this.#doc.version);
    }
    this.#doc = { version: next.version, cookies: next.cookies.map((c) => ({ ...c })) };
    return {
      doc: { version: this.#doc.version, cookies: this.#doc.cookies.map((c) => ({ ...c })) },
      stats: { accepted: true, expected, actual: next.version },
    };
  }

  /** Inspect the persisted state (tests). */
  snapshot(): CookieDocument {
    return this.load();
  }
}

export class CookieJar {
  readonly #perDomainQuota: number;
  readonly #globalQuota: number;
  readonly #maxCookieBytes: number;
  readonly #flushThreshold: number;
  readonly #now: () => number;
  readonly #store: CookieStore;
  #version: number;

  /** Access-time watermark: key -> latest access since the last commit. */
  readonly #pending = new Map<string, number>();
  #flushInFlight: Promise<number> | null = null;
  #scheduled: Promise<void> | null = null;

  private constructor(opts: Required<Omit<CookieJarOptions, 'store'>> & { store: CookieStore }, v: number) {
    this.#store = opts.store;
    this.#perDomainQuota = opts.perDomainQuota;
    this.#globalQuota = opts.globalQuota;
    this.#maxCookieBytes = opts.maxCookieBytes;
    this.#flushThreshold = opts.flushThreshold;
    this.#now = opts.now;
    this.#version = v;
  }

  /** Load the persisted snapshot before serving requests. */
  static async open(options: CookieJarOptions = {}): Promise<CookieJar> {
    const store = options.store ?? new MemoryCookieStore();
    const doc = await store.load();
    return new CookieJar(
      {
        store,
        perDomainQuota: positive(options.perDomainQuota, 50),
        globalQuota: positive(options.globalQuota, 3000),
        maxCookieBytes: positive(options.maxCookieBytes, 4096),
        flushThreshold: positive(options.flushThreshold, 32),
        now: options.now ?? (() => Date.now()),
      },
      doc.version,
    );
  }

  /** Number of unflushed read-access timestamps held in memory. */
  get pendingAccesses(): number {
    return this.#pending.size;
  }

  /** Last observed persisted document revision. */
  get revision(): number {
    return this.#version;
  }

  /**
   * Insert/replace a cookie. Expired cookies are purged and quotas enforced
   * in one CAS-protected commit; stale plans reload and retry.
   */
  async set(cookie: Cookie): Promise<SetResult> {
    if (typeof cookie.name !== 'string' || cookie.name === '' || typeof cookie.value !== 'string') {
      throw new TypeError('cookie name and value must be non-empty strings');
    }
    if (typeof cookie.domain !== 'string' || cookie.domain === '' || typeof cookie.path !== 'string') {
      throw new TypeError('cookie domain and path must be non-empty strings');
    }
    if (cookieBytes(cookie) > this.#maxCookieBytes) {
      // Oversized single cookie: reject without touching the jar.
      return { stored: false, oversize: true, expired: [], evicted: [], accessesFlushed: 0, rev: this.#version };
    }

    const priority: StoredCookie['priority'] = cookie.priority ?? 'medium';
    if (!(priority in PRIORITY_RANK)) throw new TypeError(`invalid priority: ${String(cookie.priority)}`);

    const op: PlannedCookie = {
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain.toLowerCase(),
      path: cookie.path,
      secure: cookie.secure,
      created: cookie.created ?? this.#now(),
      expires: cookie.expires,
      priority,
    };
    const { committed, plan } = await this.#commitOps([op]);
    return {
      stored: plan.outcomes[0] === 'stored',
      oversize: false,
      expired: plan.expired,
      evicted: plan.evicted,
      accessesFlushed: plan.accessesFlushed,
      rev: committed.version,
    };
  }

  /**
   * Receive the Set-Cookie fields of one HTTP response as a single atomic
   * operation. `requestUrl` is the URL that produced the response; every
   * field's domain and path are resolved against it (Domain attribute must
   * domain-match the request host, missing Path defaults from the URL path),
   * so the receive context cannot be bypassed with precomputed identities.
   *
   * Fields are validated independently — one invalid field never discards
   * the valid ones — and applied in response order, so repeated writes and
   * deletions of the same identity settle to the last field's effect.
   * All accepted fields land in one CAS-protected commit together with the
   * pending access watermark; on a revision conflict the whole response is
   * re-planned against the fresh document, never just the last field. The
   * returned per-field records, expired/evicted lists and revision all
   * describe that single final commit. A response with no acceptable field
   * leaves the jar untouched.
   */
  async receiveSetCookies(
    requestUrl: string | URL,
    setCookieFields: string | readonly string[],
  ): Promise<ReceiveResult> {
    const url = toUrl(requestUrl);
    const host = url.hostname.toLowerCase();
    if (host === '') throw new TypeError('request URL must have a host');
    const fields = typeof setCookieFields === 'string' ? [setCookieFields] : setCookieFields;
    const now = this.#now();

    const records: ReceivedSetCookie[] = [];
    const ops: PlannedCookie[] = [];
    const acceptedAt: number[] = []; // ops index -> records index
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i];
      if (typeof field !== 'string') throw new TypeError('Set-Cookie fields must be strings');
      const parsed = parseSetCookieField(field, host, url.pathname, now, this.#maxCookieBytes);
      const rec: ReceivedSetCookie = { index: i, field, accepted: parsed.ok };
      if (parsed.ok) {
        rec.name = parsed.cookie.name;
        rec.domain = parsed.cookie.domain;
        rec.path = parsed.cookie.path;
        rec.key = cookieKey(parsed.cookie.domain, parsed.cookie.path, parsed.cookie.name);
        acceptedAt.push(i);
        ops.push(parsed.cookie);
      } else {
        rec.reason = parsed.reason;
      }
      records.push(rec);
    }

    // Repeated identities: the last accepted field is the effective one.
    const lastByKey = new Map<string, number>();
    for (const i of acceptedAt) lastByKey.set(records[i].key!, i);
    for (const i of acceptedAt) {
      const last = lastByKey.get(records[i].key!)!;
      if (last !== i) records[i].supersededBy = last;
    }

    const rejected = records.length - ops.length;
    if (ops.length === 0) {
      // Nothing acceptable: no commit, watermark and document untouched.
      return {
        fields: records,
        accepted: 0,
        rejected,
        expired: [],
        evicted: [],
        accessesFlushed: 0,
        rev: this.#version,
      };
    }

    const { committed, plan } = await this.#commitOps(ops);
    for (let j = 0; j < acceptedAt.length; j++) {
      records[acceptedAt[j]].disposition = plan.outcomes[j];
    }
    return {
      fields: records,
      accepted: ops.length,
      rejected,
      expired: plan.expired,
      evicted: plan.evicted,
      accessesFlushed: plan.accessesFlushed,
      rev: committed.version,
    };
  }

  /**
   * Return matching cookies (longest path first, then creation, then name),
   * recording the access in the in-memory watermark. Storage is never written
   * synchronously per read.
   */
  async get(host: string, path: string, secure = true): Promise<StoredCookie[]> {
    const h = host.toLowerCase();
    const now = this.#now();
    const doc = await this.#store.load();
    this.#version = doc.version;

    const matches = doc.cookies.filter(
      (c) =>
        (c.expires === undefined || c.expires > now) &&
        (h === c.domain || h.endsWith('.' + c.domain)) &&
        path.startsWith(c.path) &&
        (!c.secure || secure),
    );
    matches.sort(
      (a, b) =>
        b.path.length - a.path.length ||
        a.created - b.created ||
        (a.name < b.name ? -1 : a.name > b.name ? 1 : 0),
    );

    for (const c of matches) {
      this.#pending.set(cookieKey(c.domain, c.path, c.name), now);
    }
    if (this.#pending.size >= this.#flushThreshold) this.#scheduleAutoFlush();

    // Shallow copies keep internal records immutable to callers.
    return matches.map((c) => ({ ...c }));
  }

  /** Flush the access watermark (plus expiry purge + quota enforcement). */
  flush(): Promise<number> {
    // Coalesce concurrent callers onto the in-flight flush.
    return this.#flushInFlight ?? this.#runFlush();
  }

  /** Await any scheduled/in-flight batched flush (tests/shutdown). */
  async drain(): Promise<void> {
    while (this.#scheduled || this.#flushInFlight) {
      await (this.#scheduled ?? this.#flushInFlight);
    }
  }

  #runFlush(): Promise<number> {
    const p = this.#runFlushInner().finally(() => {
      if (this.#flushInFlight === p) this.#flushInFlight = null;
    });
    this.#flushInFlight = p;
    return p;
  }

  async #runFlushInner(): Promise<number> {
    for (;;) {
      if (this.#pending.size === 0) return 0;
      const doc = await this.#store.load();
      const pending = new Map(this.#pending);
      const plan = this.#plan(doc, pending, []);
      try {
        const { doc: committed } = await this.#store.commit(plan.doc, doc.version);
        this.#version = committed.version;
        this.#reconcile(committed);
        return plan.accessesFlushed;
      } catch (e) {
        if (!(e instanceof RevisionConflict)) throw e;
      }
    }
  }

  #scheduleAutoFlush(): void {
    if (this.#scheduled || this.#flushInFlight) return;
    this.#scheduled = Promise.resolve().then(() => {
      this.#scheduled = null;
      return this.#runFlush().then(() => {});
    });
  }

  /**
   * Plan `ops` against the current document and commit the result in one
   * CAS-protected write. A revision conflict reloads and re-plans the whole
   * operation list against the fresh state, so the committed document and
   * the returned plan always describe the same final commit.
   */
  async #commitOps(ops: readonly PlannedCookie[]): Promise<{ committed: CookieDocument; plan: Plan }> {
    for (;;) {
      const doc = await this.#store.load();
      const pending = new Map(this.#pending);
      const plan = this.#plan(doc, pending, ops);
      try {
        const { doc: committed } = await this.#store.commit(plan.doc, doc.version);
        this.#version = committed.version;
        this.#reconcile(committed);
        return { committed, plan };
      } catch (e) {
        if (!(e instanceof RevisionConflict)) throw e;
        // Another writer landed first: reload and rebuild against the fresh
        // state, so its just-updated item is never evicted by our stale plan.
      }
    }
  }

  /**
   * Build the next document snapshot. All mutation paths (set, receive,
   * flush) funnel through here so expiry purge, watermark merge and quota
   * eviction use one consistent, deterministic procedure. Ops are applied
   * in the given order; an op whose expiry has already passed deletes its
   * identity instead of storing.
   */
  #plan(doc: CookieDocument, pending: Map<string, number>, ops: readonly PlannedCookie[]): Plan {
    const now = this.#now();
    const evicted: string[] = [];
    const expired: string[] = [];
    let accessesFlushed = 0;
    const outcomes: SetCookieDisposition[] = [];

    // 1. Purge expired cookies (also clears simultaneous expiries).
    const live: StoredCookie[] = [];
    for (const c of doc.cookies) {
      const k = cookieKey(c.domain, c.path, c.name);
      if (c.expires !== undefined && c.expires <= now) {
        expired.push(k);
        pending.delete(k);
      } else {
        live.push({ ...c });
      }
    }

    // 2. Apply the planned ops in order. Keys written by this batch are
    //    tracked so a delete only reports genuinely persisted removals and
    //    a same-batch rewrite does not bump the per-cookie revision twice.
    const storedThisBatch = new Set<string>();
    for (const op of ops) {
      const k = cookieKey(op.domain, op.path, op.name);
      if (op.expires !== undefined && op.expires <= now) {
        // Already-expired op: delete the identity instead of storing.
        outcomes.push('removed');
        const i = live.findIndex((c) => cookieKey(c.domain, c.path, c.name) === k);
        if (i >= 0) {
          live.splice(i, 1);
          if (!storedThisBatch.has(k)) expired.push(k);
          storedThisBatch.delete(k);
        }
        pending.delete(k);
        continue;
      }
      outcomes.push('stored');
      // A pending access for the written key is discarded into this commit.
      if (pending.delete(k)) accessesFlushed++;
      const existing = live.find((c) => cookieKey(c.domain, c.path, c.name) === k);
      if (existing) {
        existing.value = op.value;
        existing.secure = op.secure;
        existing.expires = op.expires;
        existing.priority = op.priority;
        existing.created = op.created;
        existing.lastAccess = op.created;
        if (!storedThisBatch.has(k)) existing.rev += 1; // revision bumps on overwrite
      } else {
        live.push({
          name: op.name,
          value: op.value,
          domain: op.domain,
          path: op.path,
          secure: op.secure,
          created: op.created,
          expires: op.expires,
          priority: op.priority,
          lastAccess: op.created,
          rev: 1,
        });
      }
      storedThisBatch.add(k);
    }

    // 3. Fold the remaining unflushed watermark into lastAccess.
    for (const c of live) {
      const k = cookieKey(c.domain, c.path, c.name);
      const t = pending.get(k);
      if (t !== undefined && t > c.lastAccess) {
        c.lastAccess = t;
        accessesFlushed++;
      }
    }

    return this.#finish(live, pending, doc.version, expired, evicted, accessesFlushed, outcomes);
  }

  /** Enforce quotas and canonicalize the snapshot. */
  #finish(
    live: StoredCookie[],
    pending: Map<string, number>,
    version: number,
    expired: string[],
    evicted: string[],
    accessesFlushed: number,
    outcomes: SetCookieDisposition[],
  ): Plan {
    // 4. Per-domain quota. Normally only the incoming domain can newly
    //    exceed; all offending domains are handled deterministically in a
    //    single pass over the total eviction order.
    for (;;) {
      const need = new Map<string, number>();
      let excess = 0;
      for (const c of live) {
        const n = (need.get(c.domain) ?? 0) + 1;
        need.set(c.domain, n);
      }
      for (const [d, n] of need) {
        if (n > this.#perDomainQuota) {
          need.set(d, n - this.#perDomainQuota);
          excess += n - this.#perDomainQuota;
        } else {
          need.set(d, 0);
        }
      }
      if (excess === 0) break;
      live.sort((a, b) => evictionCompare(a, b, pending));
      const survivors: StoredCookie[] = [];
      for (const c of live) {
        const remaining = need.get(c.domain) ?? 0;
        if (remaining > 0) {
          need.set(c.domain, remaining - 1);
          const k = cookieKey(c.domain, c.path, c.name);
          evicted.push(k);
          pending.delete(k);
        } else {
          survivors.push(c);
        }
      }
      live = survivors;
    }

    // 5. Global quota.
    live.sort((a, b) => evictionCompare(a, b, pending));
    while (live.length > this.#globalQuota) {
      const victim = live.shift()!;
      evicted.push(cookieKey(victim.domain, victim.path, victim.name));
      pending.delete(cookieKey(victim.domain, victim.path, victim.name));
    }

    // 6. Canonical order: makes the committed byte stream deterministic.
    live.sort((a, b) => {
      const ka = cookieKey(a.domain, a.path, a.name);
      const kb = cookieKey(b.domain, b.path, b.name);
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });

    // A key re-stored after an in-batch purge/delete is not "gone": expired
    // lists only identities absent from the final committed document.
    const finalKeys = new Set(live.map((c) => cookieKey(c.domain, c.path, c.name)));
    const gone = expired.filter((k) => !finalKeys.has(k));
    gone.sort();
    evicted.sort();

    return {
      doc: { version: version + 1, cookies: live },
      expired: gone,
      evicted,
      accessesFlushed,
      outcomes,
    };
  }

  /**
   * Reconcile the in-memory watermark against a freshly committed document:
   * drop entries the commit persisted (lastAccess at least as fresh) or whose
   * cookie no longer exists (expired, evicted by this jar or a concurrent
   * writer). Entries newer than the snapshot are retained for the next batch.
   */
  #reconcile(doc: CookieDocument): void {
    const byKey = new Map(doc.cookies.map((c) => [cookieKey(c.domain, c.path, c.name), c]));
    for (const [k, t] of this.#pending) {
      const c = byKey.get(k);
      if (!c || c.lastAccess >= t) this.#pending.delete(k);
    }
  }
}

function positive(v: number | undefined, d: number): number {
  if (v === undefined) return d;
  if (!Number.isInteger(v) || v < 1) throw new RangeError('quota values must be positive integers');
  return v;
}

function toUrl(u: string | URL): URL {
  if (u instanceof URL) return u;
  try {
    return new URL(u);
  } catch {
    throw new TypeError(`invalid request URL: ${u}`);
  }
}
