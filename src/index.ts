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

interface Plan {
  doc: CookieDocument;
  expired: string[];
  evicted: string[];
  accessesFlushed: number;
  stored: boolean;
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

    const domain = cookie.domain.toLowerCase();
    const priority: StoredCookie['priority'] = cookie.priority ?? 'medium';
    if (!(priority in PRIORITY_RANK)) throw new TypeError(`invalid priority: ${String(cookie.priority)}`);
    const created = cookie.created ?? this.#now();

    for (;;) {
      const doc = await this.#store.load();
      const pending = new Map(this.#pending);
      const plan = this.#plan(doc, pending, cookie, domain, priority, created);
      try {
        const { doc: committed } = await this.#store.commit(plan.doc, doc.version);
        this.#version = committed.version;
        this.#reconcile(committed);
        return {
          stored: plan.stored,
          oversize: false,
          expired: plan.expired,
          evicted: plan.evicted,
          accessesFlushed: plan.accessesFlushed,
          rev: committed.version,
        };
      } catch (e) {
        if (!(e instanceof RevisionConflict)) throw e;
        // Another writer landed first: reload and rebuild against the fresh
        // state, so its just-updated item is never evicted by our stale plan.
      }
    }
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
      const plan = this.#plan(doc, pending, null);
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
   * Build the next document snapshot. All mutation paths (set, flush) funnel
   * through here so expiry purge, watermark merge and quota eviction use one
   * consistent, deterministic procedure.
   */
  #plan(
    doc: CookieDocument,
    pending: Map<string, number>,
    incoming: Cookie | null,
    domain?: string,
    priority?: StoredCookie['priority'],
    created?: number,
  ): Plan {
    const now = this.#now();
    let evicted: string[] = [];
    const expired: string[] = [];

    // 1. Purge expired cookies (also clears simultaneous expiries).
    const live: StoredCookie[] = [];
    for (const c of doc.cookies) {
      if (c.expires !== undefined && c.expires <= now) {
        expired.push(cookieKey(c.domain, c.path, c.name));
        pending.delete(cookieKey(c.domain, c.path, c.name));
      } else {
        live.push({ ...c });
      }
    }

    // An already-expired incoming cookie deletes its key instead of storing.
    let stored = false;
    if (incoming && domain !== undefined && priority !== undefined && created !== undefined) {
      const inKey = cookieKey(domain, incoming.path, incoming.name);
      if (incoming.expires !== undefined && incoming.expires <= now) {
        for (let i = 0; i < live.length; i++) {
          const c = live[i];
          if (cookieKey(c.domain, c.path, c.name) === inKey) {
            expired.push(inKey);
            live.splice(i, 1);
            pending.delete(inKey);
            break;
          }
        }
      } else {
        // 2. Merge the unflushed watermark into lastAccess; insert/replace.
        let accessesFlushed = 0;
        let replaced = false;
        for (const c of live) {
          const k = cookieKey(c.domain, c.path, c.name);
          const t = pending.get(k);
          if (t !== undefined) {
            if (t > c.lastAccess) c.lastAccess = t;
            accessesFlushed++;
          }
          if (k === inKey) {
            replaced = true;
            c.value = incoming.value;
            c.secure = incoming.secure;
            c.expires = incoming.expires;
            c.priority = priority;
            c.created = created;
            c.lastAccess = created;
            c.rev += 1; // revision bumps on overwrite
          }
        }
        if (!replaced) {
          live.push({
            ...incoming,
            domain,
            priority,
            created,
            lastAccess: created,
            rev: 1,
          });
        }
        pending.delete(inKey);
        return this.#finish(live, pending, doc.version, expired, evicted, accessesFlushed, true);
      }
    }

    // 3. Flush path (or set of an expired cookie): fold the watermark.
    let accessesFlushed = 0;
    for (const c of live) {
      const k = cookieKey(c.domain, c.path, c.name);
      const t = pending.get(k);
      if (t !== undefined && t > c.lastAccess) {
        c.lastAccess = t;
        accessesFlushed++;
      }
    }
    return this.#finish(live, pending, doc.version, expired, evicted, accessesFlushed, stored);
  }

  /** Enforce quotas and canonicalize the snapshot. */
  #finish(
    live: StoredCookie[],
    pending: Map<string, number>,
    version: number,
    expired: string[],
    evicted: string[],
    accessesFlushed: number,
    stored: boolean,
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
    expired.sort();
    evicted.sort();

    return {
      doc: { version: version + 1, cookies: live },
      expired,
      evicted,
      accessesFlushed,
      stored,
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
