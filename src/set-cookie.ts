/**
 * Parsing of raw HTTP `Set-Cookie` header fields (RFC 6265 §5.1/§5.2/§5.3).
 *
 * The parser never touches storage: it only turns one raw field into either a
 * normalized cookie (domain/path resolved against the response URL, never
 * taken from caller-supplied values that bypass the response context) or a
 * typed rejection. {@link CookieJar.setCookies} applies the parsed fields to
 * the jar as a single atomic reception.
 */

/**
 * Why a raw field was rejected. These are field-level diagnostics: one bad
 * field never invalidates the other fields of the same response.
 */
export type RejectReason =
  | 'not-a-string'
  | 'empty-field'
  | 'missing-name' // no '=' (or an empty name) in the name=value pair
  | 'invalid-name' // CTL / separator characters
  | 'invalid-value' // CTL characters outside HTAB
  | 'invalid-max-age'
  | 'domain-mismatch' // Domain attribute is not a suffix of the response host
  | 'host-only-domain' // IP-literal request host with a Domain attribute
  | 'bad-host-prefix' // __Host- / __Secure- prefix rules (RFC 6265bis)
  | 'oversize'; // jar-level: name=value exceeds the configured byte cap

/** Cookie normalization product of {@link parseSetCookieField}. */
export interface ParsedSetCookie {
  outcome: 'ok';
  name: string;
  value: string;
  /** Canonical (lower-cased, leading-dot stripped) storage domain. */
  domain: string;
  path: string;
  secure: boolean;
  /** True when the cookie is host-only (no Domain attribute). */
  hostOnly: boolean;
  /** Absolute expiry (ms epoch); undefined for a session cookie. */
  expires?: number;
  priority: 'low' | 'medium' | 'high';
}

export interface RejectedSetCookie {
  outcome: 'rejected';
  reason: RejectReason;
}

export type SetCookieParseResult = ParsedSetCookie | RejectedSetCookie;

/** CTL characters except HTAB. */
const CTL_EXCEPT_TAB = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;

/** RFC 7230 token: the cookie-name grammar (RFC 6265 §4.1.1). */
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const MONTHS = [
  'jan',
  'feb',
  'mar',
  'apr',
  'may',
  'jun',
  'jul',
  'aug',
  'sep',
  'oct',
  'nov',
  'dec',
];

/**
 * RFC 6265 §5.1.1 cookie-date parser.
 * Lenient tokenization; every token is classified as time/day/month/year and
 * the date is accepted only when one of each required component was found.
 * Returns an absolute ms-epoch timestamp, or null when the string is not a
 * valid cookie date (an unparseable Expires is ignored, i.e. session cookie).
 */
export function parseCookieDate(input: string): number | null {
  // Delimiters are anything other than letters, digits and ':' (time token).
  const tokens = input.split(/[^A-Za-z0-9:]+/).filter((t) => t !== '');
  let day: number | null = null;
  let month: number | null = null;
  let year: number | null = null;
  let hh = 0;
  let mm = 0;
  let ss = 0;
  let timeSeen = false;

  for (const token of tokens) {
    const time = /^(\d{1,2}):(\d{2}):(\d{2})$/.exec(token);
    if (time) {
      timeSeen = true;
      hh = Number(time[1]);
      mm = Number(time[2]);
      ss = Number(time[3]);
      continue;
    }
    if (/^[A-Za-z]+$/.test(token)) {
      const idx = MONTHS.indexOf(token.slice(0, 3).toLowerCase());
      if (idx >= 0 && month === null) month = idx;
      continue;
    }
    if (/^\d+$/.test(token)) {
      const n = Number(token);
      // Standard forms put the day (1–2 digits) before the year (4 digits);
      // this accepts both "16 Oct 2023" and "2023 16 Oct".
      if (day === null && token.length <= 2 && n >= 1 && n <= 31) {
        day = n;
      } else if (year === null) {
        year = n;
      }
      continue;
    }
  }

  if (day === null || month === null || year === null || !timeSeen) return null;
  if (year >= 0 && year <= 69) year += 2000;
  else if (year >= 70 && year <= 99) year += 1900;
  if (day < 1 || day > 31 || year < 1601 || hh > 23 || mm > 59 || ss > 59) return null;

  // Construct as UTC; reject impossible dates (e.g. Feb 30) via rollover.
  const ms = Date.UTC(year, month, day, hh, mm, ss);
  const back = new Date(ms);
  if (
    back.getUTCFullYear() !== year ||
    back.getUTCMonth() !== month ||
    back.getUTCDate() !== day
  ) {
    return null;
  }
  return ms;
}

/** Default-path algorithm, RFC 6265 §5.1.4. */
function defaultPath(url: URL): string {
  const p = url.pathname;
  if (!p.startsWith('/') || p === '/') return '/';
  const last = p.lastIndexOf('/');
  return last <= 0 ? '/' : p.slice(0, last);
}

function isIpLiteral(host: string): boolean {
  // IPv4 dotted quad or an IPv6 literal (URL strips the brackets).
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return true;
  return host.includes(':');
}

/**
 * Parse one raw Set-Cookie field as received on a response from `url`.
 *
 * Domain/path are derived from the field *and* the response context: a Domain
 * attribute that does not domain-match the request host (§5.3 step 4) is
 * rejected, and pre-constructed domain/path values cannot be supplied out of
 * band. `now` is the reception instant, used for absolute Max-Age expiry.
 */
export function parseSetCookieField(
  raw: unknown,
  url: URL,
  now: number,
): SetCookieParseResult {
  if (typeof raw !== 'string') return { outcome: 'rejected', reason: 'not-a-string' };
  if (raw.trim() === '') return { outcome: 'rejected', reason: 'empty-field' };

  const segments = raw.split(';');
  const first = segments[0];
  const eq = first.indexOf('=');
  if (eq < 0) return { outcome: 'rejected', reason: 'missing-name' };

  const name = first.slice(0, eq).trim();
  // The value is the raw remainder up to the next ';'; per RFC 6265 §4.1.1 it
  // is cookie-octets optionally wrapped in one DQUOTE pair, with no surrounding
  // whitespace or other CTLs. Trimming would silently accept malformed fields.
  const value = first.slice(eq + 1);
  if (name === '') return { outcome: 'rejected', reason: 'missing-name' };
  if (!TOKEN.test(name)) return { outcome: 'rejected', reason: 'invalid-name' };
  if (CTL_EXCEPT_TAB.test(value) || /[\t ]/.test(value)) {
    return { outcome: 'rejected', reason: 'invalid-value' };
  }

  // Attribute map: first occurrence wins (§5.2 step 3).
  const attrs = new Map<string, string | boolean>();
  for (const seg of segments.slice(1)) {
    const pos = seg.indexOf('=');
    const aname = (pos < 0 ? seg : seg.slice(0, pos)).trim().toLowerCase();
    if (aname === '' || attrs.has(aname)) continue;
    attrs.set(aname, pos < 0 ? true : seg.slice(pos + 1).trim());
  }

  // Expiry: Max-Age takes precedence over Expires (§5.3 step 7).
  let expires: number | undefined;
  const maxAge = attrs.get('max-age');
  if (maxAge !== undefined) {
    const t = typeof maxAge === 'string' ? maxAge.trim() : '';
    if (!/^-?\d+$/.test(t)) return { outcome: 'rejected', reason: 'invalid-max-age' };
    expires = now + Number(t) * 1000; // <= now -> the reception deletes the cookie
  } else {
    const exp = attrs.get('expires');
    if (typeof exp === 'string') {
      const ms = parseCookieDate(exp);
      if (ms !== null) expires = ms; // unparseable -> ignored (session cookie)
    }
  }

  const secure = attrs.has('secure');
  // URL.hostname keeps the brackets of an IPv6 literal; storage uses the bare
  // address (brackets are URI syntax, not part of the host).
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();

  // Prefix rules (RFC 6265bis §4.1.3), checked against the raw attributes.
  if (name.startsWith('__Host-')) {
    if (!secure || attrs.has('domain') || attrs.get('path') !== '/') {
      return { outcome: 'rejected', reason: 'bad-host-prefix' };
    }
  } else if (name.startsWith('__Secure-') && !secure) {
    return { outcome: 'rejected', reason: 'bad-host-prefix' };
  }

  // Domain: an IP-literal host forbids the attribute entirely; otherwise the
  // attribute value must domain-match the response host (§5.3 steps 4–6).
  let domain = host;
  let hostOnly = true;
  const domAttr = attrs.get('domain');
  if (typeof domAttr === 'string' && domAttr !== '') {
    if (isIpLiteral(host)) return { outcome: 'rejected', reason: 'host-only-domain' };
    const d = domAttr.replace(/^\.+/, '').toLowerCase();
    if (d === '' || (host !== d && !host.endsWith('.' + d))) {
      return { outcome: 'rejected', reason: 'domain-mismatch' };
    }
    domain = d;
    hostOnly = false;
  }

  // Path: default from the request-URI unless an absolute one is given.
  let path = defaultPath(url);
  const pathAttr = attrs.get('path');
  if (typeof pathAttr === 'string' && pathAttr.startsWith('/')) path = pathAttr;

  let priority: ParsedSetCookie['priority'] = 'medium';
  const pr = attrs.get('priority');
  if (typeof pr === 'string') {
    const p = pr.toLowerCase();
    if (p === 'low' || p === 'medium' || p === 'high') priority = p;
  }

  return {
    outcome: 'ok',
    name,
    value,
    domain,
    path,
    secure,
    hostOnly,
    ...(expires !== undefined ? { expires } : {}),
    priority,
  };
}
