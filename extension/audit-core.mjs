import { getDomain } from "tldts";

const HTTP_PROTOCOLS = new Set(["http:", "https:"]);

export function parseSupportedUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError("Enter a valid HTTP or HTTPS page URL.");
  }
  if (!HTTP_PROTOCOLS.has(parsed.protocol)) {
    throw new TypeError("Audits are supported only on regular HTTP or HTTPS pages.");
  }
  return parsed;
}

export function getSiteDomain(value) {
  const parsed = value instanceof URL ? value : parseSupportedUrl(value);
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!hostname || hostname === "localhost" || /^\d+(\.\d+){3}$/.test(hostname) || hostname.includes(":")) {
    return hostname;
  }
  // URL parsing above canonicalizes the hostname; tldts uses its bundled PSL
  // snapshot, including private suffixes. Fall back for single-label hosts and
  // public-suffix-only hosts, which have no registrable domain.
  return getDomain(hostname, { allowPrivateDomains: true }) ?? hostname;
}

export function classifyRequestDomain(pageUrl, requestUrl) {
  const page = parseSupportedUrl(pageUrl);
  const request = parseSupportedUrl(requestUrl);
  return {
    domain: request.hostname.toLowerCase(),
    party: getSiteDomain(page) === getSiteDomain(request) ? "first-party" : "third-party",
  };
}

export class AuditSession {
  constructor(pageUrl, savedState = null) {
    const page = parseSupportedUrl(pageUrl);
    this.pageOrigin = page.origin;
    this.pageDomain = page.hostname.toLowerCase();
    this.active = true;
    this.totalRequests = 0;
    this.domains = Object.create(null);
    if (savedState) {
      this.active = Boolean(savedState.active);
      this.totalRequests = Number(savedState.totalRequests) || 0;
      this.domains = savedState.domains && typeof savedState.domains === "object"
        ? Object.assign(Object.create(null), savedState.domains)
        : Object.create(null);
    }
  }

  record(requestUrl) {
    if (!this.active) return false;
    let classified;
    try {
      classified = classifyRequestDomain(this.pageOrigin, requestUrl);
    } catch {
      return false;
    }

    this.totalRequests += 1;
    const existing = this.domains[classified.domain];
    this.domains[classified.domain] = {
      party: classified.party,
      count: (existing?.count || 0) + 1,
    };
    return true;
  }

  stop() {
    this.active = false;
    return this.snapshot();
  }

  snapshot() {
    return {
      active: this.active,
      pageOrigin: this.pageOrigin,
      pageDomain: this.pageDomain,
      totalRequests: this.totalRequests,
      domains: { ...this.domains },
    };
  }
}
