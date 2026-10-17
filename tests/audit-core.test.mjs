import test from "node:test";
import assert from "node:assert/strict";
import { AuditSession, classifyRequestDomain, getSiteDomain, parseSupportedUrl } from "../extension/audit-core.mjs";

test("classifies subdomains and different ports as first-party", () => {
  assert.deepEqual(
    classifyRequestDomain("https://www.example.com:8443/path", "https://api.example.com:9443/data"),
    { domain: "api.example.com", party: "first-party" },
  );
  assert.equal(classifyRequestDomain("https://shop.example.co.in", "https://cdn.example.co.in:444/x").party, "first-party");
});

test("same registrable domain stays first-party across subdomains and ports", () => {
  assert.equal(getSiteDomain("https://kn.wikipedia.org"), "wikipedia.org");
  assert.equal(getSiteDomain("https://www.wikipedia.org:8443"), "wikipedia.org");
  assert.equal(classifyRequestDomain("https://kn.wikipedia.org", "https://www.wikipedia.org:9443").party, "first-party");
});

test("different registrable domains are third-party", () => {
  assert.equal(classifyRequestDomain("https://kn.wikipedia.org", "https://www.wikimedia.org").party, "third-party");
  assert.equal(classifyRequestDomain("https://shop.example.com", "https://api.other.com").party, "third-party");
});

test("Wikimedia hosts are consistently third-party relative to kn.wikipedia.org", () => {
  for (const host of ["thumb.wikimedia.org", "upload.wikimedia.org", "auth.wikimedia.org"]) {
    assert.equal(classifyRequestDomain("https://kn.wikipedia.org", `https://${host}/resource`).party, "third-party", host);
  }
});

test("does not confuse a suffix lookalike with a subdomain", () => {
  assert.equal(classifyRequestDomain("https://example.com", "https://notexample.com").party, "third-party");
  assert.equal(classifyRequestDomain("https://wikipedia.org", "https://notwikipedia.org").party, "third-party");
  assert.equal(getSiteDomain("https://tracker.other.net"), "other.net");
});

test("uncommon multi-label public suffixes keep registrants separate", () => {
  for (const suffix of ["com.hk", "com.ar"]) {
    assert.equal(
      classifyRequestDomain(`https://www.alpha.${suffix}`, `https://api.alpha.${suffix}`).party,
      "first-party",
      `same registrant under ${suffix}`,
    );
    assert.equal(
      classifyRequestDomain(`https://www.alpha.${suffix}`, `https://beta.${suffix}`).party,
      "third-party",
      `different registrants under ${suffix}`,
    );
  }
});

test("private hosting suffixes keep separate tenants separate", () => {
  assert.equal(classifyRequestDomain("https://alice.github.io", "https://docs.alice.github.io").party, "first-party");
  assert.equal(classifyRequestDomain("https://alice.github.io", "https://bob.github.io").party, "third-party");
  assert.equal(classifyRequestDomain("https://alpha.appspot.com", "https://beta.appspot.com").party, "third-party");
});

test("private hosting suffix wildcard rules separate tenants", () => {
  assert.equal(classifyRequestDomain("https://alice.blogspot.com", "https://cdn.alice.blogspot.com").party, "first-party");
  assert.equal(classifyRequestDomain("https://alice.blogspot.com", "https://bob.blogspot.com").party, "third-party");
});

test("PSL wildcard rules identify tenant registrants", () => {
  assert.equal(classifyRequestDomain("https://a.foo.ck", "https://b.foo.ck").party, "third-party");
  assert.equal(classifyRequestDomain("https://a.foo.ck", "https://cdn.a.foo.ck").party, "first-party");
});

test("PSL exception rules identify registrants", () => {
  assert.equal(getSiteDomain("https://www.ck"), "www.ck");
  assert.equal(classifyRequestDomain("https://www.ck", "https://api.www.ck").party, "first-party");
});

test("IP addresses and localhost retain host-based classification", () => {
  assert.equal(classifyRequestDomain("http://127.0.0.1:8000", "http://127.0.0.1:9000").party, "first-party");
  assert.equal(classifyRequestDomain("http://127.0.0.1", "http://127.0.0.2").party, "third-party");
  assert.equal(classifyRequestDomain("http://[::1]:8000", "http://[::1]:9000").party, "first-party");
  assert.equal(classifyRequestDomain("http://localhost:8000", "http://localhost:9000").party, "first-party");
  assert.equal(classifyRequestDomain("http://localhost", "http://other.localhost").party, "third-party");
});

test("malformed URLs are rejected before hostname classification", () => {
  for (const url of ["http://[", "https://example.com:bad", "not a URL"]) {
    assert.throws(() => getSiteDomain(url), TypeError);
  }
});

test("duplicate requests increment request and domain counts without duplicating domain entries", () => {
  const audit = new AuditSession("https://www.example.com");
  audit.record("https://api.example.com/data");
  audit.record("https://api.example.com/again");
  audit.record("https://tracker.test/pixel");
  const result = audit.snapshot();
  assert.equal(result.totalRequests, 3);
  assert.equal(Object.keys(result.domains).length, 2);
  assert.equal(result.domains["api.example.com"].count, 2);
  assert.equal(result.domains["tracker.test"].count, 1);
});

test("audit lifecycle records only while active and stop is idempotent", () => {
  const audit = new AuditSession("http://example.com");
  assert.equal(audit.active, true);
  assert.equal(audit.record("https://cdn.example.com/asset"), true);
  const stopped = audit.stop();
  assert.equal(stopped.active, false);
  assert.equal(audit.stop().active, false);
  assert.equal(audit.record("https://tracker.test/pixel"), false);
  assert.equal(audit.snapshot().totalRequests, 1);
});

test("rejects unsupported and invalid URLs", () => {
  for (const url of ["chrome://settings", "file:///tmp/example", "data:text/plain,hello", "not a URL"]) {
    assert.throws(() => parseSupportedUrl(url), TypeError);
  }
  const audit = new AuditSession("https://example.com");
  assert.equal(audit.record("chrome://settings"), false);
  assert.equal(audit.totalRequests, 0);
});
