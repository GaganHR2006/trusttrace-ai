import test from "node:test";
import assert from "node:assert/strict";
import { discoverPolicyCandidates } from "../extension/policy-discovery.mjs";

function anchor({ href, text, visible = true, ariaLabel = "" }) {
  return {
    href,
    innerText: text,
    textContent: text,
    title: "",
    getAttribute(name) { return name === "aria-label" ? ariaLabel : null; },
    getClientRects() { return visible ? [{}] : []; },
  };
}

test("discovers visible privacy links and same-origin common patterns", () => {
  globalThis.location = { href: "https://shop.example.com/products/item" };
  globalThis.getComputedStyle = () => ({ display: "block", visibility: "visible", opacity: "1" });
  globalThis.document = {
    querySelectorAll: () => [
      anchor({ href: "https://shop.example.com/privacy-policy#choices", text: "Privacy Policy" }),
      anchor({ href: "https://vendor.example/privacy", text: "Data Protection" }),
      anchor({ href: "/hidden-privacy", text: "Privacy", visible: false }),
      anchor({ href: "javascript:alert(1)", text: "Privacy Policy" }),
      anchor({ href: "/contact", text: "Contact" }),
    ],
  };

  const candidates = discoverPolicyCandidates();
  assert.equal(candidates[0].url, "https://shop.example.com/privacy-policy");
  assert.equal(candidates[0].source, "Visible page link");
  assert.equal(candidates[1].url, "https://vendor.example/privacy");
  assert(candidates.some((item) => item.url === "https://shop.example.com/privacy"));
  assert(!candidates.some((item) => item.url.includes("hidden-privacy")));
  assert(!candidates.some((item) => item.url.startsWith("javascript:")));
  assert.equal(new Set(candidates.map((item) => item.url)).size, candidates.length);
});

test("rejects active-tab schemes outside HTTP and HTTPS", () => {
  globalThis.location = { href: "chrome://settings" };
  globalThis.document = { querySelectorAll: () => [] };
  assert.throws(() => discoverPolicyCandidates(), /HTTP and HTTPS/);
});

test("injected discovery function is self-contained when serialized", () => {
  globalThis.location = { href: "https://shop.example.com/" };
  globalThis.document = { querySelectorAll: () => [] };
  const injected = Function(`return (${discoverPolicyCandidates.toString()})`)();
  assert(injected().some((item) => item.url === "https://shop.example.com/privacy-policy"));
});
