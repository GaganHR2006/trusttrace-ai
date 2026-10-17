import test from "node:test";
import assert from "node:assert/strict";

class FakeElement {
  textContent = "";
  disabled = false;
  children = [];
  listeners = new Map();

  addEventListener(type, callback) {
    this.listeners.set(type, callback);
  }

  replaceChildren(...children) {
    this.children = children;
  }

  append(...children) {
    this.children.push(...children);
  }
}

test("popup refreshes request counts when the session snapshot changes", async () => {
  const elements = new Map();
  const getElement = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement());
    return elements.get(id);
  };
  let storageChanged;
  globalThis.document = {
    getElementById: getElement,
    createElement: () => new FakeElement(),
  };
  globalThis.chrome = {
    tabs: { query: async () => [{ id: 9, url: "https://example.com/", title: "Example" }] },
    storage: { onChanged: { addListener: (listener) => { storageChanged = listener; } } },
    runtime: {
      sendMessage(_message, callback) {
        callback({ ok: true, result: { active: true, pageOrigin: "https://example.com", totalRequests: 0, domains: {} } });
      },
    },
  };

  await import(`../extension/popup.js?popup-test=${Date.now()}`);
  assert.equal(getElement("request-count").textContent, "0");

  storageChanged({
    phase1Audit: {
      newValue: {
        snapshot: {
          active: true,
          pageOrigin: "https://example.com",
          totalRequests: 2,
          domains: { "cdn.example.net": { party: "third-party", count: 2 } },
        },
      },
    },
  }, "session");

  assert.equal(getElement("request-count").textContent, "2");
  assert.equal(getElement("domain-count").textContent, "1");
  assert.match(getElement("domain-list").children[0].children[0].textContent, /cdn\.example\.net/);
});
