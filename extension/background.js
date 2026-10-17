import { AuditSession, parseSupportedUrl } from "./audit-core.mjs";

const STATE_KEY = "phase1Audit";
const AUDIT_ORIGINS = ["http://*/*", "https://*/*"];
let session = null;
let targetTabId = null;
let lastSnapshot = null;
let queue = Promise.resolve();

function enqueue(operation) {
  const result = queue.then(operation, operation);
  queue = result.catch(() => {});
  return result;
}

async function initialize() {
  const stored = await chrome.storage.session.get(STATE_KEY);
  const saved = stored[STATE_KEY];
  if (saved?.snapshot) lastSnapshot = saved.snapshot;
  if (saved?.snapshot?.active && Number.isInteger(saved.tabId)) {
    try {
      session = new AuditSession(saved.snapshot.pageOrigin, saved.snapshot);
      targetTabId = saved.tabId;
    } catch {
      session = null;
      targetTabId = null;
      lastSnapshot = null;
      await chrome.storage.session.remove(STATE_KEY);
    }
  }
}

const ready = initialize();

async function saveSession() {
  if (!session) {
    await chrome.storage.session.remove(STATE_KEY);
    return;
  }
  await chrome.storage.session.set({
    [STATE_KEY]: { tabId: targetTabId, snapshot: session.snapshot() },
  });
}

async function stopAudit() {
  if (session) session.stop();
  const result = session?.snapshot() || null;
  lastSnapshot = result;
  targetTabId = null;
  session = null;
  await chrome.storage.session.set({ [STATE_KEY]: { tabId: null, snapshot: result } });
  await chrome.permissions.remove({ origins: AUDIT_ORIGINS });
  return result;
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.tabId < 0) return;
    void enqueue(async () => {
      await ready;
      if (!session?.active || details.tabId !== targetTabId) return;
      if (session.record(details.url)) await saveSession();
    });
  },
  { urls: ["<all_urls>"] },
);

chrome.tabs.onRemoved.addListener((tabId) => {
  void enqueue(async () => {
    await ready;
    if (tabId === targetTabId) await stopAudit();
  });
});

chrome.runtime.onStartup.addListener(() => {
  void enqueue(async () => {
    await ready;
    session = null;
    targetTabId = null;
    lastSnapshot = null;
    await chrome.storage.session.remove(STATE_KEY);
    await chrome.permissions.remove({ origins: AUDIT_ORIGINS });
  });
});

chrome.runtime.onInstalled.addListener(() => {
  void enqueue(async () => {
    await ready;
    session = null;
    targetTabId = null;
    lastSnapshot = null;
    await chrome.storage.session.remove(STATE_KEY);
    await chrome.permissions.remove({ origins: AUDIT_ORIGINS });
  });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!["START_AUDIT", "STOP_AUDIT", "GET_AUDIT"].includes(message?.type)) return;
  void enqueue(async () => {
    await ready;
    if (message.type === "START_AUDIT") {
      if (session?.active) throw new Error("An audit is already running. Stop it before starting another.");
      const page = parseSupportedUrl(message.pageUrl);
      if (!Number.isInteger(message.tabId) || message.tabId < 0) throw new Error("The active tab is unavailable.");
      session = new AuditSession(page.href);
      targetTabId = message.tabId;
      lastSnapshot = null;
      await saveSession();
      return session.snapshot();
    }
    if (message.type === "STOP_AUDIT") return stopAudit();
    return session?.snapshot() || lastSnapshot;
  }).then(
    (result) => sendResponse({ ok: true, result }),
    (error) => sendResponse({ ok: false, error: error.message || "Audit operation failed." }),
  );
  return true;
});
