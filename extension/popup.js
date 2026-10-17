import { parseSupportedUrl } from "./audit-core.mjs";
import { discoverPolicyCandidates } from "./policy-discovery.mjs";

const readTabButton = document.getElementById("read-tab");
const titleElement = document.getElementById("page-title");
const urlElement = document.getElementById("page-url");
const statusElement = document.getElementById("status");
const startButton = document.getElementById("start-audit");
const stopButton = document.getElementById("stop-audit");
const auditStatus = document.getElementById("audit-status");
const requestCount = document.getElementById("request-count");
const domainCount = document.getElementById("domain-count");
const domainList = document.getElementById("domain-list");
const STATE_KEY = "phase1Audit";
const discoverPolicyButton = document.getElementById("discover-policy");
const policyCandidate = document.getElementById("policy-candidate");
const fetchPolicyButton = document.getElementById("fetch-policy");
const policyStatus = document.getElementById("policy-status");
const policyResult = document.getElementById("policy-result");
const policySource = document.getElementById("policy-source");
const policyText = document.getElementById("policy-text");
const policyTruncated = document.getElementById("policy-truncated");
const API_ORIGIN = "http://127.0.0.1:8000";

let activeTab = null;
let policyCandidates = [];

function message(type, fields = {}) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, ...fields }, (response) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!response?.ok) return reject(new Error(response?.error || "Audit operation failed."));
      resolve(response.result);
    });
  });
}

function renderAudit(snapshot) {
  const domains = Object.entries(snapshot?.domains || {}).sort(([a], [b]) => a.localeCompare(b));
  requestCount.textContent = String(snapshot?.totalRequests || 0);
  domainCount.textContent = String(domains.length);
  domainList.replaceChildren();
  for (const [domain, details] of domains) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = `${domain} · ${details.party}`;
    const count = document.createElement("strong");
    count.textContent = String(details.count);
    item.append(label, count);
    domainList.append(item);
  }
  const running = Boolean(snapshot?.active);
  startButton.disabled = running || !activeTab;
  stopButton.disabled = !running;
  if (running) {
    auditStatus.textContent = `Audit running for ${snapshot.pageOrigin}. Stop it to end observation and release site access.`;
  } else if (snapshot) {
    auditStatus.textContent = `Audit stopped for ${snapshot.pageOrigin}. ${snapshot.totalRequests} request(s) observed.`;
  } else {
    auditStatus.textContent = "No audit is running.";
  }
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "session" || !Object.hasOwn(changes, STATE_KEY)) return;
  renderAudit(changes[STATE_KEY].newValue?.snapshot || null);
});

function renderCandidates(candidates) {
  policyCandidates = candidates;
  policyCandidate.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Review and select a candidate…";
  placeholder.selected = true;
  placeholder.disabled = true;
  policyCandidate.append(placeholder);
  for (const [index, candidate] of candidates.entries()) {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = `${candidate.label} — ${candidate.url}`;
    policyCandidate.append(option);
  }
  policyCandidate.disabled = candidates.length === 0;
  fetchPolicyButton.disabled = true;
  policyStatus.textContent = candidates.length
    ? `${candidates.length} candidate(s) found. Review the URL and select one before fetching.`
    : "No candidate links or common policy paths were found.";
}

discoverPolicyButton.addEventListener("click", async () => {
  discoverPolicyButton.disabled = true;
  policyStatus.textContent = "Reading visible policy links and checking common paths…";
  policyResult.hidden = true;
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (!tab?.id || !tab.url) throw new Error("No active tab is available.");
    parseSupportedUrl(tab.url);
    activeTab = tab;
    const [execution] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: discoverPolicyCandidates,
    });
    renderCandidates(Array.isArray(execution?.result) ? execution.result : []);
  } catch (error) {
    policyStatus.textContent = error.message || "Unable to inspect this tab.";
  } finally {
    discoverPolicyButton.disabled = false;
  }
});

policyCandidate.addEventListener("change", () => {
  fetchPolicyButton.disabled = !policyCandidates[Number(policyCandidate.value)];
});

fetchPolicyButton.addEventListener("click", async () => {
  const candidate = policyCandidates[Number(policyCandidate.value)];
  if (!candidate) return;
  fetchPolicyButton.disabled = true;
  policyStatus.textContent = "Requesting access to the local TRUSTTRACE API…";
  policyResult.hidden = true;
  try {
    const permitted = await chrome.permissions.request({ origins: [`${API_ORIGIN}/*`] });
    if (!permitted) throw new Error("Local API access was not granted. The policy was not fetched.");
    policyStatus.textContent = "Fetching and extracting the selected policy…";
    const response = await fetch(`${API_ORIGIN}/policy/extract`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: candidate.url }),
      signal: AbortSignal.timeout(15_000),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || `Policy API returned HTTP ${response.status}.`);
    policySource.href = result.source_url;
    policySource.textContent = result.source_url;
    policyText.textContent = result.text;
    policyTruncated.hidden = !result.truncated;
    policyResult.hidden = false;
    policyStatus.textContent = `Extracted ${result.text.length.toLocaleString()} characters from the selected policy. Text is shown verbatim after HTML cleanup.`;
  } catch (error) {
    policyStatus.textContent = error.name === "TimeoutError"
      ? "The local policy request timed out."
      : error.message || "Unable to fetch this policy.";
  } finally {
    fetchPolicyButton.disabled = policyCandidates.length === 0;
  }
});

async function loadActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  activeTab = tab || null;
  startButton.disabled = !activeTab;
  if (!activeTab?.url) return;
  titleElement.textContent = activeTab.title || "(Page title unavailable)";
  urlElement.textContent = activeTab.url;
  try {
    parseSupportedUrl(activeTab.url);
  } catch {
    startButton.disabled = true;
  }
}

readTabButton.addEventListener("click", async () => {
  titleElement.textContent = "Reading active tab…";
  urlElement.textContent = "—";
  statusElement.textContent = "Checking current tab.";
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (!tab?.url) throw new Error("No active tab was available.");
    parseSupportedUrl(tab.url);
    titleElement.textContent = tab.title || "(Page title unavailable)";
    urlElement.textContent = tab.url;
    statusElement.textContent = "Active tab check passed. This check reads the title and URL; browser observation runs only after you start an audit.";
  } catch (error) {
    titleElement.textContent = "Unable to read this page";
    urlElement.textContent = "—";
    statusElement.textContent = error.message || "An unexpected error occurred.";
  }
});

startButton.addEventListener("click", async () => {
  if (!activeTab?.url) return;
  startButton.disabled = true;
  auditStatus.textContent = "Requesting temporary HTTP/HTTPS site access…";
  try {
    parseSupportedUrl(activeTab.url);
    const granted = await chrome.permissions.request({ origins: ["http://*/*", "https://*/*"] });
    if (!granted) throw new Error("Site access was not granted. No audit was started.");
    const snapshot = await message("START_AUDIT", { tabId: activeTab.id, pageUrl: activeTab.url });
    renderAudit(snapshot);
  } catch (error) {
    auditStatus.textContent = error.message || "Unable to start the audit.";
    startButton.disabled = false;
  }
});

stopButton.addEventListener("click", async () => {
  stopButton.disabled = true;
  auditStatus.textContent = "Stopping audit and releasing temporary site access…";
  try {
    renderAudit(await message("STOP_AUDIT"));
  } catch (error) {
    auditStatus.textContent = error.message || "Unable to stop the audit.";
    stopButton.disabled = false;
  }
});

try {
  await loadActiveTab();
  renderAudit(await message("GET_AUDIT"));
} catch (error) {
  auditStatus.textContent = error.message || "Unable to read audit state.";
}
