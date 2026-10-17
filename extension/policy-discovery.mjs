// This function is injected into the active tab. Keep it self-contained so
// Chrome can serialize it; it only reads the DOM and never follows a link.
export function discoverPolicyCandidates() {
  const policyLinkHint = /privacy|data[\s-]*protection|personal[\s-]*data/i;
  const commonPolicyPaths = [
    "/privacy-policy",
    "/privacy",
    "/privacy_notice",
    "/privacy-notice",
    "/privacy-statement",
    "/policies/privacy-policy",
    "/legal/privacy",
  ];
  const page = new URL(location.href);
  if (page.protocol !== "http:" && page.protocol !== "https:") {
    throw new Error("Policy discovery is supported only on HTTP and HTTPS pages.");
  }

  const candidates = [];
  const known = new Set();
  for (const anchor of document.querySelectorAll("a[href]")) {
    const text = (anchor.innerText || anchor.textContent || anchor.getAttribute("aria-label") || anchor.title || "")
      .replace(/\s+/g, " ").trim();
    const isVisible = anchor.getClientRects().length > 0
      && (typeof getComputedStyle !== "function" || (() => {
        const style = getComputedStyle(anchor);
        return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
      })());
    if (!isVisible) continue;

    let destination;
    try {
      destination = new URL(anchor.href, page.href);
    } catch {
      continue;
    }
    if (!new Set(["http:", "https:"]).has(destination.protocol)
      || destination.username || destination.password
      || !(policyLinkHint.test(text) || policyLinkHint.test(destination.href))) continue;

    destination.hash = "";
    if (known.has(destination.href)) continue;
    known.add(destination.href);
    candidates.push({
      url: destination.href,
      label: text || "Privacy-related link",
      source: "Visible page link",
    });
    if (candidates.length >= 20) break;
  }

  for (const path of commonPolicyPaths) {
    const destination = new URL(path, page.origin);
    if (known.has(destination.href)) continue;
    known.add(destination.href);
    candidates.push({ url: destination.href, label: path, source: "Common policy URL pattern" });
  }
  return candidates;
}
