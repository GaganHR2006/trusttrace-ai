# TRUSTTRACE AI — Phase 3

Team Sentrix's local Chrome Extension Manifest V3 prototype and FastAPI backend.

- Phase 1 observes request metadata only during a user-controlled audit and classifies hostnames.
- Phase 2 discovers candidate privacy-policy URLs, lets the user choose one, then fetches and extracts its text through the local API.
- Phase 3 retrieves source passages from a locally indexed set of official Indian DPDP instruments. It does not call an LLM, interpret legal obligations, or score risk.

## Requirements

- Windows 10/11
- Python 3.11 or newer
- Node.js 20 LTS or newer
- Google Chrome

## 1. Windows setup

Open PowerShell in the project root:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r backend\requirements-dev.txt
npm ci
```

If Python 3.14 is unavailable, replace `-3.14` with `-3.11` or another installed 3.11+ version. Check installed versions with `py -0p`. If PowerShell blocks activation, allow it for this terminal only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

`requirements-dev.txt` includes the backend runtime dependencies needed to run the API and its tests. The extension dependencies are pinned in `package-lock.json`.

## 2. Run the local API

With the virtual environment activated, start FastAPI from the project root:

```powershell
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

The API binds to loopback only. In another PowerShell window, verify the retained health endpoint and interactive docs:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health | ConvertTo-Json -Compress
Invoke-WebRequest http://127.0.0.1:8000/docs -UseBasicParsing | Select-Object -ExpandProperty StatusCode
```

Expected health response remains `{"status":"ok","service":"trusttrace-api","phase":"0"}`; docs should return `200`.

## 3. Build and load the extension

From the project root:

```powershell
npm run build:extension
```

The generated extension is `dist\extension`. In Chrome, open `chrome://extensions`, enable **Developer mode**, and select **Load unpacked** → `dist\extension`. Reload the extension after rebuilding. Phase 1 audit behavior is preserved.

The manifest adds only the `scripting` API permission for a one-time, user-triggered scan of the active page DOM. The existing `activeTab` permission scopes that operation to the tab where the user opened the popup. No broad, persistent site access is added. The existing optional HTTP/HTTPS host patterns cover the local API origin; the extension requests only `http://127.0.0.1:8000/*` when the user chooses **Fetch selected policy**.

## 4. Discover and extract a policy

1. Start the API using the command above.
2. Open an ordinary HTTP/HTTPS website and open the TRUSTTRACE AI popup.
3. Click **Find policy candidates**. The extension reads visible anchor text/URLs and adds common same-origin policy paths. It does not fetch candidates during discovery.
4. Review the candidate URL in the selector and choose one explicitly.
5. Click **Fetch selected policy** and approve the local API origin request if Chrome asks.
6. The popup displays the final source URL and extracted text. The backend response also includes exact excerpt slices with offsets and the source URL. Offsets are zero-based Python Unicode code-point indexes into the exact returned `text`; `end` is exclusive and `text[start:end]` equals each excerpt's text.

The API can also be called from PowerShell after it starts. This example asks the local API to retrieve a public policy URL:

```powershell
$body = @{ url = "https://example.com/privacy" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/policy/extract -ContentType "application/json" -Body $body
```

## 5. Fetching and extraction limits

- Only HTTP/HTTPS and their standard ports are accepted. URL credentials and local/reserved hostnames are rejected.
- Before each connection, every DNS answer is checked and must be globally routable. The checked addresses are pinned for that request; environment proxy settings are ignored. Redirects are followed manually, with each destination revalidated and resolved again (maximum four redirects).
- The fetch has an overall time limit, DNS/connect/read timeouts, a 1 MB response limit, and permits only HTML, XHTML, or plain text. Compressed responses are rejected. These controls also reject loopback, private, link-local, reserved, and metadata-service IPs.
- At most 8 policy fetches and 4 system DNS lookups may be in flight per backend process. When capacity is full, new work receives HTTP 503 rather than queuing without a bound. A timed-out system `getaddrinfo` call may continue in its worker thread; its slot remains occupied until that underlying call completes. The fixed worker pool and lookup slots bound that residual work, but cannot forcibly cancel an OS resolver call.
- HTML parsing removes scripts, styles, navigation, headers, footers, forms, frames, and similar elements, then normalizes whitespace. This is extracted text, not a byte-for-byte copy of source HTML. Returned excerpts are exact slices of that extracted text, with zero-based Python Unicode code-point offsets (exclusive `end`) into the returned string and the final source URL. The response reports when text was truncated at 200,000 characters.
- Fetched page content is treated as untrusted text. It is never executed, interpreted as instructions, summarized, or sent to an LLM. The API and popup do not persist the policy text.
- Discovery can miss links hidden behind scripts, buttons, consent dialogs, or pages outside the current DOM. Common paths are guesses; a candidate is not confirmed until the user selects it and the fetch succeeds.
- This prototype is not a general-purpose fetch proxy. Keep the API bound to loopback and do not expose it publicly. SSRF checks reduce risk but do not replace operating-system or network egress controls.
- Backend additions are `aiohttp` (Apache-2.0 and MIT) and Beautiful Soup 4 (MIT); their package distributions contain the license texts.

## 6. Run the complete automated test suite

With Node.js installed and the Python virtual environment active:

```powershell
npm test
.\.venv\Scripts\python.exe -m unittest discover -s backend\tests -v
```

When the virtual environment is activated, `npm run test:all` runs the same Node and Python suites in sequence. The explicit interpreter command above is reliable even when PowerShell has not activated `.venv`.

This runs all Node tests (classifier, audit popup refresh, and policy-link discovery) followed by the Python `unittest` suite. Most Python fetch and redirect tests use mocked DNS/network responses and do not fetch public websites. One local HTTPS integration test starts a loopback-only test server with a checked-in, test-only certificate/CA, trusts that CA without disabling TLS verification, and routes a deliberately unresolvable test hostname to loopback through the pinned resolver. It checks the actual TLS hostname/SNI, HTTP `Host`, pinned-address connection, and ignored proxy environment variables. The certificate private key in `backend\tests\fixtures` is test-only and must never be used outside this suite. Tests do not verify live Chrome permission prompts, DOM injection, or browser event delivery.

To run either suite separately:

```powershell
npm test
npm run test:python
```

## 7. Build the local DPDP legal corpus

With the virtual environment activated, run this explicit one-time/refresh command from the repository root:

```powershell
python scripts\ingest-legal-sources.py
```

It downloads only the fixed HTTPS PDF URLs listed in `backend\data\legal_sources.json`, checks the official-host allowlist, same-host HTTPS redirects, PDF signature and a 12 MB per-file ceiling, then extracts text from the PDFs and creates a local SQLite index. The index stores one passage per numbered Act section or Rule, each document's schedules as a separate passage, and whole instrument text for notifications and orders. Provision text is preserved as extracted by `pypdf`; schedule passages retain the PDF's extracted numbering but are not represented as sections or rules. The source PDFs and generated database are local, ignored runtime data; no download occurs when the API starts. Update the registry and review the official documents before refreshing it.

If ingestion fails with a certificate-verification error and Python's configured CA file is missing, do not disable TLS verification. In PowerShell, install `certifi` into the active virtual environment if needed and point this command at its CA bundle for the current session:

```powershell
python -m pip install certifi
$env:SSL_CERT_FILE = python -c "import certifi; print(certifi.where())"
python scripts\ingest-legal-sources.py
Remove-Item Env:SSL_CERT_FILE
```

Use that workaround only for the certificate-store problem; DNS or HTTP errors should be diagnosed separately. The current Windows setup needed the `certifi` bundle because its configured OpenSSL CA file was absent.

The source registry currently records the Act as enacted (MeitY-hosted Gazette PDF), final Rules G.S.R. 846(E), the Act commencement notification G.S.R. 843(E), Rules corrigendum G.S.R. 892(E), and the Digital Personal Data Protection (Removal of Difficulties) Order, 2026, S.O. 5458(E). The Act PDF is the original 2023 Gazette text; the 2026 Order is a separate amendment passage and is not silently merged into a purported consolidated Act. Rules and Act provisions have phased/provision-specific commencement. The registry records the issuing dates and source metadata; use the cited commencement notification and each instrument rather than treating one date as applying to every provision.

The retriever uses deterministic TF-IDF term vectors in SQLite, with no downloaded embedding model, no network queries, and no additional site/API permissions. This is intentionally a small offline MVP; lexical TF-IDF can miss semantically related wording. Search returns complete provision passages with source URL, instrument/version, locator, SHA-256 of the source PDF and an exact quote/offset invariant. A low-match or empty corpus produces `insufficient_evidence`; an uninitialized corpus returns HTTP 503 until ingestion succeeds.

Example API calls after ingestion and API startup:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/legal/sources | ConvertTo-Json -Depth 6
$body = @{ query = "notice and consent request"; limit = 5 } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/legal/search -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 8
```

Retrieved citations identify source passages for research. They do not establish that a law applies to a particular website, that a website violated a law, or that a browser-observed request transferred personal data. The retriever is independent of the browser observation store and deterministic risk engine. No legal RAG answer generation or LLM is connected in this phase.

### Phase 3 source and evidence limitations

- The corpus was downloaded from the five registry URLs and indexed locally on 2026-10-18 (72 passages across five distinct PDFs). Each passage records its source URL, instrument/version metadata, effective-date note and SHA-256 of the exact source PDF. Rebuild it explicitly after reviewing the official source registry; tests do not fetch public websites.
- The extraction is PDF text extraction, not OCR or a certified transcription. Review source text and extracted passages against the linked official PDF. Source URLs and hashes identify the input file, while the API quote is an exact slice of the locally stored extraction.
- PDF text order and line wrapping can be imperfect. Numbered Act sections and Rules are extracted as separate passages; schedules are preserved in a single schedule passage per instrument so numbered schedule rows are not cited as statutory section/rule numbers.
- The Act PDF is as enacted in 2023. The registry separately includes the 2026 Removal of Difficulties Order to expose the known later text changes; it is not a consolidated statute. Other amendments or notifications may be issued later, so refresh/review the registry before operational reliance.
- TF-IDF is lexical retrieval, not neural semantic search. “Insufficient evidence” means this local index returned no passage above its retrieval threshold; it is not a legal conclusion that no relevant law exists.
- This is a hackathon research aid, not legal advice or a substitute for checking the current Official Gazette/India Code record.

Phase 1/2 integration note: request observation, policy discovery/extraction, and failed-fetch handling were manually reported as passed. The optional wildcard-origin comparison was observed as `[]` → both HTTP/HTTPS wildcards → `[]`; Chrome Site access was set to **On all sites**, so **On click** behavior was not tested. The file-URL access setting was not changed.

## Privacy interpretation limits

Observed third-party requests do not prove personal-data transfer, user tracking, illegality, or a legal violation. Extracted privacy-policy text is source material only; Phase 2 makes no claim about its accuracy, legal meaning, or consistency with observed requests. Phase 3 retrieval identifies source passages only and does not determine applicability or a legal violation.
