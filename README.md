# CrowdStrike → Zafran Starlark integration

Pulls CrowdStrike device and Spotlight vulnerability data, maps it into Zafran `InstanceData` and `Vulnerability` models, and outputs integration results through the Starlark runner.

`API`: CrowdStrike Falcon | `Models`: `InstanceData`, `Vulnerability` | `Runtime`: Linux/macOS runner

---

## ✨ What this integration does

- Collects machine assets from CrowdStrike device APIs.
- Collects vulnerabilities from Spotlight and enriches remediation actions.
- Correlates vulnerabilities to assets by CrowdStrike AID before collection.

---

## 🚀 Quick start

### ✅ Prerequisites

- CrowdStrike API client with:
  - `devices:read`
  - `vulnerabilities:read`
- Runner binary from Zafran public repo.
- CrowdStrike cloud base URL (default: `https://api.us-2.crowdstrike.com`).

### 🧪 Mock run (fast validation)

```bash
./starlark-runner-linux -script crowdstrike.star -params "mock_mode=true"
```

Expected output: script succeeds and collects mock asset/vulnerability data.

### 🐧 Live run (Linux)

```bash
./starlark-runner-linux \
  -script crowdstrike.star \
  -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET,page_size=200,max_pages=20,max_retries=3,device_details_batch_size=100" \
  -output results.json
```

### 🍎 Live run (macOS)

```bash
./starlark-runner-mac \
  -script crowdstrike.star \
  -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET,page_size=200,max_pages=20,max_retries=3,device_details_batch_size=100" \
  -output results.json
```

Optional pretty formatting:

```bash
python -c "import json, pathlib; p=pathlib.Path('results.json'); d=json.loads(p.read_text(encoding='utf-8')); p.write_text(json.dumps(d, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')"
```

---

## ⚙️ Configuration reference

### 🔐 Required

- `client_id` or `api_key`: CrowdStrike OAuth client ID.
- `api_secret`: CrowdStrike OAuth client secret.

### 🛡️ Optional: safety and performance

- `api_url` (default: `https://api.us-2.crowdstrike.com`): CrowdStrike cloud base URL.
- `page_size` (default: `100`): records requested per page.
- `max_pages` (default: `20`): safety cap per collection loop.
- `max_retries` (default: `3`): retries for token refresh and retryable authenticated GET errors.
- `device_details_batch_size` (default: `100`): number of IDs per device-details call.

### 🔎 Optional: filtering and testing

- `vuln_filter` (default: `status:'open'`): Spotlight FQL filter.
- `mock_mode` (default: `false`): offline synthetic-data mode.

---

## 🧭 Data mapping

### 🖥️ Asset mapping (`InstanceData`)

- `instance_id` and identifier map to CrowdStrike AID.
- Name, OS, IPs, MAC, labels, and key-value tags are mapped from device payload fields.
- `instance_type` is set to machine.

### 🐞 Vulnerability mapping (`Vulnerability`)

- CVE, component metadata, CVSS, severity, scanner fields, and references are mapped from Spotlight payloads.
- Remediation suggestion is enriched from remediations API action when available.
- Remediation ID priority:
  - `apps[].remediation_info.recommended_id`
  - `apps[].remediation_info.minimum_id`
  - `apps[].remediation.ids[]`
- Fallback remediation message:
  - `"No remediation guidance provided by CrowdStrike"`

---

## 🔄 Runtime behavior

1. Authenticate via OAuth2 `POST /oauth2/token`.
2. Collect devices via query + entity hydration endpoints.
3. Collect vulnerabilities via Spotlight combined endpoint.
4. Enrich remediations via remediations entities endpoint.
5. Flush collected data once at completion.

### 🧯 Reliability and safeguards

- Authenticated GET requests auto-refresh token on `401`.
- Retryable statuses (`429`, `5xx`) are retried with bounded backoff.
- Pagination safety controls prevent runaway loops:
  - `max_pages` cap
  - repeated cursor detection
  - short-page termination
- Vulnerabilities are collected only when `instance_id` matches an instance collected in the same run.

---

## 📊 Validation evidence

- Mock run validates end-to-end script execution and data collection plumbing.
- Short live run (`max_pages=1`) validates bounded traversal and mapping correctness.
- Broader live run (`max_pages>1`) validates multi-page traversal, cache behavior, and summary counters.

---

## 🛠️ Troubleshooting

- **Auth failures** -> verify client scopes, client credentials, and correct `api_url` cloud.
- **Zero vulnerabilities** -> validate effective filter and confirm `instance_id` overlap with collected AIDs.
- **Partial data** -> increase `max_pages` and review stop reason in summary logs.
- **Rate limits / slow runs** -> lower `page_size` and/or tune `max_retries`.
- **Windows execution issues** -> run Linux runner under WSL.

---

## 🔗 Reference links

- Runner source: https://github.com/ZafranSecurity/zafran-custom-integrations-public/tree/main
- `genericimport.proto` source of truth: https://github.com/ZafranSecurity/zafran-custom-integrations-public/blob/main/genericimport.proto
- CrowdStrike Falcon docs: https://falcon.crowdstrike.com/documentation