# CrowdStrike → Zafran Starlark Integration

This repo contains a Starlark script that pulls CrowdStrike devices and vulnerabilities and maps them into Zafran's Assets (`InstanceData`) and Vulnerabilities models using the provided runner.

## Files
- `crowdstrike.star` — integration script (authentication, asset pull, vulnerability pull, mapping, flushing).
- `genericimport.proto` reference (upstream source of truth): https://github.com/ZafranSecurity/zafran-custom-integrations-public/blob/main/genericimport.proto

## Prerequisites
- CrowdStrike API client with scopes:
  - `devices:read`
  - `vulnerabilities:read`
- Runner binary from the Zafran public repo (`starlark-runner-linux` or `starlark-runner-mac`).
- Base URL for your cloud (default `https://api.us-2.crowdstrike.com`).

## Parameters
- `api_url`: CrowdStrike base URL (default `https://api.us-2.crowdstrike.com`).
- `client_id` (or `api_key`): CrowdStrike OAuth client id.
- `api_secret`: CrowdStrike client secret.
- `page_size` (optional): Pagination size (default `100`).
- `vuln_filter` (optional): Explicit Spotlight FQL filter. Default is `status:'open'`.
- `max_pages` (optional): Safety cap per collection loop (default `20`).
- `max_retries` (optional): Max retries for `401` refresh and retryable statuses (`429`, `5xx`) (default `3`).
- `device_details_batch_size` (optional): Number of device IDs per device-details request (default `100`).
- `mock_mode` (optional): `true`/`false` toggle for offline mock collection (default `false`).

## Run Examples
```bash
# Mock mode (offline validation)
./starlark-runner-linux -script crowdstrike.star -params "mock_mode=true"

# Linux
./starlark-runner-linux \
  -script crowdstrike.star \
  -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET,page_size=200,max_pages=20,max_retries=3,device_details_batch_size=100" \
  -output results.json \
  && python -c "import json, pathlib; p=pathlib.Path('results.json'); d=json.loads(p.read_text(encoding='utf-8')); p.write_text(json.dumps(d, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')"

# macOS
./starlark-runner-mac \
  -script crowdstrike.star \
  -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET,page_size=200,max_pages=20,max_retries=3,device_details_batch_size=100" \
  -output results.json \
  && python -c "import json, pathlib; p=pathlib.Path('results.json'); d=json.loads(p.read_text(encoding='utf-8')); p.write_text(json.dumps(d, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')"

```

## Behavior
- Authenticates via OAuth2 `POST /oauth2/token`.
- For authenticated `GET` requests, refreshes token on `401` and retries retryable statuses (`429`, `5xx`) up to `max_retries`.
- Paginates devices (`/devices/queries/devices/v1` + `/devices/entities/devices/v2`).
  - Device details are requested with repeated `ids` query params (`ids=id1&ids=id2...`) and batched by `device_details_batch_size` (default `100` IDs/request).
- Paginates vulnerabilities (`/spotlight/combined/vulnerabilities/v1`) using CrowdStrike `after` continuation tokens.
- Applies required Spotlight FQL filter (`status:'open'` by default, or `vuln_filter` when supplied).
- Applies `max_pages` as a safety stop for both device and vulnerability loops.
- Maps:
  - `InstanceData`: `instance_id`/identifier from AID, hostname, OS/platform, IPs, MAC, tags/groups to labels, domain/site/platform/product_type as key-value tags, type `INSTANCE_TYPE_MACHINE`.
  - `Vulnerability`: CVE, CVSS (score/vector), component (app/vendor/version), remediation suggestion, severity, links.
    - Remediation suggestions are enriched from `GET /spotlight/entities/remediations/v2` using remediation IDs discovered in vulnerability payloads.
    - ID priority: `apps[].remediation_info.recommended_id` -> `apps[].remediation_info.minimum_id` -> `apps[].remediation.ids[]`.
    - If no remediation action is resolved from API, fallback mapping is used and finally defaults to `"No remediation guidance provided by CrowdStrike"`.
- Collects vulnerabilities only when `instance_id` matches an instance collected in the current run.
- Logs vulnerability summary counters:
  - pages processed
  - collected vulnerabilities
  - skipped findings with missing `instance_id`
  - skipped findings with unknown instance mapping
  - remediation IDs discovered, lookup requests, cache hits, and resolved remediation actions
  - suggestions sourced from remediations API action vs fallback
  - stop reason for traversal termination
- Flushes once at completion to preserve instance/vulnerability association.

## Validation Summary
- Mock run (`mock_mode=true`): script executes successfully and collects 1 instance and 1 vulnerability.
- Short live sample (`max_pages=1`): validates end-to-end API/auth flow and expected bounded traversal behavior.
- Broader live sample (`max_pages>1`): validates multi-page pagination, remediation cache enrichment, and summary counters.

## Design Choices
- Safety-first traversal: `max_pages` caps both device and vulnerability loops to avoid runaway pagination.
- Default vulnerability scope: uses `status:'open'` unless `vuln_filter` is explicitly provided.
- Remediation enrichment: resolves remediation actions via remediations API with page-level discovery and run-level cache reuse.
- Association integrity: vulnerabilities are collected only if `instance_id` maps to an instance collected in the same run.

## Known Limitations
- OAuth token exchange (`POST /oauth2/token`) is a single request path; retry/backoff logic is implemented for authenticated `GET` requests.
- `max_pages` may truncate very large environments if set too low; tune based on expected tenant size.
- Minimal URL encoding is used for query composition and assumes expected CrowdStrike ID/filter character sets.

## Notes
- `starlark-runner-linux` and `starlark-runner-mac` can be downloaded from the Zafran public repo: https://github.com/ZafranSecurity/zafran-custom-integrations-public/tree/main
- Keep credentials secure; pass via runner params or env injection, not hard-coded.
- If you see auth failures, verify client scopes and base URL for your CrowdStrike cloud.
- Large environments: adjust `page_size` down if rate-limited, or up to reduce calls within limits.
- If vulnerabilities are `0`, check the run summary counters and verify that vulnerability `instance_id` values overlap with collected CrowdStrike device AIDs.
- When running on Windows, execute the Linux runner inside WSL.