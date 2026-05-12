# CrowdStrike → Zafran Starlark Integration

This repo contains a Starlark script that pulls CrowdStrike devices and vulnerabilities and maps them into Zafran's Assets (`InstanceData`) and Vulnerabilities models using the provided runner.

## Files
- `crowdstrike.star` — integration script (authentication, asset pull, vulnerability pull, mapping, flushing).
- `genericimport.proto` — reference types (sourced from Zafran public repo).

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
- `mock_mode` (optional): `true`/`false` toggle for offline mock collection (default `false`).

## Run Examples
```bash
# Linux (default open-vuln filter)
./starlark-runner-linux -script crowdstrike.star -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET,page_size=200" -output results.json

# macOS
./starlark-runner-mac -script crowdstrike.star -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET" -output results.json

# Linux with safety cap and retry tuning
./starlark-runner-linux -script crowdstrike.star -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET,page_size=200,max_pages=20,max_retries=3" -output results.json

# Linux with explicit vulnerability filter
./starlark-runner-linux -script crowdstrike.star -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET,vuln_filter=status:'open'" -output results.json

# Mock mode (offline validation)
./starlark-runner-linux -script crowdstrike.star -params "mock_mode=true"

# Save output to JSON
./starlark-runner-linux -script crowdstrike.star -output results.json -params "api_url=https://api.us-2.crowdstrike.com,api_key=YOUR_ID,api_secret=YOUR_SECRET" -output results.json
```

## Behavior
- Authenticates via OAuth2 `POST /oauth2/token`.
- Refreshes token and retries on HTTP `401`; retries `429` and `5xx` up to `max_retries`.
- Paginates devices (`/devices/queries/devices/v1` + `/devices/entities/devices/v2`).
  - Device details are requested with repeated `ids` query params (`ids=id1&ids=id2...`) and batched by 100 IDs/request.
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

## Notes
- Keep credentials secure; pass via runner params or env injection, not hard-coded.
- If you see auth failures, verify client scopes and base URL for your CrowdStrike cloud.
- Large environments: adjust `page_size` down if rate-limited, or up to reduce calls within limits.
- If vulnerabilities are `0`, check the run summary counters and verify that vulnerability `instance_id` values overlap with collected CrowdStrike device AIDs.
- When running on Windows, execute the Linux runner inside WSL.