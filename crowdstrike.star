load("http", "http")
load("json", "json")
load("log", "log")
load("time", "time")
load("zafran", "zafran")

# Defaults can be overridden via runner params
DEFAULT_API_URL = "https://api.us-2.crowdstrike.com"
DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_PAGES = 20
DEFAULT_MAX_RETRIES = 3
DEVICE_DETAILS_BATCH_SIZE = 100


def main(**kwargs):
    """
    CrowdStrike → Zafran integration.

    Runner params:
    - api_url: CrowdStrike base URL (default https://api.us-2.crowdstrike.com)
    - client_id/api_key: CrowdStrike client id
    - api_secret: CrowdStrike client secret
    - page_size: Page size for paginated endpoints (default 100)
    - max_pages: Max pages to process per endpoint (default 20)
    - max_retries: Max retry attempts for retryable HTTP statuses (default 3)
    - vuln_filter: Optional explicit FQL filter for vulnerabilities (default status:'open')
    """
    api_url = kwargs.get("api_url", DEFAULT_API_URL).rstrip("/")
    client_id = kwargs.get("client_id", kwargs.get("api_key", ""))
    client_secret = kwargs.get("api_secret", "")
    page_size = _to_int(kwargs.get("page_size", "100"), DEFAULT_PAGE_SIZE)
    max_pages = _to_int(kwargs.get("max_pages", "20"), DEFAULT_MAX_PAGES)
    max_retries = _to_int(kwargs.get("max_retries", "3"), DEFAULT_MAX_RETRIES)
    vuln_filter = kwargs.get("vuln_filter", "")
    mock_mode = _is_true(kwargs.get("mock_mode", "false"))

    pb = zafran.proto_file

    if not client_id or not client_secret:
        log.error("Missing client_id/api_key or api_secret")
        return None

    auth = {
        "api_url": api_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "token": "",
        "max_retries": max_retries,
    }

    if not mock_mode:
        token = get_bearer_token(api_url, client_id, client_secret)
        if not token:
            log.error("Authentication failed, aborting run")
            return None
        auth["token"] = token

    log.info(
        "Starting run: page_size=%d, max_pages=%d, max_retries=%d, mock_mode=%s"
        % (page_size, max_pages, max_retries, str(mock_mode))
    )

    if mock_mode:
        _collect_mock_data(pb)
        zafran.flush()
        log.info("Mock run complete")
        return None

    # Collect assets
    instance_ids = collect_devices(auth, page_size, max_pages, pb)

    # Collect vulnerabilities (after instances to keep associations intact)
    collect_vulnerabilities(auth, page_size, max_pages, vuln_filter, pb, instance_ids)

    # Final flush in case any data remains
    zafran.flush()
    log.info("Run complete")
    return None


def get_bearer_token(api_url, client_id, client_secret):
    """Client-credentials OAuth2 token exchange."""
    token_url = api_url + "/oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = "client_id=%s&client_secret=%s" % (client_id, client_secret)

    resp = http.post(token_url, headers=headers, body=payload)
    if resp["status_code"] != 201 and resp["status_code"] != 200:
        log.error("Token request failed: status=%d" % resp["status_code"])
        log.error("Body: %s" % resp.get("body", "")[:400])
        return ""

    data = json.decode(resp.get("body", "{}") or "{}")
    token = data.get("access_token", "")
    if not token:
        log.error("Token missing in response")
    return token


def collect_devices(auth, page_size, max_pages, pb):
    """Fetch device IDs, hydrate details, map to InstanceData, and flush per page."""
    offset = 0
    page = 1
    known_ids = {}
    last_offset_key = ""
    while True:
        if page > max_pages:
            log.warn("Reached max_pages while collecting devices: %d" % max_pages)
            break
        ids, next_offset = fetch_device_ids(auth, page_size, offset)
        if not ids:
            if page == 1:
                log.info("No devices returned")
            break

        log.info("Devices page %d: %d ids" % (page, len(ids)))
        details = fetch_device_details(auth, ids)
        if type(details) != "list":
            log.error("Device details not list, skipping page: %s" % str(type(details)))
            break
        for raw_device in details:
            instance = parse_device(raw_device, pb)
            if instance:
                zafran.collect_instance(instance)
                known_ids[instance.instance_id] = True

        log.info("Collected device page %d (%d devices)" % (page, len(details)))

        if next_offset:
            if str(next_offset) == last_offset_key:
                log.warn("Device cursor repeated, stopping pagination")
                break
            last_offset_key = str(next_offset)
            offset = next_offset
        elif len(ids) < page_size:
            break
        else:
            if type(offset) != "int":
                log.warn("Offset is non-int without next cursor, stopping device pagination")
                break
            offset += page_size
        page += 1
    return known_ids


def fetch_device_ids(auth, page_size, offset):
    url = "%s/devices/queries/devices/v1?limit=%d&offset=%s" % (auth["api_url"], page_size, str(offset))
    resp = _authed_get(auth, url)
    if not resp:
        return [], ""
    if type(resp) != "dict":
        return [], ""
    return _as_list(resp.get("resources", [])), _extract_next_cursor(resp)


def fetch_device_details(auth, ids):
    if not ids:
        return []
    details = []
    string_ids = _as_string_list(ids)
    for id_batch in _chunk_list(string_ids, DEVICE_DETAILS_BATCH_SIZE):
        ids_query = _build_ids_query(id_batch)
        url = "%s/devices/entities/devices/v2?%s" % (auth["api_url"], ids_query)
        resp = _authed_get(auth, url)
        if not resp:
            continue
        if type(resp) != "dict":
            continue
        for item in _as_list(resp.get("resources", [])):
            details.append(item)
    return details


def parse_device(raw, pb):
    aid = raw.get("device_id") or raw.get("aid") or ""
    if not aid:
        log.warn("Device missing AID/device_id, skipping")
        return None

    hostname = raw.get("hostname", "")
    platform = raw.get("platform_name", "")
    os_version = raw.get("os_version", "")
    mac = raw.get("mac_address", "")

    ips = []
    for key in ["local_ip", "external_ip"]:
        val = raw.get(key, "")
        if val:
            ips.append(val)
    # Deduplicate IPs
    seen = {}
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            unique_ips.append(ip)
            seen[ip] = True

    labels = []
    for label in _as_list(raw.get("tags", [])):
        if label:
            labels.append(pb.InstanceLabel(label=label))

    for group in _as_list(raw.get("groups", [])):
        if type(group) == "dict":
            name = group.get("name", "")
            if name:
                labels.append(pb.InstanceLabel(label=name))
        elif type(group) == "string" and group:
            labels.append(pb.InstanceLabel(label=group))

    key_value_tags = []
    for kv in [
        ("domain", raw.get("machine_domain", "")),
        ("site", raw.get("site_name", "")),
        ("platform", platform),
        ("product_type", raw.get("product_type_desc", "")),
    ]:
        if kv[1]:
            key_value_tags.append(pb.InstanceTagKeyValue(key=kv[0], value=kv[1]))

    identifiers = [
        pb.InstanceIdentifier(
            key=pb.IdentifierType.CROWDSTRIKE_AID,
            value=aid,
        )
    ]

    instance = pb.InstanceData(
        instance_id=aid,
        name=hostname or aid,
        operating_system=_compose_os(platform, os_version),
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=unique_ips,
            mac_addresses=[mac] if mac else [],
        ),
        identifiers=identifiers,
        labels=labels,
        key_value_tags=key_value_tags,
        instance_type=pb.InstanceType.INSTANCE_TYPE_MACHINE,
    )

    return instance


def collect_vulnerabilities(auth, page_size, max_pages, vuln_filter, pb, known_instance_ids):
    after_token = ""
    page = 1
    last_after_key = ""
    collected_count = 0
    skipped_missing_instance_id = 0
    skipped_unknown_instance = 0
    pages_processed = 0
    stop_reason = "completed"
    effective_filter = _resolve_vuln_filter(vuln_filter)
    log.info("Effective vulnerability filter: %s" % effective_filter)

    while True:
        if page > max_pages:
            stop_reason = "reached_max_pages"
            log.warn("Reached max_pages while collecting vulnerabilities: %d" % max_pages)
            break
        vulns, next_after = fetch_vulnerabilities(auth, page_size, after_token, effective_filter)
        if not vulns:
            if page == 1:
                stop_reason = "no_vulnerabilities_first_page"
                log.info("No vulnerabilities returned")
            else:
                stop_reason = "no_more_vulnerabilities"
            break

        pages_processed += 1
        log.info("Vuln page %d: %d items" % (page, len(vulns)))
        for raw_vuln in vulns:
            finding = parse_vulnerability(raw_vuln, pb)
            if finding:
                # Skip vulnerabilities without a mapped instance in this run.
                if not finding.instance_id:
                    skipped_missing_instance_id += 1
                    continue
                if not known_instance_ids.get(finding.instance_id, False):
                    skipped_unknown_instance += 1
                    continue
                zafran.collect_vulnerability(finding)
                collected_count += 1

        log.info("Collected vulnerability page %d (%d vulns)" % (page, len(vulns)))

        if next_after:
            if str(next_after) == last_after_key:
                stop_reason = "repeated_after_token"
                log.warn("Vulnerability cursor repeated, stopping pagination")
                break
            last_after_key = str(next_after)
            after_token = next_after
        elif len(vulns) < page_size:
            stop_reason = "short_page"
            break
        else:
            stop_reason = "missing_after_token"
            log.warn("No after token returned with full page, stopping vulnerability pagination")
            break
        page += 1

    log.info(
        "Vulnerability summary: pages_processed=%d, collected=%d, skipped_missing_instance_id=%d, skipped_unknown_instance=%d, stop_reason=%s"
        % (pages_processed, collected_count, skipped_missing_instance_id, skipped_unknown_instance, stop_reason)
    )


def fetch_vulnerabilities(auth, page_size, after_token, effective_filter):
    base = "%s/spotlight/combined/vulnerabilities/v1?limit=%d" % (
        auth["api_url"],
        page_size,
    )

    if after_token:
        base = base + "&after=" + _url_encode(after_token)

    if effective_filter:
        base = base + "&filter=" + _url_encode(effective_filter)

    resp = _authed_get(auth, base)
    if not resp:
        return [], ""
    if type(resp) != "dict":
        return [], ""
    return _as_list(resp.get("resources", [])), _extract_after_cursor(resp)


def parse_vulnerability(raw, pb):
    aid = raw.get("aid", "")
    cve_obj = raw.get("cve", {}) or {}
    cve = cve_obj.get("id") or raw.get("vulnerability_id", "")
    if not cve:
        log.warn("Vulnerability missing CVE/id, skipping")
        return None

    apps = _as_list(raw.get("apps", []))
    component = None
    if len(apps) > 0:
        app = apps[0]
        component = pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=app.get("product_name_normalized", "") or app.get("product_name_version", ""),
            vendor=app.get("vendor_normalized", ""),
            version=app.get("product_version", ""),
            display_name=app.get("product_name_version", ""),
        )
    else:
        component = pb.Component(
            type=pb.ComponentType.APPLICATION,
            product="unknown",
            vendor="unknown",
            version="",
        )

    cvss_list = []
    base_score = cve_obj.get("base_score") or raw.get("rating")
    vector = cve_obj.get("vector", "")
    parsed_score = _to_float_or_none(base_score)
    if parsed_score != None and vector:
        cvss_list.append(
            pb.CVSS(
                base_score=parsed_score,
                vector=vector,
                version="3.1",
                source="crowdstrike",
            )
        )

    remediation_obj = {}
    rem_entities = _as_list((raw.get("remediation", {}) or {}).get("entities", []))
    if len(rem_entities) > 0:
        remediation_obj = rem_entities[0]

    remediation = pb.Remediation(
        suggestion=remediation_obj.get("action", "") or remediation_obj.get("title", ""),
        source="CrowdStrike",
        fixed_in_version=remediation_obj.get("reference", ""),
    )

    severity = cve_obj.get("severity", "").lower()

    finding = pb.Vulnerability(
        instance_id=aid,
        cve=cve,
        in_runtime=True,
        component=component,
        remediation=remediation,
        CVSS=cvss_list,
        description=cve_obj.get("description", "") or raw.get("status", ""),
        severity=severity,
        scanner_id=raw.get("scanner_id", ""),
        external_url=_first_non_empty(
            remediation_obj.get("link", ""),
            remediation_obj.get("vendor_url", ""),
        ),
        references_url=_first_from_list(_as_list(cve_obj.get("references", []))),
    )

    return finding


# Helpers ------------------------------------------------------------------

def _authed_get(auth, url):
    max_retries = _to_int(auth.get("max_retries", DEFAULT_MAX_RETRIES), DEFAULT_MAX_RETRIES)
    attempt = 0
    while True:
        headers = {"Authorization": "Bearer " + auth["token"]}
        resp = http.get(url, headers=headers)
        status_code = resp["status_code"]

        if status_code == 401 and attempt < max_retries:
            log.info("401 received; refreshing bearer token and retrying")
            refreshed = get_bearer_token(auth["api_url"], auth["client_id"], auth["client_secret"])
            if not refreshed:
                log.error("Token refresh failed")
                return None
            auth["token"] = refreshed
            attempt += 1
            continue

        if _should_retry(status_code) and attempt < max_retries:
            attempt += 1
            _sleep_with_backoff(attempt)
            log.warn("Retrying HTTP request: status=%d attempt=%d/%d" % (status_code, attempt, max_retries))
            continue
        break

    if resp["status_code"] != 200:
        log.error("GET failed: url=%s status=%d" % (url, resp["status_code"]))
        log.error("Body: %s" % (resp.get("body", "")[:400]))
        return None
    body = resp.get("body", "")
    if not body:
        return {}
    decoded = json.decode(body)
    if type(decoded) == "string":
        log.error("Decoded body is string, expected object/array: %s" % decoded[:200])
        return {}
    return decoded


def _resolve_vuln_filter(vuln_filter):
    """
    Spotlight combined endpoint requires a filter.
    Use explicit vuln_filter when provided, otherwise default to open vulnerabilities.
    """
    if type(vuln_filter) == "string" and vuln_filter:
        return vuln_filter
    return "status:'open'"


def _to_int(value, default):
    if type(value) == "int":
        return value
    if type(value) != "string":
        return default
    s = value.strip()
    if s == "":
        return default
    normalized = s
    normalized = normalized.replace("0", "")
    normalized = normalized.replace("1", "")
    normalized = normalized.replace("2", "")
    normalized = normalized.replace("3", "")
    normalized = normalized.replace("4", "")
    normalized = normalized.replace("5", "")
    normalized = normalized.replace("6", "")
    normalized = normalized.replace("7", "")
    normalized = normalized.replace("8", "")
    normalized = normalized.replace("9", "")
    if normalized != "":
        return default
    return int(s)


def _to_float_or_none(value):
    if type(value) == "float":
        return value
    if type(value) == "int":
        return float(value)
    if type(value) != "string":
        return None
    s = value.strip()
    if s == "":
        return None
    normalized = s
    normalized = normalized.replace(".", "")
    normalized = normalized.replace("0", "")
    normalized = normalized.replace("1", "")
    normalized = normalized.replace("2", "")
    normalized = normalized.replace("3", "")
    normalized = normalized.replace("4", "")
    normalized = normalized.replace("5", "")
    normalized = normalized.replace("6", "")
    normalized = normalized.replace("7", "")
    normalized = normalized.replace("8", "")
    normalized = normalized.replace("9", "")
    if normalized != "":
        return None
    return float(s)


def _is_true(value):
    if type(value) == "bool":
        return value
    s = str(value).lower()
    return s == "true" or s == "1" or s == "yes"


def _as_list(value):
    """Return value if list, else empty list."""
    if type(value) == "list":
        return value
    return []


def _as_string_list(values):
    out = []
    for value in values:
        if type(value) == "string":
            out.append(value)
        else:
            out.append(str(value))
    return out


def _chunk_list(values, chunk_size):
    chunks = []
    if chunk_size <= 0:
        return chunks
    i = 0
    size = len(values)
    while i < size:
        end = i + chunk_size
        if end > size:
            end = size
        chunks.append(values[i:end])
        i = end
    return chunks


def _extract_next_cursor(resp):
    meta = resp.get("meta", {})
    if type(meta) != "dict":
        return ""
    pagination = meta.get("pagination", {})
    if type(pagination) != "dict":
        return ""
    next_value = pagination.get("next", "")
    if next_value == None:
        return ""
    if type(next_value) == "int":
        return next_value
    if type(next_value) == "string":
        return next_value
    return ""


def _extract_after_cursor(resp):
    meta = resp.get("meta", {})
    if type(meta) != "dict":
        return ""
    pagination = meta.get("pagination", {})
    if type(pagination) != "dict":
        return ""
    after_value = pagination.get("after", "")
    if after_value == None:
        return ""
    if type(after_value) == "string":
        return after_value
    if type(after_value) == "int":
        return str(after_value)
    return ""


def _build_ids_query(ids):
    if not ids:
        return ""
    parts = []
    for aid in ids:
        parts.append("ids=" + aid)
    return "&".join(parts)


def _url_encode(value):
    # Minimal encoder for FQL query parameter composition.
    encoded = value
    encoded = encoded.replace("%", "%25")
    encoded = encoded.replace(" ", "%20")
    encoded = encoded.replace(">", "%3E")
    encoded = encoded.replace(":", "%3A")
    encoded = encoded.replace("+", "%2B")
    encoded = encoded.replace("'", "%27")
    return encoded


def _should_retry(status_code):
    return status_code == 429 or status_code >= 500


def _sleep_with_backoff(attempt):
    # Exponential-style bounded backoff: 1s, 2s, 4s, then capped at 5s.
    delay_seconds = 1
    if attempt == 2:
        delay_seconds = 2
    elif attempt >= 3:
        delay_seconds = 4
    if delay_seconds > 5:
        delay_seconds = 5
    time.sleep(delay_seconds)


def _compose_os(platform, version):
    if platform and version:
        return "%s %s" % (platform, version)
    return platform or version or ""


def _first_non_empty(a, b):
    if a:
        return a
    if b:
        return b
    return ""


def _first_from_list(arr):
    if type(arr) != "list":
        return ""
    if not arr:
        return ""
    return arr[0]


def _collect_mock_data(pb):
    instance = pb.InstanceData(
        instance_id="mock-aid-1",
        name="mock-host-1",
        operating_system="Windows 11",
        identifiers=[pb.InstanceIdentifier(key=pb.IdentifierType.CROWDSTRIKE_AID, value="mock-aid-1")],
        labels=[pb.InstanceLabel(label="mock")],
        key_value_tags=[pb.InstanceTagKeyValue(key="source", value="crowdstrike-mock")],
        instance_type=pb.InstanceType.INSTANCE_TYPE_MACHINE,
    )
    zafran.collect_instance(instance)

    vuln = pb.Vulnerability(
        instance_id="mock-aid-1",
        cve="CVE-2024-0001",
        in_runtime=True,
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product="mock-product",
            vendor="mock-vendor",
            version="1.0.0",
        ),
        remediation=pb.Remediation(
            suggestion="Update to 1.0.1",
            source="CrowdStrike",
        ),
        severity="medium",
        description="Mock vulnerability for offline testing",
    )
    zafran.collect_vulnerability(vuln)
