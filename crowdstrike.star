# CrowdStrike Starlark integration script
# Collects device assets and Spotlight vulnerabilities from the CrowdStrike Falcon API
# and maps them to Zafran proto types.
#
# Structure:
#   - main: Entry point that orchestrates the integration
#   - get_bearer_token: Gets a bearer token from CrowdStrike OAuth2 endpoint
#   - collect_devices: Paginates device IDs, hydrates details, collects instances
#   - fetch_device_ids: Fetches a page of device AIDs
#   - fetch_device_details: Hydrates device details in batches
#   - parse_device: Transforms raw device data into InstanceData proto
#   - collect_vulnerabilities: Paginates Spotlight vulns, resolves remediations, collects findings
#   - fetch_vulnerabilities: Fetches a page of combined vulnerabilities
#   - fetch_remediation_actions: Fetches remediation action text by ID
#   - parse_vulnerability: Transforms raw vulnerability data into Vulnerability proto
#
# Data Collection:
#   - Use zafran.collect_instance() and zafran.collect_vulnerability() to collect data
#   - Use zafran.flush() to send collected data mid-execution (useful for large datasets)
#   - Any unflushed data is automatically sent when the script completes

load("http", "http")
load("json", "json")
load("log", "log")
load("time", "time")
load("zafran", "zafran")

# Defaults can be overridden via runner params
DEFAULT_API_URL = "https://api.us-2.crowdstrike.com"
DEFAULT_PAGE_SIZE = 20
DEFAULT_MAX_PAGES = 3
DEFAULT_MAX_RETRIES = 3
DEFAULT_DEVICE_DETAILS_BATCH_SIZE = 20
REMEDIATION_DETAILS_BATCH_SIZE = 20
DEFAULT_VULN_FILTER = "status:'open'"
DEFAULT_REMEDIATION_GUIDANCE = "No remediation guidance provided by CrowdStrike"
CROWDSTRIKE_SOURCE = "CrowdStrike"
LOG_BODY_PREVIEW_LEN = 400
LOG_PREFIX_STEP = "❇️ "
LOG_PREFIX_SUCCESS = "✅ "
LOG_PREFIX_WARN = "⚠️ "
LOG_PREFIX_ERROR = "❌ "
LOG_PREFIX_DEVICE = "💻 "
LOG_PREFIX_VULN = "🚨 "
LOG_PREFIX_MOCK = "🧪 "
LOG_PREFIX_SUMMARY = "🐞 "
LOG_PREFIX_REMEDIATION = "🔫 "

STOP_REASON_COMPLETED = "completed"
STOP_REASON_REACHED_MAX_PAGES = "reached_max_pages"
STOP_REASON_SHORT_PAGE = "short_page"
STOP_REASON_NO_DEVICES_FIRST_PAGE = "no_devices_first_page"
STOP_REASON_NO_MORE_DEVICES = "no_more_devices"
STOP_REASON_REPEATED_NEXT_OFFSET = "repeated_next_offset"
STOP_REASON_NON_INT_OFFSET_WITHOUT_CURSOR = "non_int_offset_without_cursor"
STOP_REASON_NO_VULNERABILITIES_FIRST_PAGE = "no_vulnerabilities_first_page"
STOP_REASON_NO_MORE_VULNERABILITIES = "no_more_vulnerabilities"
STOP_REASON_REPEATED_AFTER_TOKEN = "repeated_after_token"
STOP_REASON_MISSING_AFTER_TOKEN = "missing_after_token"

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
    - device_details_batch_size: Number of device IDs per details hydration request (default 100)
    - vuln_filter: Optional explicit FQL filter for vulnerabilities (default status:'open')
    """
    log.info(LOG_PREFIX_STEP + "Step 0: Parsing configuration parameters...")
    api_url = kwargs.get("api_url", DEFAULT_API_URL).rstrip("/")
    client_id = kwargs.get("client_id", kwargs.get("api_key", ""))
    client_secret = kwargs.get("api_secret", "")
    page_size = _to_int(kwargs.get("page_size", str(DEFAULT_PAGE_SIZE)), DEFAULT_PAGE_SIZE)
    max_pages = _to_int(kwargs.get("max_pages", str(DEFAULT_MAX_PAGES)), DEFAULT_MAX_PAGES)
    max_retries = _to_int(kwargs.get("max_retries", str(DEFAULT_MAX_RETRIES)), DEFAULT_MAX_RETRIES)
    device_details_batch_size = _to_int(
        kwargs.get("device_details_batch_size", str(DEFAULT_DEVICE_DETAILS_BATCH_SIZE)),
        DEFAULT_DEVICE_DETAILS_BATCH_SIZE,
    )
    vuln_filter = kwargs.get("vuln_filter", "")
    mock_mode = _is_true(kwargs.get("mock_mode", "false"))

    pb = zafran.proto_file
    log.info("Starting integration with API: %s" % api_url)

    if mock_mode:
        log.info(
            LOG_PREFIX_MOCK + ("Starting mock run: page_size=%d, max_pages=%d, max_retries=%d"
            % (page_size, max_pages, max_retries))
        )
        _collect_mock_data(pb)
        zafran.flush()
        log.info(LOG_PREFIX_MOCK + "Mock run complete")
        return None

    log.info(LOG_PREFIX_STEP + "Step 1: Validating the input parameters...")
    if page_size <= 0:
        log.warn(LOG_PREFIX_WARN + ("Invalid page_size=%d; using default=%d" % (page_size, DEFAULT_PAGE_SIZE)))
        page_size = DEFAULT_PAGE_SIZE
    if max_pages <= 0:
        log.warn(LOG_PREFIX_WARN + ("Invalid max_pages=%d; using default=%d" % (max_pages, DEFAULT_MAX_PAGES)))
        max_pages = DEFAULT_MAX_PAGES
    if max_retries <= 0:
        log.warn(LOG_PREFIX_WARN + ("Invalid max_retries=%d; using default=%d" % (max_retries, DEFAULT_MAX_RETRIES)))
        max_retries = DEFAULT_MAX_RETRIES
    if not client_id or not client_secret:
        log.error(LOG_PREFIX_ERROR + "Missing client_id/api_key or api_secret")
        return None
    if device_details_batch_size <= 0:
        log.warn(
            LOG_PREFIX_WARN + ("Invalid device_details_batch_size=%d; using default=%d"
            % (device_details_batch_size, DEFAULT_DEVICE_DETAILS_BATCH_SIZE))
        )
        device_details_batch_size = DEFAULT_DEVICE_DETAILS_BATCH_SIZE

    log.info(LOG_PREFIX_STEP + "Step 2: Authenticating via OAuth2...")
    auth = {
        "api_url": api_url,
        "client_id": client_id,
        "client_secret": client_secret,
        "token": "",
        "max_retries": max_retries,
    }
    token = get_bearer_token(api_url, client_id, client_secret)
    if not token:
        log.error(LOG_PREFIX_ERROR + "Authentication failed, aborting run")
        return None
    auth["token"] = token

    log.info(
        "Starting run: page_size=%d, max_pages=%d, max_retries=%d, device_details_batch_size=%d"
        % (page_size, max_pages, max_retries, device_details_batch_size)
    )

    log.info(LOG_PREFIX_STEP + "Step 3: Collecting device assets...")
    instance_ids = collect_devices(auth, page_size, max_pages, device_details_batch_size, pb)

    log.info(LOG_PREFIX_STEP + "Step 4: Collecting vulnerabilities...")
    collect_vulnerabilities(auth, page_size, max_pages, vuln_filter, pb, instance_ids)

    log.info(LOG_PREFIX_STEP + "Step 5: Flushing remaining collected data...")
    zafran.flush()

    log.info(LOG_PREFIX_SUCCESS + "Data extracted successfully from CrowdStrike and collected into Zafran")
    return None


def get_bearer_token(api_url, client_id, client_secret):
    """
    Client-credentials OAuth2 token exchange.

    This helper performs a single OAuth token request. Retry/backoff behavior
    is intentionally implemented in `_authed_get` for authenticated GET calls.

    Args:
        api_url: CrowdStrike base URL
        client_id: OAuth client ID
        client_secret: OAuth client secret

    Returns:
        Bearer token string, or None if the exchange failed
    """
    token_url = api_url + "/oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = "client_id=%s&client_secret=%s" % (
        _form_url_encode(client_id),
        _form_url_encode(client_secret),
    )

    # POST to OAuth2 token endpoint
    resp = http.post(token_url, headers=headers, body=payload)
    if resp["status_code"] != 201 and resp["status_code"] != 200:
        log.error(LOG_PREFIX_ERROR + ("Token request failed: status=%d" % resp["status_code"]))
        log.error(LOG_PREFIX_ERROR + ("Body: %s" % resp.get("body", "")[:LOG_BODY_PREVIEW_LEN]))
        return None

    # Extract access_token from response
    data = json.decode(resp.get("body", "{}") or "{}")
    token = data.get("access_token", "")
    if not token:
        log.error(LOG_PREFIX_ERROR + "Token missing in response")
        return None
    log.info(LOG_PREFIX_SUCCESS + "Successfully obtained bearer token")
    return token


def collect_devices(auth, page_size, max_pages, device_details_batch_size, pb):
    """
    Fetch device IDs, hydrate details, map to InstanceData, and collect per page.

    Args:
        auth: Auth dict with api_url, client_id, client_secret, token, max_retries
        page_size: Number of device IDs to request per page
        max_pages: Maximum number of pages to process before stopping
        device_details_batch_size: Number of IDs per device details hydration request
        pb: Proto types from zafran.proto_file

    Returns:
        Dict of known instance IDs (AID -> True) collected during this run
    """
    offset = 0
    page = 1
    known_ids = {}
    last_offset_key = ""
    stats = _new_device_collection_stats()
    while True:
        if page > max_pages:
            stats["stop_reason"] = STOP_REASON_REACHED_MAX_PAGES
            log.warn(LOG_PREFIX_WARN + ("Reached max_pages while collecting devices: %d" % max_pages))
            break

        ids, next_offset = fetch_device_ids(auth, page_size, offset)
        if not ids:
            if page == 1:
                stats["stop_reason"] = STOP_REASON_NO_DEVICES_FIRST_PAGE
                log.info(LOG_PREFIX_DEVICE + "No devices returned")
            else:
                stats["stop_reason"] = STOP_REASON_NO_MORE_DEVICES
            break

        stats["pages_processed"] += 1
        stats["ids_requested"] += len(ids)
        log.info(LOG_PREFIX_DEVICE + ("Devices page %d: %d ids" % (page, len(ids))))
        details_returned, instances_collected, instances_skipped = _collect_device_page_instances(
            auth,
            ids,
            pb,
            device_details_batch_size,
            known_ids,
        )
        stats["details_returned"] += details_returned
        stats["instances_collected"] += instances_collected
        stats["instances_skipped"] += instances_skipped

        log.info(
            LOG_PREFIX_DEVICE + ("Collected device page %d (details_returned=%d, instances_collected=%d, instances_skipped=%d)"
            % (page, details_returned, instances_collected, instances_skipped))
        )

        should_continue, new_offset, new_last_offset_key, stop_reason = _advance_device_pagination(
            next_offset,
            last_offset_key,
            len(ids),
            page_size,
            offset,
        )
        if not should_continue:
            stats["stop_reason"] = stop_reason
            if stop_reason == STOP_REASON_REPEATED_NEXT_OFFSET:
                log.warn(LOG_PREFIX_WARN + "Device cursor repeated, stopping pagination")
            elif stop_reason == STOP_REASON_NON_INT_OFFSET_WITHOUT_CURSOR:
                log.warn(LOG_PREFIX_WARN + "Offset is non-int without next cursor, stopping device pagination")
            break

        offset = new_offset
        last_offset_key = new_last_offset_key
        page += 1

    _log_device_collection_summary(stats, known_ids)
    log.info(LOG_PREFIX_DEVICE + ("Collected %d unique device instances" % len(known_ids)))
    return known_ids


def _new_device_collection_stats():
    return {
        "pages_processed": 0,
        "ids_requested": 0,
        "details_returned": 0,
        "instances_collected": 0,
        "instances_skipped": 0,
        "stop_reason": STOP_REASON_COMPLETED,
    }


def _collect_device_page_instances(auth, ids, pb, device_details_batch_size, known_ids):
    details = fetch_device_details(auth, ids, device_details_batch_size)
    details_returned = len(details)
    instances_collected = 0
    instances_skipped = 0

    for raw_device in details:
        instance = parse_device(raw_device, pb)
        if instance:
            zafran.collect_instance(instance)
            known_ids[instance.instance_id] = True
            instances_collected += 1
        else:
            instances_skipped += 1

    return details_returned, instances_collected, instances_skipped


def _advance_device_pagination(next_offset, last_offset_key, ids_count, page_size, current_offset):
    if next_offset:
        next_offset_key = str(next_offset)
        if next_offset_key == last_offset_key:
            return False, current_offset, last_offset_key, STOP_REASON_REPEATED_NEXT_OFFSET
        return True, next_offset, next_offset_key, ""
    if ids_count < page_size:
        return False, current_offset, last_offset_key, STOP_REASON_SHORT_PAGE
    if type(current_offset) != "int":
        return False, current_offset, last_offset_key, STOP_REASON_NON_INT_OFFSET_WITHOUT_CURSOR
    return True, current_offset + page_size, last_offset_key, ""


def _log_device_collection_summary(stats, known_ids):
    log.info(
        LOG_PREFIX_DEVICE + ("Device summary: pages_processed=%d, ids_requested=%d, details_returned=%d, instances_collected=%d, instances_skipped=%d, unique_instances=%d, stop_reason=%s"
        % (
            stats["pages_processed"],
            stats["ids_requested"],
            stats["details_returned"],
            stats["instances_collected"],
            stats["instances_skipped"],
            len(known_ids),
            stats["stop_reason"],
        ))
    )


def fetch_device_ids(auth, page_size, offset):
    """
    Fetch a page of device AIDs from the CrowdStrike devices query endpoint.

    Args:
        auth: Auth dict with api_url, token, and retry settings
        page_size: Number of device IDs to request
        offset: Pagination offset (int or cursor string)

    Returns:
        Tuple of (list of device ID strings, next pagination cursor)
    """
    url = "%s/devices/queries/devices/v1?limit=%d&offset=%s" % (auth["api_url"], page_size, str(offset))
    resp = _authed_get(auth, url)
    if not resp:
        return [], ""
    if type(resp) != "dict":
        return [], ""
    return _as_list(resp.get("resources", [])), _extract_next_cursor(resp)


def fetch_device_details(auth, ids, batch_size):
    """
    Hydrate full device details for a list of device AIDs in batches.

    Args:
        auth: Auth dict with api_url, token, and retry settings
        ids: List of device AID strings to look up
        batch_size: Number of IDs per request to device details endpoint

    Returns:
        List of raw device detail dicts from the API
    """
    if not ids:
        return []
    details = []
    string_ids = _as_string_list(ids)
    for id_batch in _chunk_list(string_ids, batch_size):
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
    """
    Transform a raw CrowdStrike device dict into an InstanceData proto message.

    Args:
        raw: Raw device dict from the CrowdStrike devices API
        pb: Proto types from zafran.proto_file

    Returns:
        InstanceData proto message, or None if the device is missing an AID
    """
    aid = raw.get("device_id") or raw.get("aid") or ""
    if not aid:
        log.warn(LOG_PREFIX_WARN + "Device missing AID/device_id, skipping")
        return None

    # Extract basic device attributes
    hostname = raw.get("hostname", "")
    platform = raw.get("platform_name", "")
    os_version = raw.get("os_version", "")
    mac = raw.get("mac_address", "")

    # Collect and deduplicate IP addresses
    ips = []
    for key in ["local_ip", "external_ip"]:
        val = raw.get(key, "")
        if val:
            ips.append(val)
    seen = {}
    unique_ips = []
    for ip in ips:
        if ip not in seen:
            unique_ips.append(ip)
            seen[ip] = True

    # Build labels from tags and groups
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

    # Build key-value tags from domain, site, platform, product type
    key_value_tags = []
    for kv in [
        ("domain", raw.get("machine_domain", "")),
        ("site", raw.get("site_name", "")),
        ("platform", platform),
        ("product_type", raw.get("product_type_desc", "")),
    ]:
        if kv[1]:
            key_value_tags.append(pb.InstanceTagKeyValue(key=kv[0], value=kv[1]))

    # Build CrowdStrike AID identifier
    identifiers = [
        pb.InstanceIdentifier(
            key=pb.IdentifierType.CROWDSTRIKE_AID,
            value=aid,
        )
    ]

    # Assemble and return InstanceData protobuf
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
    """
    Paginate Spotlight vulnerabilities, resolve remediation actions, and collect findings.

    Vulnerabilities are filtered to only include those whose instance_id matches
    a device collected in the current run. Remediation actions are fetched from
    the remediations API and cached across pages.

    Args:
        auth: Auth dict with api_url, token, and retry settings
        page_size: Number of vulnerabilities to request per page
        max_pages: Maximum number of pages to process before stopping
        vuln_filter: Optional explicit FQL filter string (defaults to status:'open')
        pb: Proto types from zafran.proto_file
        known_instance_ids: Dict of AID -> True for devices collected in this run
    """
    traversal = _new_vuln_traversal_state()
    stats = _new_vulnerability_stats()
    remediation_cache = {}
    remediation_ids_seen = {}

    # Resolve effective FQL filter for Spotlight API
    effective_filter = _resolve_vuln_filter(vuln_filter)
    log.info(LOG_PREFIX_VULN + ("Effective vulnerability filter: %s" % effective_filter))

    while True:
        if traversal["page"] > max_pages:
            _set_vuln_stop_reason(stats, STOP_REASON_REACHED_MAX_PAGES)
            log.warn(LOG_PREFIX_WARN + ("Reached max_pages while collecting vulnerabilities: %d" % max_pages))
            break

        vulns, next_after = fetch_vulnerabilities(auth, page_size, traversal["after_token"], effective_filter)
        if not vulns:
            if traversal["page"] == 1:
                _set_vuln_stop_reason(stats, STOP_REASON_NO_VULNERABILITIES_FIRST_PAGE)
                log.info("No vulnerabilities returned")
            else:
                _set_vuln_stop_reason(stats, STOP_REASON_NO_MORE_VULNERABILITIES)
            break

        stats["pages_processed"] += 1
        log.info(LOG_PREFIX_VULN + ("Vuln page %d: %d items" % (traversal["page"], len(vulns))))

        # Resolve remediation actions for this page (with run-level caching)
        remediation_stats = _hydrate_remediation_cache_for_page(
            auth,
            vulns,
            remediation_cache,
            remediation_ids_seen,
        )

        # Parse each vulnerability, filter by known instances, and collect
        page_collection_stats = _collect_vulnerabilities_for_page(
            vulns,
            pb,
            remediation_cache,
            known_instance_ids,
        )
        _apply_page_results_to_stats(stats, remediation_stats, page_collection_stats)
        log.info(LOG_PREFIX_VULN + ("Collected vulnerability page %d (%d vulns)" % (traversal["page"], len(vulns))))

        # Advance pagination cursor or stop (see helper docstring for stop reasons).
        should_continue, stop_reason = _advance_vuln_state(
            traversal,
            next_after,
            len(vulns),
            page_size,
        )
        if not should_continue:
            _set_vuln_stop_reason(stats, stop_reason)
            if stop_reason == STOP_REASON_REPEATED_AFTER_TOKEN:
                log.warn(LOG_PREFIX_WARN + "Vulnerability cursor repeated, stopping pagination")
            elif stop_reason == STOP_REASON_MISSING_AFTER_TOKEN:
                log.warn(LOG_PREFIX_WARN + "No after token returned with full page, stopping vulnerability pagination")
            break

    _log_vulnerability_summary(stats, remediation_ids_seen)


def _new_vuln_traversal_state():
    return {
        "page": 1,
        "after_token": "",
        "last_after_key": "",
    }


def _set_vuln_stop_reason(stats, stop_reason):
    stats["stop_reason"] = stop_reason


def _new_vulnerability_stats():
    return {
        "pages_processed": 0,
        "collected_count": 0,
        "skipped_missing_instance_id": 0,
        "skipped_unknown_instance": 0,
        "remediation_lookup_requests": 0,
        "remediation_cache_hits": 0,
        "remediation_actions_resolved": 0,
        "stop_reason": STOP_REASON_COMPLETED,
    }


def _apply_page_results_to_stats(stats, remediation_stats, page_collection_stats):
    """Merge per-page remediation and collection map results into run-level stats."""
    stats["remediation_cache_hits"] += remediation_stats.get("cache_hits", 0)
    stats["remediation_lookup_requests"] += remediation_stats.get("lookup_requests", 0)
    stats["remediation_actions_resolved"] += remediation_stats.get("actions_resolved", 0)

    stats["collected_count"] += page_collection_stats.get("collected_count", 0)
    stats["skipped_missing_instance_id"] += page_collection_stats.get("skipped_missing_instance_id", 0)
    stats["skipped_unknown_instance"] += page_collection_stats.get("skipped_unknown_instance", 0)


def _hydrate_remediation_cache_for_page(auth, vulns, remediation_cache, remediation_ids_seen):
    """
    Resolve remediation actions for one vulnerability page and update cache state.

    Side effects:
      - updates `remediation_ids_seen` with page remediation IDs
      - updates `remediation_cache` with fetched remediation actions

    Returns:
      Map with keys:
      - cache_hits
      - lookup_requests
      - actions_resolved
    """
    page_remediation_ids = _collect_page_remediation_ids(vulns)
    missing_ids = []
    cache_hits = 0

    for rid in page_remediation_ids:
        remediation_ids_seen[rid] = True
        if rid in remediation_cache:
            cache_hits += 1
        else:
            missing_ids.append(rid)

    lookup_requests = len(missing_ids)
    actions_resolved = 0
    if lookup_requests > 0:
        fetched_actions = fetch_remediation_actions(auth, missing_ids)
        for rid in missing_ids:
            action = fetched_actions.get(rid, "")
            remediation_cache[rid] = action
            if action:
                actions_resolved += 1

    return {
        "cache_hits": cache_hits,
        "lookup_requests": lookup_requests,
        "actions_resolved": actions_resolved,
    }


def _collect_vulnerabilities_for_page(vulns, pb, remediation_cache, known_instance_ids):
    """
    Parse and collect one page of vulnerabilities.

    Returns:
      Map with keys:
      - collected_count
      - skipped_missing_instance_id
      - skipped_unknown_instance
    """
    collected_count = 0
    skipped_missing_instance_id = 0
    skipped_unknown_instance = 0

    for raw_vuln in vulns:
        finding = parse_vulnerability(raw_vuln, pb, remediation_cache)
        if not finding:
            continue
        if not finding.instance_id:
            skipped_missing_instance_id += 1
            continue
        if not known_instance_ids.get(finding.instance_id, False):
            skipped_unknown_instance += 1
            continue

        zafran.collect_vulnerability(finding)
        collected_count += 1

    return {
        "collected_count": collected_count,
        "skipped_missing_instance_id": skipped_missing_instance_id,
        "skipped_unknown_instance": skipped_unknown_instance
    }


def _advance_vuln_state(traversal, next_after, page_count, page_size):
    """
    Advance traversal state for vulnerability pagination.

    Returns:
      Tuple of (should_continue, stop_reason)
    """
    should_continue, new_after_token, new_last_after_key, stop_reason = _advance_vulnerability_pagination(
        next_after,
        traversal["last_after_key"],
        page_count,
        page_size,
    )
    if not should_continue:
        return False, stop_reason

    traversal["after_token"] = new_after_token
    traversal["last_after_key"] = new_last_after_key
    traversal["page"] += 1
    return True, ""


def _advance_vulnerability_pagination(next_after, last_after_key, page_count, page_size):
    """
    Compute next pagination state for vulnerability traversal.

    Stop reasons:
      - repeated_after_token: service returned same cursor again
      - short_page: current page has fewer records than requested
      - missing_after_token: full page but no continuation token
    """
    if next_after:
        if str(next_after) == last_after_key:
            return False, "", last_after_key, STOP_REASON_REPEATED_AFTER_TOKEN
        return True, next_after, str(next_after), ""
    if page_count < page_size:
        return False, "", last_after_key, STOP_REASON_SHORT_PAGE
    return False, "", last_after_key, STOP_REASON_MISSING_AFTER_TOKEN


def _log_vulnerability_summary(stats, remediation_ids_seen):
    log.info(
        LOG_PREFIX_SUMMARY + ("Vulnerability summary: pages_processed=%d, collected=%d, skipped_missing_instance_id=%d, skipped_unknown_instance=%d, stop_reason=%s"
        % (
            stats["pages_processed"],
            stats["collected_count"],
            stats["skipped_missing_instance_id"],
            stats["skipped_unknown_instance"],
            stats["stop_reason"],
        ))
    )
    log.info(
        LOG_PREFIX_REMEDIATION + ("Remediation summary: ids_discovered=%d, lookup_requests=%d, cache_hits=%d, actions_resolved=%d"
        % (
            len(remediation_ids_seen),
            stats["remediation_lookup_requests"],
            stats["remediation_cache_hits"],
            stats["remediation_actions_resolved"],
        ))
    )


def fetch_vulnerabilities(auth, page_size, after_token, effective_filter):
    """
    Fetch a page of combined vulnerabilities from the CrowdStrike Spotlight API.

    Args:
        auth: Auth dict with api_url, token, and retry settings
        page_size: Number of vulnerabilities to request
        after_token: Cursor token for fetching the next page (empty string for first page)
        effective_filter: FQL filter string for the Spotlight endpoint

    Returns:
        Tuple of (list of raw vulnerability dicts, next after cursor string)
    """
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


def fetch_remediation_actions(auth, remediation_ids):
    """
    Fetch remediation action text for a list of remediation IDs in batches.

    Args:
        auth: Auth dict with api_url, token, and retry settings
        remediation_ids: List of remediation ID strings to look up

    Returns:
        Dict mapping remediation ID -> action text for IDs that resolved
    """
    action_by_id = {}
    if len(remediation_ids) == 0:
        return action_by_id

    for id_batch in _chunk_list(remediation_ids, REMEDIATION_DETAILS_BATCH_SIZE):
        query = _build_ids_query(id_batch)
        url = "%s/spotlight/entities/remediations/v2?%s" % (auth["api_url"], query)
        resp = _authed_get(auth, url)
        if not resp or type(resp) != "dict":
            continue

        resources = _as_list(resp.get("resources", []))
        for item in resources:
            if type(item) != "dict":
                continue
            remediation_id = item.get("id", "")
            action = item.get("action", "")
            if type(remediation_id) == "string" and remediation_id and type(action) == "string" and action:
                action_by_id[remediation_id] = action

    return action_by_id


def parse_vulnerability(raw, pb, remediation_cache):
    """
    Transform a raw CrowdStrike Spotlight vulnerability dict into a Vulnerability proto.

    Args:
        raw: Raw vulnerability dict from the Spotlight combined API
        pb: Proto types from zafran.proto_file
        remediation_cache: Dict of remediation ID -> action text for cached lookups

    Returns:
        Tuple of (Vulnerability proto, bool indicating if cached remediation action was used),
        or (None, False) if the vulnerability is missing a CVE identifier
    """
    # Extract and validate CVE identifier
    aid = raw.get("aid", "")
    cve_obj = raw.get("cve", {}) or {}
    cve = cve_obj.get("id") or raw.get("vulnerability_id", "")
    if not cve:
        log.warn(LOG_PREFIX_WARN + "Vulnerability missing CVE/id, skipping")
        return None, False

    # Build affected component from apps data
    apps = _as_list(raw.get("apps", []))
    component = None
    if len(apps) > 0 and type(apps[0]) == "dict":
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

    # Build CVSS scoring data
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
                source=CROWDSTRIKE_SOURCE,
            )
        )

    primary_remediation_id = _resolve_primary_remediation_id(raw)
    remediation_action = _resolve_action_from_cache(primary_remediation_id, remediation_cache)

    # Build Remediation protobuf with suggestion and fixed version
    remediation = pb.Remediation(
        suggestion=remediation_action,
        source=CROWDSTRIKE_SOURCE
    )

    severity = _as_string(cve_obj.get("severity", "")).lower()

    # Assemble and return Vulnerability protobuf
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
        references_url=_first_from_list(_as_list(cve_obj.get("references", []))),
    )

    return finding


# Helpers ------------------------------------------------------------------

def _authed_get(auth, url):
    """
    Perform an authenticated GET request with automatic token refresh and retry logic.

    Handles 401 responses by refreshing the bearer token, and retries on 429/5xx
    status codes with exponential backoff.
    This retry policy applies only to authenticated GET requests. The initial
    OAuth token POST in `get_bearer_token` does not use this helper.

    Args:
        auth: Auth dict with api_url, client_id, client_secret, token, max_retries
        url: Fully-qualified URL to GET

    Returns:
        Decoded JSON response as a dict, empty dict if body is empty, or None on failure
    """
    max_retries = _to_int(auth.get("max_retries", DEFAULT_MAX_RETRIES), DEFAULT_MAX_RETRIES)
    attempt = 0
    while True:
        headers = {"Authorization": "Bearer " + auth["token"]}
        resp = http.get(url, headers=headers)
        status_code = resp["status_code"]

        if status_code == 401 and attempt < max_retries:
            log.info(LOG_PREFIX_ERROR + "401 received; refreshing bearer token and retrying")
            refreshed = get_bearer_token(auth["api_url"], auth["client_id"], auth["client_secret"])
            if not refreshed:
                log.error(LOG_PREFIX_ERROR + "Token refresh failed")
                return None
            auth["token"] = refreshed
            attempt += 1
            continue

        # Handle retryable status codes (429, 5xx) with backoff
        if _should_retry(status_code) and attempt < max_retries:
            attempt += 1
            _sleep_with_backoff(attempt)
            log.warn(LOG_PREFIX_WARN + ("Retrying HTTP request: status=%d attempt=%d/%d" % (status_code, attempt, max_retries)))
            continue
        break

    if resp["status_code"] != 200:
        log.error(LOG_PREFIX_ERROR + ("GET failed: url=%s status=%d" % (url, resp["status_code"])))
        log.error(LOG_PREFIX_ERROR + ("Body: %s" % (resp.get("body", "")[:LOG_BODY_PREVIEW_LEN])))
        return None

    body = resp.get("body", "")
    if not body:
        return {}
    decoded = json.decode(body)
    if type(decoded) == "string":
        log.error(LOG_PREFIX_ERROR + ("Decoded body is string, expected object/array: %s" % decoded[:200]))
        return {}
    return decoded


def _resolve_vuln_filter(vuln_filter):
    """
    Spotlight combined endpoint requires a filter.
    Use explicit vuln_filter when provided, otherwise default to open vulnerabilities.
    """
    if type(vuln_filter) == "string" and vuln_filter:
        return vuln_filter
    return DEFAULT_VULN_FILTER


def _to_int(value, default):
    if type(value) == "int":
        return value
    if type(value) != "string":
        return default
    s = value.strip()
    if s == "":
        return default
    normalized = _remove_digits(s)
    if normalized != "":
        return default
    return int(s)

def _remove_digits(value):
    normalized = value
    for digit in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]:
        normalized = normalized.replace(digit, "")
    return normalized

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
    normalized = _remove_digits(normalized)
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


def _as_string(value):
    if type(value) == "string":
        return value
    return ""


def _as_string_list(values):
    out = []
    for value in values:
        if type(value) == "string":
            out.append(value)
        else:
            out.append(str(value))
    return out


def _chunk_list(values, chunk_size):
    if chunk_size <= 0:
        return []

    chunks = []
    i = 0

    while i < len(values):
        chunks.append(values[i:i + chunk_size])
        i += chunk_size

    return chunks

def _extract_next_cursor(resp):
    return _extract_pagination_cursor(resp, "next", False)


def _extract_after_cursor(resp):
    return _extract_pagination_cursor(resp, "after", True)


def _extract_pagination_cursor(resp, key, stringify_int):
    meta = resp.get("meta", {})
    if type(meta) != "dict":
        return ""
    pagination = meta.get("pagination", {})
    if type(pagination) != "dict":
        return ""
    cursor_value = pagination.get(key, "")
    if cursor_value == None:
        return ""
    if type(cursor_value) == "string":
        return cursor_value
    if type(cursor_value) == "int":
        if stringify_int:
            return str(cursor_value)
        return cursor_value
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
    return _as_string(arr[0])


def _form_url_encode(value):
    encoded = _as_string(value)
    encoded = encoded.replace("%", "%25")
    encoded = encoded.replace("&", "%26")
    encoded = encoded.replace("=", "%3D")
    encoded = encoded.replace("+", "%2B")
    encoded = encoded.replace(" ", "%20")
    return encoded


def _collect_page_remediation_ids(vulns):
    seen = {}
    ordered = []
    for raw_vuln in vulns:
        rid = _resolve_primary_remediation_id(raw_vuln)
        if rid and not seen.get(rid, False):
            seen[rid] = True
            ordered.append(rid)
    return ordered


def _resolve_primary_remediation_id(raw):
    """
    Resolve the primary remediation ID for a vulnerability.

    Priority order:
      1) remediation_info.recommended_id
      2) remediation_info.minimum_id
      3) first ID from remediation payload

    Args:
        raw: Raw vulnerability dict from the Spotlight API

    Returns:
        A remediation ID string, or empty string when none can be resolved
    """
    if type(raw) != "dict":
        return ""

    recommended_id, minimum_id = _extract_recommended_and_minimum_ids(raw)
    if recommended_id:
        return recommended_id
    if minimum_id:
        return minimum_id

    top_level_fallback_id = _first_remediation_id(raw.get("remediation", {}))
    if top_level_fallback_id:
        return top_level_fallback_id

    first_app = _first_app_dict(raw)
    if type(first_app) == "dict":
        return _first_remediation_id(first_app.get("remediation", {}))
    return ""


def _extract_recommended_and_minimum_ids(raw):
    """
    Extract recommended/minimum remediation IDs from vulnerability payload.

    Prefers top-level remediation_info, then falls back to first app remediation_info.
    """
    recommended_id, minimum_id = _ids_from_remediation_info(raw.get("remediation_info", {}))
    if recommended_id or minimum_id:
        return recommended_id, minimum_id

    first_app = _first_app_dict(raw)
    if type(first_app) != "dict":
        return "", ""
    return _ids_from_remediation_info(first_app.get("remediation_info", {}))


def _ids_from_remediation_info(remediation_info):
    if type(remediation_info) != "dict":
        return "", ""
    return (
        _as_string(remediation_info.get("recommended_id", "")),
        _as_string(remediation_info.get("minimum_id", "")),
    )


def _first_remediation_id(remediation_value):
    """Extract the first remediation ID from a remediation payload."""
    if type(remediation_value) == "string":
        return remediation_value
    if type(remediation_value) == "list":
        if not remediation_value:
            return ""
        first = remediation_value[0]
        if type(first) == "dict":
            return _as_string(first.get("id", ""))
        return _as_string(first)
    if type(remediation_value) != "dict":
        return ""

    direct_id = _as_string(remediation_value.get("id", ""))
    if direct_id:
        return direct_id

    remediation_ids = _as_list(remediation_value.get("ids", []))
    if remediation_ids:
        return _as_string(remediation_ids[0])

    entities = _as_list(remediation_value.get("entities", []))
    if entities and type(entities[0]) == "dict":
        return _as_string(entities[0].get("id", ""))
    return ""


def _first_app_dict(raw):
    if type(raw) != "dict":
        return {}
    apps = _as_list(raw.get("apps", []))
    if apps and type(apps[0]) == "dict":
        return apps[0]
    return {}


def _first_remediation_entity(raw):
    """Return first remediation entity from top-level or first app remediation."""
    if type(raw) != "dict":
        return {}

    top_level_remediation = raw.get("remediation", {})
    if type(top_level_remediation) == "dict":
        top_entities = _as_list(top_level_remediation.get("entities", []))
        if top_entities and type(top_entities[0]) == "dict":
            return top_entities[0]

    first_app = _first_app_dict(raw)
    app_remediation = first_app.get("remediation", {}) if type(first_app) == "dict" else {}
    if type(app_remediation) == "dict":
        app_entities = _as_list(app_remediation.get("entities", []))
        if app_entities and type(app_entities[0]) == "dict":
            return app_entities[0]
    return {}


def _resolve_action_from_cache(remediation_id, remediation_cache):
    """
    Look up remediation action text from cache for one remediation ID.

    Args:
        remediation_id: Remediation ID string
        remediation_cache: Dict of remediation ID -> action text

    Returns:
        Action text string, or empty string when not found
    """
    if not remediation_id:
        return DEFAULT_REMEDIATION_GUIDANCE
    return _as_string(remediation_cache.get(remediation_id, ""))



def _collect_mock_data(pb):
    """
    Collect synthetic device and vulnerability data for offline testing.

    Args:
        pb: Proto types from zafran.proto_file
    """
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
        cve="CVE-2026-0001",
        in_runtime=True,
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product="mock-product",
            vendor="mock-vendor",
            version="1.0.0",
        ),
        remediation=pb.Remediation(
            suggestion="Update to 1.0.1",
            source=CROWDSTRIKE_SOURCE,
        ),
        severity="medium",
        description="Mock vulnerability for offline testing",
    )
    zafran.collect_vulnerability(vuln)
