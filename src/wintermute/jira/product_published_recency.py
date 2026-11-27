from __future__ import annotations

import json
import math
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from wintermute.blackduck.client import RETRYABLE_STATUSES
from wintermute.blackduck.occurrences import same_instance_url
from wintermute.blackduck.request_control import BlackDuckCircuitOpenError


VULNERABILITY_ID = re.compile(
    r"(?:CVE-[0-9]{4}-[0-9]{4,}|BDSA-[0-9]{4}-[0-9]+)",
    re.IGNORECASE,
)
ACCEPT = "application/vnd.blackducksoftware.vulnerability-4+json"


def parse_published_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def read_advisory(client: Any, identifier: str) -> dict[str, Any]:
    """Read the exact vulnerability V4 resource with the required Accept type."""
    if VULNERABILITY_ID.fullmatch(identifier) is None:
        raise RuntimeError("Unsupported CVE/BDSA vulnerability identifier")

    url = same_instance_url(
        client,
        f"/api/vulnerabilities/{quote(identifier, safe='')}",
    )
    attempts = client.retries + 1
    token_refreshed = False
    attempt = 0

    while attempt < attempts:
        token = client.bearer_token
        if not token:
            raise RuntimeError("Black Duck advisory read requires authentication")

        permit = client.request_control.before_request("GET", url)
        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": ACCEPT,
            },
            method="GET",
        )
        try:
            with urlopen(
                request,
                timeout=client.timeout,
                context=client.ssl_context,
            ) as response:
                data = response.read()
            client.request_control.record_success()
            try:
                payload = json.loads(data)
            except (ValueError, UnicodeError) as error:
                raise RuntimeError(
                    f"Invalid vulnerability V4 JSON for {identifier}"
                ) from error
            if not isinstance(payload, dict):
                raise RuntimeError(
                    f"Invalid vulnerability V4 resource for {identifier}"
                )
            if payload.get("name") != identifier:
                raise RuntimeError(
                    f"Vulnerability V4 identity differs from {identifier}"
                )
            return payload
        except HTTPError as error:
            _, opened = client.request_control.record_server_failure(
                error.code, url, context=permit.context,
            )
            if opened:
                raise client.request_control.circuit_error() from error
            if error.code == 401 and not token_refreshed:
                token_refreshed = True
                client.authenticate()
                continue
            if error.code not in RETRYABLE_STATUSES or attempt + 1 == attempts:
                raise RuntimeError(
                    f"Vulnerability V4 read failed for {identifier}: "
                    f"HTTP {error.code}"
                ) from error
            raw_delay = error.headers.get("Retry-After")
            try:
                delay = float(raw_delay) if raw_delay else client.retry_delay * (attempt + 1)
            except ValueError:
                delay = client.retry_delay * (attempt + 1)
            time.sleep(delay if math.isfinite(delay) and delay >= 0 else client.retry_delay)
        except (URLError, TimeoutError, OSError) as error:
            if attempt + 1 == attempts:
                raise RuntimeError(
                    f"Vulnerability V4 read failed for {identifier}: "
                    f"{type(error).__name__}"
                ) from error
            time.sleep(max(0.0, client.retry_delay * (attempt + 1)))
        attempt += 1

    raise RuntimeError(f"Vulnerability V4 read failed for {identifier}")


def filter_published_findings(
    client: Any,
    findings: list[Any],
    days: int | None,
    report: dict[str, Any],
    *,
    strict: bool = True,
    now: datetime | None = None,
) -> list[Any]:
    """Select findings by advisory publication date, not product detection."""
    findings = list(findings)
    report["published_within_days"] = days
    if days is None:
        report["published_filter"] = {"enabled": False}
        return findings
    if type(days) is not int or not 1 <= days <= 3650:
        raise ValueError("--published-within-days must be from 1 to 3650")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Current time must include a timezone")
    current = current.astimezone(timezone.utc)
    cutoff = current - timedelta(days=days)
    identifiers = sorted({
        str(finding.vulnerability or "").strip()
        for finding in findings
    })
    dates: dict[str, datetime | None] = {}
    failed: dict[str, str] = {}

    for identifier in identifiers:
        try:
            advisory = read_advisory(client, identifier)
        except BlackDuckCircuitOpenError:
            raise
        except (RuntimeError, ValueError) as error:
            failed[identifier] = str(error)
            continue
        dates[identifier] = parse_published_date(advisory.get("publishedDate"))

    counts = {
        "matched": 0,
        "older": 0,
        "invalid_date": 0,
        "future_date": 0,
        "read_failed": 0,
    }
    selected = []
    for finding in findings:
        identifier = str(finding.vulnerability or "").strip()
        if identifier in failed:
            counts["read_failed"] += 1
            continue
        published = dates[identifier]
        if published is None:
            counts["invalid_date"] += 1
        elif published > current:
            counts["future_date"] += 1
        elif published < cutoff:
            counts["older"] += 1
        else:
            counts["matched"] += 1
            selected.append(finding)

    report["published_filter"] = {
        "enabled": True,
        "scope": "exact-vulnerability-v4-publishedDate",
        "cutoff_utc": cutoff.isoformat().replace("+00:00", "Z"),
        "evaluated_at_utc": current.isoformat().replace("+00:00", "Z"),
        "advisory_count": len(identifiers),
        "failed_advisories": failed,
        **counts,
    }

    # Keep strict mode strict. In allow-partial mode, other independently
    # validated findings remain eligible, but failed IDs are never published.
    if failed and strict:
        raise RuntimeError(
            f"Published-date lookup failed for {len(failed)} advisory ID(s); "
            "see product-selection.json"
        )
    return selected
