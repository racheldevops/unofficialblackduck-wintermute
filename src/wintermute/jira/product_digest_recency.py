from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from wintermute.blackduck.client import RETRYABLE_STATUSES
from wintermute.blackduck.occurrences import same_instance_url


DIGEST_ACCEPT = "application/vnd.blackducksoftware.vulnerability-digest-1+json"
MAX_PAGES = 10000


def parse_detection(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def read_page(client: Any, *, offset: int, limit: int) -> dict[str, Any]:
    url = same_instance_url(
        client,
        f"/api/vulnerabilities-digest?{urlencode({'offset': offset, 'limit': limit})}",
    )
    attempts = client.retries + 1

    for attempt in range(attempts):
        token = client.bearer_token
        if not token:
            raise RuntimeError("Black Duck digest requires authentication")

        permit = client.request_control.before_request("GET", url)
        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": DIGEST_ACCEPT,
            },
            method="GET",
        )
        try:
            with urlopen(
                request,
                timeout=client.timeout,
                context=client.ssl_context,
            ) as response:
                body = response.read()
            client.request_control.record_success()
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise RuntimeError("Black Duck digest page is not an object")
            return payload

        except HTTPError as error:
            _, opened = client.request_control.record_server_failure(
                error.code, url, context=permit.context,
            )
            if opened:
                raise client.request_control.circuit_error() from error
            detail = error.read(2000).decode("utf-8", errors="replace")
            if error.code not in RETRYABLE_STATUSES or attempt == attempts - 1:
                raise RuntimeError(
                    f"Black Duck digest request failed: HTTP {error.code}: {detail}"
                ) from error
            retry_after = error.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else client.retry_delay * (attempt + 1)
            except ValueError:
                delay = client.retry_delay * (attempt + 1)
            time.sleep(max(0.0, delay))

        except (URLError, TimeoutError, OSError) as error:
            if attempt == attempts - 1:
                raise RuntimeError(
                    f"Black Duck digest request failed after {attempts} attempt(s): {error}"
                ) from error
            time.sleep(max(0.0, client.retry_delay * (attempt + 1)))

        except (UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Black Duck digest returned invalid JSON") from error

    raise RuntimeError("Black Duck digest request did not complete")


def load_digest(client: Any) -> dict[str, Any]:
    if type(client.page_limit) is not int or client.page_limit < 1:
        raise RuntimeError("Black Duck digest page limit must be positive")

    by_id: dict[str, Any] = {}
    total = None
    offset = 0

    for _ in range(MAX_PAGES):
        payload = read_page(client, offset=offset, limit=client.page_limit)
        reported_total = payload.get("totalCount")
        page = payload.get("items")
        if type(reported_total) is not int or reported_total < 0:
            raise RuntimeError("Black Duck digest totalCount is invalid")
        if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
            raise RuntimeError("Black Duck digest items are invalid")
        if total is not None and total != reported_total:
            raise RuntimeError("Black Duck digest changed during pagination")
        total = reported_total

        if not page:
            if offset != total:
                raise RuntimeError("Black Duck digest ended before totalCount")
            return by_id

        for item in page:
            identifier = item.get("vulnerabilityId")
            if not isinstance(identifier, str) or not identifier.strip():
                raise RuntimeError("Black Duck digest item has no vulnerabilityId")
            identifier = identifier.strip()
            if identifier in by_id:
                raise RuntimeError("Black Duck digest repeated a vulnerabilityId")
            by_id[identifier] = item.get("firstDetected")

        offset += len(page)
        if offset > total:
            raise RuntimeError("Black Duck digest exceeds totalCount")
        if offset == total:
            return by_id

    raise RuntimeError("Black Duck digest exceeded pagination limit")


def filter_recent_findings(
    client: Any,
    findings: list[Any],
    days: int | None,
    report: dict[str, Any],
    *,
    now: datetime | None = None,
) -> list[Any]:
    report["first_detected_within_days"] = days
    if days is None:
        report["first_detected_filter"] = {"enabled": False}
        return list(findings)

    if type(days) is not int or not 1 <= days <= 3650:
        raise ValueError("--first-detected-within-days must be from 1 to 3650")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Current time must include a timezone")
    current = current.astimezone(timezone.utc)
    cutoff = datetime.fromtimestamp(
        current.timestamp() - days * 86400,
        timezone.utc,
    )

    # A failure here stops publishing; --allow-partial governs collection
    # failures, not an unevaluable date filter.
    digest = load_digest(client)
    counts = {
        "matched": 0,
        "older": 0,
        "unmatched": 0,
        "invalid_date": 0,
        "future_date": 0,
    }
    selected = []
    for finding in findings:
        identifier = str(finding.vulnerability or "").strip()
        if identifier not in digest:
            counts["unmatched"] += 1
            continue
        detected = parse_detection(digest[identifier])
        if detected is None:
            counts["invalid_date"] += 1
        elif detected > current:
            counts["future_date"] += 1
        elif detected < cutoff:
            counts["older"] += 1
        else:
            counts["matched"] += 1
            selected.append(finding)

    report["first_detected_filter"] = {
        "enabled": True,
        "scope": "blackduck-instance-vulnerability-digest",
        "cutoff_utc": cutoff.isoformat().replace("+00:00", "Z"),
        "evaluated_at_utc": current.isoformat().replace("+00:00", "Z"),
        "digest_items": len(digest),
        **counts,
    }
    return selected
