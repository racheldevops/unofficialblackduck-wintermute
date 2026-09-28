from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any


EPIC_LABEL = re.compile(r"bd_cve_[0-9a-f]{8,64}")
CHILD_LABEL = re.compile(
    r"bd_cve_(?:project|product)_[0-9a-f]{8,64}"
)


def own_lookup_labels(labels: Iterable[str]) -> set[str]:
    """Remove Epic identity labels inherited by product/child Tasks."""
    selected = set(labels)
    if any(CHILD_LABEL.fullmatch(label) for label in selected):
        return {
            label for label in selected
            if EPIC_LABEL.fullmatch(label) is None
        }
    return selected


def search_by_labels(
    client: Any,
    deployment: str,
    project_key: str,
    labels: list[str],
    batch_size: int = 50,
) -> dict[str, dict[str, Any]]:
    """Read all search pages and reject duplicate own identities.

    This function is used directly by product reporting. It does not modify
    the existing publisher's client class or global functions.
    """
    if deployment not in {"cloud", "datacenter"}:
        raise RuntimeError("Unsupported Jira deployment")
    if not isinstance(project_key, str) or not project_key.strip():
        raise RuntimeError("Jira project key is required")
    if type(batch_size) is not int or batch_size < 1:
        raise RuntimeError("Jira label batch size must be positive")
    if not isinstance(labels, list) or not all(
        isinstance(label, str) and label.strip() for label in labels
    ):
        raise RuntimeError("Jira labels must be nonempty strings")

    selected = sorted(set(labels))
    found: dict[str, dict[str, Any]] = {}
    path = (
        "/rest/api/3/search/jql"
        if deployment == "cloud"
        else "/rest/api/2/search"
    )

    for start in range(0, len(selected), batch_size):
        batch = set(selected[start:start + batch_size])
        quoted = ", ".join(json.dumps(label) for label in sorted(batch))
        query: dict[str, Any] = {
            "jql": (
                f"project = {json.dumps(project_key)} "
                f"AND labels in ({quoted}) ORDER BY key ASC"
            ),
            "fields": "summary,labels,status",
            "maxResults": 100,
        }
        if deployment == "datacenter":
            query["startAt"] = 0

        seen_keys: set[str] = set()
        seen_tokens: set[str] = set()

        for _ in range(10000):
            response = client.request_json(
                "GET", path, query=dict(query), expected_statuses={200},
            )
            if not isinstance(response, dict):
                raise RuntimeError("Jira search response is not an object")
            issues = response.get("issues")
            if not isinstance(issues, list):
                raise RuntimeError("Jira search response has no issues array")

            for issue in issues:
                if not isinstance(issue, dict):
                    raise RuntimeError("Jira search returned an invalid issue")
                key = issue.get("key")
                fields = issue.get("fields")
                if not isinstance(key, str) or not key or not isinstance(fields, dict):
                    raise RuntimeError("Jira search returned invalid issue fields")
                if key in seen_keys:
                    raise RuntimeError("Jira search pagination repeated an issue")
                seen_keys.add(key)

                issue_labels = fields.get("labels")
                if not isinstance(issue_labels, list) or not all(
                    isinstance(label, str) for label in issue_labels
                ):
                    raise RuntimeError("Jira search returned invalid labels")

                status = fields.get("status") or {}
                if not isinstance(status, dict):
                    raise RuntimeError("Jira search returned invalid status")

                for label in batch.intersection(own_lookup_labels(issue_labels)):
                    previous = found.get(label)
                    if previous is not None and previous["key"] != key:
                        raise RuntimeError(
                            "Multiple Jira issues share an own lookup identity: "
                            + label
                        )
                    found[label] = {
                        "key": key,
                        "summary": fields.get("summary", ""),
                        "status": status.get("name", ""),
                        "labels": issue_labels,
                    }

            if deployment == "cloud":
                is_last = response.get("isLast")
                token = response.get("nextPageToken")
                if is_last is not None and type(is_last) is not bool:
                    raise RuntimeError("Jira Cloud isLast is invalid")
                if token is not None and not isinstance(token, str):
                    raise RuntimeError("Jira Cloud nextPageToken is invalid")
                if is_last is True:
                    break
                if not token:
                    if is_last is False:
                        raise RuntimeError("Jira Cloud omitted a required page token")
                    break
                if token in seen_tokens:
                    raise RuntimeError("Jira Cloud page token repeated")
                seen_tokens.add(token)
                query["nextPageToken"] = token
            else:
                offset = query["startAt"]
                returned = response.get("startAt", offset)
                total = response.get("total")
                if type(returned) is not int or returned != offset:
                    raise RuntimeError("Jira Data Center offset did not advance")
                if total is not None and (type(total) is not int or total < 0):
                    raise RuntimeError("Jira Data Center total is invalid")
                if not issues:
                    if total is not None and offset < total:
                        raise RuntimeError("Jira search ended before its reported total")
                    break
                query["startAt"] = offset + len(issues)
                if total is not None and query["startAt"] >= total:
                    break
        else:
            raise RuntimeError("Jira search pagination limit exceeded")

    return found
