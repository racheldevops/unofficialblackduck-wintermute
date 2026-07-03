#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


REQUIRED_FINDING_FIELDS = [
    "parent_project",
    "parent_version",
    "parent_version_href",
    "subproject_path",
    "subproject",
    "subproject_version",
    "subproject_version_href",
    "relationship_detection_method",
    "component",
    "component_version",
    "vulnerability",
    "score_field",
    "score",
    "severity",
    "blackduck_url",
    "rollup_key",
]

DEFAULT_CONFIG = {
    "jira": {
        "url": "",
        "project_key": "",
        "issue_type": "Task",
        "api_version": "2",
        "auth_mode": "basic",
        "verify_tls": True,
    },
    "issue": {
        "summary_template": (
            "[Black Duck] {severity} {vulnerability} in {component} - "
            "{parent_project} {parent_version}"
        ),
        "labels": ["blackduck", "subproject_rollup"],
        "priority_by_severity": {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        },
        "status_by_severity": {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
        },
        "additional_fields": {},
    },
    "dedupe": {
        "label_prefix": "bd_rollup_",
        "hash_length": 24,
    },
    "ai": {
        "enabled": False,
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
    },
    "hierarchy": {
        "epic_issue_type": "Epic",
        "story_issue_type": "Story",
        "vulnerability_issue_type": "Task",
        "story_parent_mode": "jira_parent",
        "vulnerability_parent_mode": "issue_link",
        "issue_link_type": "Relates",
        "epic_link_field": "",
        "labels": {
            "epic": ["bd_rollup_parent"],
            "story": ["bd_rollup_child"],
            "vulnerability": ["bd_rollup_vuln"],
        },
        "additional_fields": {
            "epic": {},
            "story": {},
            "vulnerability": {},
        },
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)

    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value

    return merged


def load_json_file(path: str, default: dict[str, Any]) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return dict(default)

    with open(path, encoding="utf-8") as input_file:
        loaded = json.load(input_file)

    if not isinstance(loaded, dict):
        raise RuntimeError(f"{path} must contain a JSON object")

    return deep_merge(default, loaded)


def save_json_file(path: str, payload: dict[str, Any]) -> None:
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, indent=2, sort_keys=True)

    os.replace(tmp_path, path)


def load_state(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        return {
            "schema_version": 1,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "issues_by_external_id": {},
            "links_by_key": {},
        }

    try:
        with open(path, encoding="utf-8") as input_file:
            state = json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Failed to read state file {path}: {error}") from error

    if not isinstance(state, dict):
        raise RuntimeError(f"State file {path} must contain a JSON object")

    state.setdefault("schema_version", 1)
    state.setdefault("created_at", now_iso())
    state.setdefault("updated_at", now_iso())
    state.setdefault("issues_by_external_id", {})
    state.setdefault("links_by_key", {})

    if not isinstance(state["issues_by_external_id"], dict):
        raise RuntimeError("State field issues_by_external_id must be an object")

    if not isinstance(state["links_by_key"], dict):
        raise RuntimeError("State field links_by_key must be an object")

    return state


def sanitize_jira_label(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_") or "unknown"


def rollup_external_id(rollup_key: str) -> str:
    return hashlib.sha256(rollup_key.encode("utf-8")).hexdigest()


def rollup_label(rollup_key: str, config: dict[str, Any]) -> str:
    dedupe_config = config.get("dedupe", {})
    prefix = str(dedupe_config.get("label_prefix") or "bd_rollup_")
    hash_length = int(dedupe_config.get("hash_length") or 24)
    external_id = rollup_external_id(rollup_key)
    return sanitize_jira_label(f"{prefix}{external_id[:hash_length]}")


def truncate(value: str, max_length: int) -> str:
    if len(value) <= max_length:
        return value

    return value[: max_length - 3] + "..."


def safe_format(template: str, context: dict[str, Any]) -> str:
    class SafeDict(dict):
        def __missing__(self, key: str) -> str:
            return "{" + key + "}"

    return template.format_map(SafeDict(context))


def render_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return safe_format(value, context)

    if isinstance(value, list):
        return [render_value(item, context) for item in value]

    if isinstance(value, dict):
        return {key: render_value(item, context) for key, item in value.items()}

    return value


def normalize_lookup(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def configured_status_for_severity(severity: str, config: dict[str, Any]) -> str:
    issue_config = config.get("issue", {})
    status_by_severity = issue_config.get("status_by_severity", {})

    if not isinstance(status_by_severity, dict):
        return ""

    return str(status_by_severity.get(str(severity or "").strip().upper()) or "").strip()


def normalize_finding(row: dict[str, str]) -> dict[str, str]:
    normalized = {field: str(row.get(field, "") or "").strip() for field in REQUIRED_FINDING_FIELDS}

    if not normalized["rollup_key"]:
        normalized["rollup_key"] = "|".join(
            [
                normalized["parent_project"],
                normalized["parent_version"],
                normalized["subproject"],
                normalized["subproject_version"],
                normalized["component"],
                normalized["component_version"],
                normalized["vulnerability"],
            ]
        )

    normalized["severity"] = normalized["severity"].upper()

    return normalized


def read_findings(path: str) -> list[dict[str, str]]:
    if path == "-":
        input_file = sys.stdin
        close_after = False
    else:
        input_file = open(path, newline="", encoding="utf-8")
        close_after = True

    try:
        reader = csv.DictReader(input_file)

        if not reader.fieldnames:
            raise RuntimeError("Findings CSV has no header row")

        missing = [field for field in REQUIRED_FINDING_FIELDS if field not in reader.fieldnames]
        if missing:
            raise RuntimeError(f"Findings CSV is missing required fields: {', '.join(missing)}")

        findings = [normalize_finding(row) for row in reader]
    finally:
        if close_after:
            input_file.close()

    deduped: list[dict[str, str]] = []
    seen_rollup_keys: set[str] = set()

    for finding in findings:
        rollup_key = finding["rollup_key"]

        if rollup_key in seen_rollup_keys:
            continue

        seen_rollup_keys.add(rollup_key)
        deduped.append(finding)

    return deduped


def finding_context(finding: dict[str, str], config: dict[str, Any]) -> dict[str, Any]:
    rollup_key = finding["rollup_key"]
    external_id = rollup_external_id(rollup_key)
    label = rollup_label(rollup_key, config)

    context: dict[str, Any] = dict(finding)
    context["rollup_external_id"] = external_id
    context["rollup_label"] = label
    context["short_rollup_hash"] = external_id[:12]

    return context


def validate_rollup_key_hash(value: str) -> str:
    normalized = str(value or "").strip().lower()

    if not re.fullmatch(r"[a-f0-9]{64}", normalized):
        raise RuntimeError(
            "--only-rollup-key-hash must be a full 64-character SHA-256 hex hash, "
            f"but got {json.dumps(value)}"
        )

    return normalized


def build_wiki_description(finding: dict[str, str], context: dict[str, Any]) -> str:
    return f"""h2. Black Duck vulnerability rollup finding

This Jira issue was generated from a Black Duck subproject vulnerability rollup.

h3. Finding summary

||Field||Value||
|Parent project|{finding["parent_project"]}|
|Parent version|{finding["parent_version"]}|
|Subproject path|{finding["subproject_path"]}|
|Subproject|{finding["subproject"]}|
|Subproject version|{finding["subproject_version"]}|
|Component|{finding["component"]}|
|Component version|{finding["component_version"]}|
|Vulnerability|{finding["vulnerability"]}|
|Severity|{finding["severity"]}|
|Score|{finding["score"]}|
|Score field|{finding["score_field"]}|
|Relationship detection method|{finding["relationship_detection_method"]}|

h3. Links

* Black Duck vulnerability: {finding["blackduck_url"]}
* Parent project version: {finding["parent_version_href"]}
* Subproject version: {finding["subproject_version_href"]}

h3. Suggested remediation workflow

# Review the Black Duck vulnerability advisory.
# Confirm whether the vulnerable component is reachable or exploitable in the affected subproject.
# Upgrade, patch, or replace the vulnerable component where possible.
# If no upgrade is available, document compensating controls or an accepted-risk decision.
# Rescan the affected subproject in Black Duck.
# Close this issue after the rollup no longer reports this finding.

h3. Deduplication metadata

* Rollup key hash: {context["rollup_external_id"]}
* Jira lookup label: {context["rollup_label"]}

{{noformat}}
{finding["rollup_key"]}
{{noformat}}
"""


def text_to_adf_paragraphs(text: str) -> dict[str, Any]:
    content = []

    for line in text.splitlines():
        if not line.strip():
            continue

        content.append(
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": line[:30000],
                    }
                ],
            }
        )

    return {
        "type": "doc",
        "version": 1,
        "content": content or [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Black Duck vulnerability rollup finding.",
                    }
                ],
            }
        ],
    }


def maybe_generate_ai_description(
        finding: dict[str, str],
        context: dict[str, Any],
        config: dict[str, Any],
        timeout: int,
        debug: bool,
) -> str | None:
    ai_config = config.get("ai", {})

    if not ai_config.get("enabled"):
        return None

    api_key_env = str(ai_config.get("api_key_env") or "OPENAI_API_KEY")
    api_key = os.getenv(api_key_env)

    if not api_key:
        if debug:
            print(
                f"AI description requested but {api_key_env} is not set; using template.",
                file=sys.stderr,
            )
        return None

    base_url = str(ai_config.get("base_url") or "https://api.openai.com/v1").rstrip("/")
    model = str(ai_config.get("model") or "gpt-4o-mini")
    url = f"{base_url}/chat/completions"

    prompt = {
        "model": model,
        "temperature": 0.2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You write concise, accurate Jira descriptions for vulnerability remediation. "
                    "Do not invent fixed versions, exploitability, or remediation facts that are "
                    "not present in the input. If specific remediation is unknown, recommend "
                    "reviewing the linked Black Duck advisory and upgrading to a non-vulnerable "
                    "component version."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": "Create a clear Jira issue description in Jira wiki markup.",
                        "finding": finding,
                        "dedupe": {
                            "rollup_hash": context["rollup_external_id"],
                            "jira_label": context["rollup_label"],
                        },
                    },
                    indent=2,
                ),
            },
        ],
    }

    request = Request(
        url,
        method="POST",
        data=json.dumps(prompt).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))

        return str(payload["choices"][0]["message"]["content"]).strip()

    except Exception as error:
        if debug:
            print(f"AI description generation failed; using template: {error}", file=sys.stderr)
        return None


def build_issue_payload(
        finding: dict[str, str],
        config: dict[str, Any],
        description_format: str,
        timeout: int,
        debug: bool,
) -> tuple[dict[str, Any], str]:
    context = finding_context(finding, config)

    issue_config = config.get("issue", {})
    jira_config = config.get("jira", {})

    summary_template = str(issue_config.get("summary_template") or DEFAULT_CONFIG["issue"]["summary_template"])
    summary = truncate(safe_format(summary_template, context), 255)

    base_labels = issue_config.get("labels", [])
    if not isinstance(base_labels, list):
        raise RuntimeError("issue.labels must be a list")

    labels = [sanitize_jira_label(str(label)) for label in base_labels]
    labels.append(context["rollup_label"])

    if finding["severity"]:
        labels.append(sanitize_jira_label(f"bd_sev_{finding['severity']}"))

    labels = sorted(set(label for label in labels if label))

    ai_description = maybe_generate_ai_description(
        finding=finding,
        context=context,
        config=config,
        timeout=timeout,
        debug=debug,
    )

    description_text = ai_description or build_wiki_description(finding, context)

    fields: dict[str, Any] = {
        "project": {
            "key": str(jira_config["project_key"]),
        },
        "issuetype": {
            "name": str(jira_config.get("issue_type") or "Task"),
        },
        "summary": summary,
        "labels": labels,
    }

    if description_format == "adf":
        fields["description"] = text_to_adf_paragraphs(description_text)
    else:
        fields["description"] = description_text

    priority_by_severity = issue_config.get("priority_by_severity", {})
    if isinstance(priority_by_severity, dict):
        priority_name = priority_by_severity.get(finding["severity"])
        if priority_name:
            fields["priority"] = {
                "name": str(priority_name),
            }

    additional_fields = issue_config.get("additional_fields", {})
    if isinstance(additional_fields, dict):
        rendered_additional_fields = render_value(additional_fields, context)
        fields.update(rendered_additional_fields)

    payload = {
        "fields": fields,
    }

    return payload, context["rollup_label"]


class JiraClient:
    def __init__(
            self,
            base_url: str,
            api_version: str,
            auth_mode: str,
            username: str | None,
            api_token: str | None,
            pat: str | None,
            verify_tls: bool,
            timeout: int,
            retries: int,
            retry_delay: float,
            debug: bool,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_version = api_version
        self.auth_mode = auth_mode
        self.username = username
        self.api_token = api_token
        self.pat = pat
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.debug = debug

        if verify_tls:
            self.ssl_context = None
        else:
            self.ssl_context = ssl._create_unverified_context()

    def enabled(self) -> bool:
        if not self.base_url:
            return False

        if self.auth_mode == "bearer":
            return bool(self.pat)

        return bool(self.username and self.api_token)

    def auth_headers(self) -> dict[str, str]:
        if self.auth_mode == "bearer":
            return {
                "Authorization": f"Bearer {self.pat}",
            }

        raw = f"{self.username}:{self.api_token}".encode("utf-8")
        encoded = base64.b64encode(raw).decode("ascii")

        return {
            "Authorization": f"Basic {encoded}",
        }

    def request_json(
            self,
            method: str,
            path: str,
            payload: dict[str, Any] | None = None,
            query: dict[str, Any] | None = None,
            expected_statuses: set[int] | None = None,
    ) -> Any:
        expected_statuses = expected_statuses or {200}
        url = f"{self.base_url}{path}"

        if query:
            url = f"{url}?{urlencode(query)}"

        data = None
        headers = {
            "Accept": "application/json",
        }
        headers.update(self.auth_headers())

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        retryable_statuses = {429, 500, 502, 503, 504}

        for attempt in range(self.retries + 1):
            request = Request(url, data=data, headers=headers, method=method)

            try:
                with urlopen(
                        request,
                        timeout=self.timeout,
                        context=self.ssl_context,
                ) as response:
                    response_body = response.read().decode("utf-8", errors="replace")

                    if response.status not in expected_statuses:
                        raise RuntimeError(
                            f"{method} {url} returned HTTP {response.status}: "
                            f"{response_body[:4000]}"
                        )

                    if not response_body:
                        return {}

                    return json.loads(response_body)

            except HTTPError as error:
                response_body = error.read().decode("utf-8", errors="replace")

                if error.code not in retryable_statuses or attempt >= self.retries:
                    raise RuntimeError(
                        f"{method} {url} failed: HTTP {error.code} {error.reason}\n"
                        f"{response_body[:4000]}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                if self.debug:
                    print(
                        f"Retrying Jira {method} after HTTP {error.code}; "
                        f"attempt {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                        file=sys.stderr,
                    )
                time.sleep(sleep_seconds)

            except (TimeoutError, URLError) as error:
                if attempt >= self.retries:
                    raise RuntimeError(
                        f"{method} {url} failed after {self.retries + 1} attempt(s): {error}"
                    ) from error

                sleep_seconds = self.retry_delay * (attempt + 1)
                if self.debug:
                    print(
                        f"Retrying Jira {method} after network error; "
                        f"attempt {attempt + 1}/{self.retries}, sleeping {sleep_seconds}s",
                        file=sys.stderr,
                    )
                time.sleep(sleep_seconds)

        raise RuntimeError(f"{method} {url} failed unexpectedly")

    def search_by_labels(
            self,
            project_key: str,
            labels: list[str],
            batch_size: int,
    ) -> dict[str, dict[str, Any]]:
        found_by_label: dict[str, dict[str, Any]] = {}

        for start in range(0, len(labels), batch_size):
            label_batch = labels[start : start + batch_size]

            quoted_labels = ", ".join(json.dumps(label) for label in label_batch)
            jql = f'project = "{project_key}" AND labels in ({quoted_labels})'

            search_path = "/rest/api/3/search/jql"
            query: dict[str, Any] = {
                "jql": jql,
                "fields": "summary,labels,status",
                "maxResults": 100,
            }

            while True:
                response = self.request_json(
                    "GET",
                    search_path,
                    query=query,
                    expected_statuses={200},
                )

                for issue in response.get("issues", []):
                    issue_key = issue.get("key")
                    fields = issue.get("fields", {})
                    issue_labels = fields.get("labels", [])

                    if not isinstance(issue_labels, list):
                        continue

                    for label in issue_labels:
                        if label in label_batch:
                            found_by_label[label] = {
                                "key": issue_key,
                                "summary": fields.get("summary", ""),
                                "status": (fields.get("status") or {}).get("name", ""),
                                "labels": issue_labels,
                            }

                next_page_token = response.get("nextPageToken")

                if response.get("isLast", True) or not next_page_token:
                    break

                query["nextPageToken"] = str(next_page_token)

        return found_by_label

    def create_issue(self, payload: dict[str, Any]) -> dict[str, Any]:
        create_path = f"/rest/api/{self.api_version}/issue"
        return self.request_json(
            "POST",
            create_path,
            payload=payload,
            expected_statuses={200, 201},
        )

    def get_issue_status(self, issue_key: str) -> str:
        issue_path = f"/rest/api/{self.api_version}/issue/{issue_key}"
        response = self.request_json(
            "GET",
            issue_path,
            query={"fields": "status"},
            expected_statuses={200},
        )

        if not isinstance(response, dict):
            return ""

        fields = response.get("fields", {})
        if not isinstance(fields, dict):
            return ""

        status = fields.get("status", {})
        if not isinstance(status, dict):
            return ""

        return str(status.get("name") or "")

    def get_issue_transitions(self, issue_key: str) -> list[dict[str, Any]]:
        transitions_path = f"/rest/api/{self.api_version}/issue/{issue_key}/transitions"
        response = self.request_json(
            "GET",
            transitions_path,
            expected_statuses={200},
        )

        if not isinstance(response, dict):
            raise RuntimeError(
                f"GET transitions for Jira issue {issue_key} did not return an object"
            )

        transitions = response.get("transitions", [])
        if not isinstance(transitions, list):
            raise RuntimeError(
                f"GET transitions for Jira issue {issue_key} did not return a transitions list"
            )

        return [
            transition
            for transition in transitions
            if isinstance(transition, dict)
        ]

    def transition_issue_to_status(
            self,
            issue_key: str,
            target_status: str,
    ) -> str:
        target_status = str(target_status or "").strip()

        if not target_status:
            return self.get_issue_status(issue_key)

        current_status = self.get_issue_status(issue_key)

        if normalize_lookup(current_status) == normalize_lookup(target_status):
            return current_status

        transitions = self.get_issue_transitions(issue_key)

        for transition in transitions:
            to_status = transition.get("to", {})
            if not isinstance(to_status, dict):
                continue

            to_status_name = str(to_status.get("name") or "")
            if normalize_lookup(to_status_name) != normalize_lookup(target_status):
                continue

            transition_id = str(transition.get("id") or "")
            if not transition_id:
                continue

            transitions_path = f"/rest/api/{self.api_version}/issue/{issue_key}/transitions"
            self.request_json(
                "POST",
                transitions_path,
                payload={
                    "transition": {
                        "id": transition_id,
                    },
                },
                expected_statuses={200, 204},
            )

            return self.get_issue_status(issue_key) or to_status_name or target_status

        available = sorted(
            {
                str((transition.get("to") or {}).get("name") or "")
                for transition in transitions
                if isinstance(transition.get("to"), dict)
                   and str((transition.get("to") or {}).get("name") or "")
            },
            key=str.lower,
        )

        raise RuntimeError(
            f"Jira issue {issue_key} is in status {json.dumps(current_status)}; "
            f"no available transition goes to {json.dumps(target_status)}. "
            f"Available target status(es): {', '.join(available) or '(none)'}"
        )

    def create_issue_link(
            self,
            link_type: str,
            parent_issue_key: str,
            child_issue_key: str,
    ) -> dict[str, Any]:
        link_path = f"/rest/api/{self.api_version}/issueLink"
        payload = {
            "type": {
                "name": link_type,
            },
            "inwardIssue": {
                "key": parent_issue_key,
            },
            "outwardIssue": {
                "key": child_issue_key,
            },
        }

        return self.request_json(
            "POST",
            link_path,
            payload=payload,
            expected_statuses={200, 201, 204},
        )


def build_jira_client(
        config: dict[str, Any],
        timeout: int,
        retries: int,
        retry_delay: float,
        debug: bool,
) -> JiraClient:
    jira_config = config.get("jira", {})

    base_url = str(os.getenv("JIRA_URL") or jira_config.get("url") or "").strip()
    auth_mode = str(jira_config.get("auth_mode") or "basic").strip().lower()

    return JiraClient(
        base_url=base_url,
        api_version=str(jira_config.get("api_version") or "2"),
        auth_mode=auth_mode,
        username=os.getenv("JIRA_USER"),
        api_token=os.getenv("JIRA_API_TOKEN"),
        pat=os.getenv("JIRA_PAT"),
        verify_tls=bool(jira_config.get("verify_tls", True)),
        timeout=timeout,
        retries=retries,
        retry_delay=retry_delay,
        debug=debug,
    )


def state_issue_for_external_id(
        state: dict[str, Any],
        external_id: str,
) -> dict[str, Any] | None:
    issues_by_external_id = state.get("issues_by_external_id", {})
    issue = issues_by_external_id.get(external_id)
    return issue if isinstance(issue, dict) else None


def update_state_issue(
        state: dict[str, Any],
        external_id: str,
        rollup_key: str,
        rollup_label_value: str,
        issue_key: str,
        status: str,
        action: str,
        node_type: str = "finding",
        summary: str = "",
) -> None:
    issues_by_external_id = state.setdefault("issues_by_external_id", {})
    previous = issues_by_external_id.get(external_id, {})

    if not isinstance(previous, dict):
        previous = {}

    first_seen_at = previous.get("first_seen_at") or now_iso()

    issues_by_external_id[external_id] = {
        "external_id": external_id,
        "node_type": node_type,
        "rollup_key": rollup_key,
        "rollup_label": rollup_label_value,
        "issue_key": issue_key,
        "status": status,
        "summary": summary,
        "first_seen_at": first_seen_at,
        "last_seen_at": now_iso(),
        "last_action": action,
    }

    state["updated_at"] = now_iso()


def write_results_csv(path: str, rows: list[dict[str, Any]]) -> None:
    if not path:
        return

    fieldnames = [
        "action",
        "issue_key",
        "jira_status",
        "rollup_label",
        "parent_project",
        "parent_version",
        "subproject",
        "subproject_version",
        "component",
        "component_version",
        "vulnerability",
        "severity",
        "score",
        "rollup_key",
        "message",
    ]

    with open(path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def load_hierarchy_plan(path: str) -> dict[str, Any]:
    if not path or not os.path.exists(path):
        raise RuntimeError(f"Hierarchy plan file does not exist: {path}")

    try:
        with open(path, encoding="utf-8") as input_file:
            payload = json.load(input_file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Failed to read hierarchy plan {path}: {error}") from error

    if not isinstance(payload, dict):
        raise RuntimeError(f"Hierarchy plan {path} must contain a JSON object")

    nodes = payload.get("nodes")
    if not isinstance(nodes, list):
        raise RuntimeError(f"Hierarchy plan {path} must contain a nodes array")

    for index, node in enumerate(nodes, start=1):
        if not isinstance(node, dict):
            raise RuntimeError(f"Hierarchy plan node #{index} must be an object")

        if not str(node.get("external_id") or "").strip():
            raise RuntimeError(f"Hierarchy plan node #{index} is missing external_id")

        node_type = str(node.get("node_type") or "").strip()
        if node_type not in {"epic", "story", "vulnerability"}:
            raise RuntimeError(
                f"Hierarchy plan node #{index} has unsupported node_type: "
                f"{json.dumps(node_type)}"
            )

    return payload


def node_context(node: dict[str, Any]) -> dict[str, Any]:
    context = node.get("context", {})
    return context if isinstance(context, dict) else {}


def node_stats(node: dict[str, Any]) -> dict[str, Any]:
    stats = node.get("stats", {})
    return stats if isinstance(stats, dict) else {}


def node_external_id(node: dict[str, Any]) -> str:
    return str(node.get("external_id") or "").strip()


def node_parent_external_id(node: dict[str, Any]) -> str:
    return str(node.get("parent_external_id") or "").strip()


def node_lookup_label(node: dict[str, Any]) -> str:
    explicit = str(node.get("lookup_label") or "").strip()

    if explicit:
        return sanitize_jira_label(explicit)

    return sanitize_jira_label(node_external_id(node))


def node_rollup_key(node: dict[str, Any]) -> str:
    context = node_context(node)

    if str(node.get("node_type") or "") == "vulnerability":
        return str(context.get("rollup_key") or "")

    return ""


def hierarchy_node_sort_key(node: dict[str, Any]) -> tuple[int, str, str]:
    order = {
        "epic": 0,
        "story": 1,
        "vulnerability": 2,
    }

    return (
        order.get(str(node.get("node_type") or ""), 99),
        str(node.get("parent_external_id") or ""),
        node_external_id(node),
    )


def filter_hierarchy_nodes(
        nodes: list[dict[str, Any]],
        args: argparse.Namespace,
) -> list[dict[str, Any]]:
    node_by_external_id = {
        node_external_id(node): node
        for node in nodes
    }

    filters = {
        "parent_project": getattr(args, "only_parent_project", None),
        "parent_version": getattr(args, "only_parent_version", None),
        "subproject": getattr(args, "only_subproject", None),
        "vulnerability": getattr(args, "only_vulnerability", None),
    }

    active_filters = {
        key: str(value)
        for key, value in filters.items()
        if value not in (None, "")
    }

    if not active_filters:
        selected_ids = set(node_by_external_id)
    else:
        selected_ids: set[str] = set()

        for node in nodes:
            context = node_context(node)

            if all(str(context.get(key) or "") == value for key, value in active_filters.items()):
                selected_ids.add(node_external_id(node))

    closure_ids = set(selected_ids)

    for external_id in list(selected_ids):
        current = node_by_external_id.get(external_id)

        while current:
            parent_external_id = node_parent_external_id(current)

            if not parent_external_id or parent_external_id in closure_ids:
                break

            closure_ids.add(parent_external_id)
            current = node_by_external_id.get(parent_external_id)

    filtered_nodes = [
        node
        for node in nodes
        if node_external_id(node) in closure_ids
    ]

    filtered_nodes.sort(key=hierarchy_node_sort_key)

    if args.limit is not None:
        filtered_nodes = filtered_nodes[: args.limit]

    return filtered_nodes


def hierarchy_issue_type_for_node(
        node: dict[str, Any],
        config: dict[str, Any],
) -> str:
    hierarchy_config = config.get("hierarchy", {})
    node_type = str(node.get("node_type") or "")

    if node_type == "epic":
        return str(hierarchy_config.get("epic_issue_type") or "Epic")

    if node_type == "story":
        return str(hierarchy_config.get("story_issue_type") or "Story")

    return str(hierarchy_config.get("vulnerability_issue_type") or "Task")


def hierarchy_labels_for_node(
        node: dict[str, Any],
        config: dict[str, Any],
) -> list[str]:
    node_type = str(node.get("node_type") or "")
    hierarchy_config = config.get("hierarchy", {})
    issue_config = config.get("issue", {})

    labels: list[str] = []

    base_issue_labels = issue_config.get("labels", [])
    if isinstance(base_issue_labels, list):
        labels.extend(str(label) for label in base_issue_labels)

    node_labels = node.get("labels", [])
    if isinstance(node_labels, list):
        labels.extend(str(label) for label in node_labels)

    hierarchy_label_map = hierarchy_config.get("labels", {})
    if isinstance(hierarchy_label_map, dict):
        configured_type_labels = hierarchy_label_map.get(node_type, [])
        if isinstance(configured_type_labels, list):
            labels.extend(str(label) for label in configured_type_labels)

    labels.append(node_lookup_label(node))

    context = node_context(node)
    severity = str(context.get("severity") or "").strip().upper()
    if severity:
        labels.append(f"bd_sev_{severity}")

    return sorted(
        {
            sanitize_jira_label(label)
            for label in labels
            if str(label or "").strip()
        }
    )


def hierarchy_node_description(node: dict[str, Any]) -> str:
    description = str(node.get("description") or "").strip()

    if description:
        return description

    context = node_context(node)
    stats = node_stats(node)

    lines = [
        "Black Duck Jira hierarchy node.",
        "",
        f"Node type: {node.get('node_type', '')}",
        f"External ID: {node_external_id(node)}",
        f"Parent external ID: {node_parent_external_id(node)}",
        "",
        "Context:",
    ]

    for key in sorted(context):
        lines.append(f"* {key}: {context.get(key, '')}")

    if stats:
        lines.extend(["", "Stats:"])

        for key in sorted(stats):
            lines.append(f"* {key}: {stats.get(key, '')}")

    return "\n".join(lines)


def hierarchy_render_context(node: dict[str, Any]) -> dict[str, Any]:
    context = dict(node_context(node))
    context.update(
        {
            "node_type": str(node.get("node_type") or ""),
            "external_id": node_external_id(node),
            "parent_external_id": node_parent_external_id(node),
            "lookup_label": node_lookup_label(node),
            "summary": str(node.get("summary") or ""),
        }
    )

    for key, value in node_stats(node).items():
        context[f"stats_{key}"] = value

    return context


def hierarchy_additional_fields_for_node(
        node: dict[str, Any],
        config: dict[str, Any],
) -> dict[str, Any]:
    hierarchy_config = config.get("hierarchy", {})
    additional_fields_by_type = hierarchy_config.get("additional_fields", {})
    node_type = str(node.get("node_type") or "")

    if not isinstance(additional_fields_by_type, dict):
        return {}

    additional_fields = additional_fields_by_type.get(node_type, {})
    if not isinstance(additional_fields, dict):
        return {}

    return render_value(additional_fields, hierarchy_render_context(node))


def hierarchy_severity_for_node(node: dict[str, Any]) -> str:
    context = node_context(node)
    severity = str(context.get("severity") or "").strip().upper()

    if severity:
        return severity

    stats = node_stats(node)

    if int(stats.get("critical_count") or 0) > 0:
        return "CRITICAL"

    if int(stats.get("high_count") or 0) > 0:
        return "HIGH"

    if int(stats.get("medium_count") or 0) > 0:
        return "MEDIUM"

    if int(stats.get("low_count") or 0) > 0:
        return "LOW"

    return ""


def hierarchy_target_status_for_node(
        node: dict[str, Any],
        config: dict[str, Any],
) -> str:
    if str(node.get("node_type") or "") != "vulnerability":
        return ""

    return configured_status_for_severity(
        hierarchy_severity_for_node(node),
        config,
    )


def build_hierarchy_issue_payload(
        node: dict[str, Any],
        config: dict[str, Any],
        description_format: str,
) -> dict[str, Any]:
    jira_config = config.get("jira", {})
    issue_config = config.get("issue", {})

    project_key = str(jira_config.get("project_key") or "").strip()
    if not project_key:
        raise RuntimeError("jira.project_key must be set in the config file")

    summary = truncate(str(node.get("summary") or node_external_id(node)), 255)
    description_text = hierarchy_node_description(node)

    fields: dict[str, Any] = {
        "project": {
            "key": project_key,
        },
        "issuetype": {
            "name": hierarchy_issue_type_for_node(node, config),
        },
        "summary": summary,
        "labels": hierarchy_labels_for_node(node, config),
    }

    if description_format == "adf":
        fields["description"] = text_to_adf_paragraphs(description_text)
    else:
        fields["description"] = description_text

    severity = hierarchy_severity_for_node(node)
    priority_by_severity = issue_config.get("priority_by_severity", {})

    if severity and isinstance(priority_by_severity, dict):
        priority_name = priority_by_severity.get(severity)
        if priority_name:
            fields["priority"] = {
                "name": str(priority_name),
            }

    fields.update(hierarchy_additional_fields_for_node(node, config))

    return {
        "fields": fields,
    }


def hierarchy_parent_mode_for_node(
        node: dict[str, Any],
        config: dict[str, Any],
) -> str:
    node_type = str(node.get("node_type") or "")
    hierarchy_config = config.get("hierarchy", {})

    if node_type == "story":
        return str(hierarchy_config.get("story_parent_mode") or "jira_parent")

    if node_type == "vulnerability":
        return str(hierarchy_config.get("vulnerability_parent_mode") or "issue_link")

    return ""


def apply_parent_to_hierarchy_payload(
        payload: dict[str, Any],
        node: dict[str, Any],
        parent_issue_key: str,
        config: dict[str, Any],
) -> None:
    mode = hierarchy_parent_mode_for_node(node, config)

    if not mode or mode == "issue_link":
        return

    fields = payload.setdefault("fields", {})

    if mode == "jira_parent":
        fields["parent"] = {
            "key": parent_issue_key,
        }
        return

    if mode == "epic_link_field":
        hierarchy_config = config.get("hierarchy", {})
        epic_link_field = str(hierarchy_config.get("epic_link_field") or "").strip()

        if not epic_link_field:
            raise RuntimeError(
                "hierarchy.epic_link_field must be set when story_parent_mode "
                "is epic_link_field"
            )

        fields[epic_link_field] = parent_issue_key
        return

    raise RuntimeError(f"Unsupported hierarchy parent mode: {mode}")


def hierarchy_node_needs_issue_link(
        node: dict[str, Any],
        config: dict[str, Any],
) -> bool:
    return hierarchy_parent_mode_for_node(node, config) == "issue_link"


def hierarchy_link_state_key(
        parent_external_id: str,
        child_external_id: str,
        issue_link_type: str,
) -> str:
    return f"{parent_external_id}->{child_external_id}:{issue_link_type}"


def state_link_exists(
        state: dict[str, Any],
        link_key: str,
) -> bool:
    links_by_key = state.setdefault("links_by_key", {})
    return isinstance(links_by_key.get(link_key), dict)


def update_state_link(
        state: dict[str, Any],
        link_key: str,
        parent_external_id: str,
        child_external_id: str,
        parent_issue_key: str,
        child_issue_key: str,
        issue_link_type: str,
        action: str,
) -> None:
    links_by_key = state.setdefault("links_by_key", {})
    previous = links_by_key.get(link_key, {})

    if not isinstance(previous, dict):
        previous = {}

    first_seen_at = previous.get("first_seen_at") or now_iso()

    links_by_key[link_key] = {
        "link_key": link_key,
        "parent_external_id": parent_external_id,
        "child_external_id": child_external_id,
        "parent_issue_key": parent_issue_key,
        "child_issue_key": child_issue_key,
        "issue_link_type": issue_link_type,
        "first_seen_at": first_seen_at,
        "last_seen_at": now_iso(),
        "last_action": action,
    }

    state["updated_at"] = now_iso()


def write_hierarchy_results_csv(path: str, rows: list[dict[str, Any]]) -> None:
    if not path:
        return

    fieldnames = [
        "action",
        "issue_key",
        "jira_status",
        "node_type",
        "external_id",
        "parent_external_id",
        "lookup_label",
        "summary",
        "parent_project",
        "parent_version",
        "subproject",
        "subproject_version",
        "component",
        "component_version",
        "vulnerability",
        "severity",
        "score",
        "message",
    ]

    with open(path, "w", newline="", encoding="utf-8") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def process_hierarchy_plan(args: argparse.Namespace) -> int:
    config = load_json_file(args.config, DEFAULT_CONFIG)
    state = load_state(args.state)

    plan = load_hierarchy_plan(args.hierarchy_plan)
    all_nodes = list(plan.get("nodes", []))
    nodes = filter_hierarchy_nodes(all_nodes, args)

    jira_config = config.get("jira", {})
    project_key = str(jira_config.get("project_key") or "").strip()

    if not project_key:
        raise RuntimeError("jira.project_key must be set in the config file")

    jira_client = build_jira_client(
        config=config,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        debug=args.debug,
    )

    dry_run = args.dry_run or not args.apply

    if not jira_client.enabled():
        dry_run = True
        print(
            "Jira URL/auth not fully configured; running in dry-run mode.",
            file=sys.stderr,
        )

    node_by_external_id = {
        node_external_id(node): node
        for node in nodes
    }

    labels_by_external_id = {
        external_id: node_lookup_label(node)
        for external_id, node in node_by_external_id.items()
    }

    missing_external_ids: list[str] = []

    for external_id in node_by_external_id:
        cached_issue = state_issue_for_external_id(state, external_id)

        if cached_issue and str(cached_issue.get("issue_key") or "") and not args.refresh_existing:
            continue

        missing_external_ids.append(external_id)

    existing_by_label: dict[str, dict[str, Any]] = {}

    if missing_external_ids and not dry_run:
        labels_to_search = sorted(
            {
                labels_by_external_id[external_id]
                for external_id in missing_external_ids
            }
        )
        existing_by_label = jira_client.search_by_labels(
            project_key=project_key,
            labels=labels_to_search,
            batch_size=args.jql_label_batch_size,
        )

    results: list[dict[str, Any]] = []
    issue_keys_by_external_id: dict[str, str] = {}

    created_count = 0
    skipped_existing_count = 0
    planned_create_count = 0
    linked_count = 0
    planned_link_count = 0
    skipped_link_count = 0
    error_count = 0

    for node in nodes:
        external_id = node_external_id(node)
        parent_external_id = node_parent_external_id(node)
        lookup_label = node_lookup_label(node)
        context = node_context(node)
        target_status = hierarchy_target_status_for_node(node, config)

        result_row: dict[str, Any] = {
            "action": "",
            "issue_key": "",
            "jira_status": "",
            "node_type": node.get("node_type", ""),
            "external_id": external_id,
            "parent_external_id": parent_external_id,
            "lookup_label": lookup_label,
            "summary": str(node.get("summary") or ""),
            "parent_project": context.get("parent_project", ""),
            "parent_version": context.get("parent_version", ""),
            "subproject": context.get("subproject", ""),
            "subproject_version": context.get("subproject_version", ""),
            "component": context.get("component", ""),
            "component_version": context.get("component_version", ""),
            "vulnerability": context.get("vulnerability", ""),
            "severity": context.get("severity", ""),
            "score": context.get("score", ""),
            "message": "",
        }

        cached_issue = state_issue_for_external_id(state, external_id)

        if cached_issue and str(cached_issue.get("issue_key") or "") and not args.refresh_existing:
            issue_key = str(cached_issue.get("issue_key") or "")
            issue_keys_by_external_id[external_id] = issue_key

            result_row["action"] = "skip_existing_state"
            result_row["issue_key"] = issue_key
            result_row["jira_status"] = str(cached_issue.get("status") or "")
            result_row["message"] = "Found in local state cache"

            skipped_existing_count += 1
            results.append(result_row)
            continue

        existing_issue = existing_by_label.get(lookup_label)

        if existing_issue:
            issue_key = str(existing_issue.get("key") or "")
            issue_keys_by_external_id[external_id] = issue_key

            result_row["action"] = "skip_existing_jira"
            result_row["issue_key"] = issue_key
            result_row["jira_status"] = str(existing_issue.get("status") or "")
            result_row["message"] = "Found in Jira by hierarchy lookup label"

            if target_status and issue_key:
                try:
                    transitioned_status = jira_client.transition_issue_to_status(
                        issue_key=issue_key,
                        target_status=target_status,
                    )
                    result_row["action"] = "updated_existing_status"
                    result_row["jira_status"] = transitioned_status
                    result_row["message"] = (
                        f"Found in Jira by hierarchy lookup label and moved to "
                        f"{transitioned_status}"
                    )
                except RuntimeError as transition_error:
                    result_row["action"] = "existing_status_error"
                    result_row["message"] = (
                        f"Found in Jira by hierarchy lookup label, but failed moving it "
                        f"to {target_status}: {transition_error}"
                    )
                    error_count += 1

            update_state_issue(
                state=state,
                external_id=external_id,
                rollup_key=node_rollup_key(node),
                rollup_label_value=lookup_label,
                issue_key=issue_key,
                status=str(result_row.get("jira_status") or ""),
                action=str(result_row.get("action") or "skip_existing_jira"),
                node_type=str(node.get("node_type") or ""),
                summary=str(node.get("summary") or ""),
            )

            skipped_existing_count += 1
            results.append(result_row)
            continue

        payload = build_hierarchy_issue_payload(
            node=node,
            config=config,
            description_format=args.description_format,
        )

        parent_issue_key = issue_keys_by_external_id.get(parent_external_id, "")

        if parent_external_id and hierarchy_parent_mode_for_node(node, config) != "issue_link":
            if not parent_issue_key:
                result_row["action"] = "error"
                result_row["message"] = (
                    f"Parent issue key not available for parent_external_id={parent_external_id}"
                )
                error_count += 1
                results.append(result_row)
                continue

            try:
                apply_parent_to_hierarchy_payload(
                    payload=payload,
                    node=node,
                    parent_issue_key=parent_issue_key,
                    config=config,
                )
            except RuntimeError as error:
                result_row["action"] = "error"
                result_row["message"] = str(error)
                error_count += 1
                results.append(result_row)
                continue

        if dry_run:
            planned_key = f"DRY-{external_id[:8].upper()}"
            issue_keys_by_external_id[external_id] = planned_key

            result_row["action"] = "would_create"
            result_row["issue_key"] = planned_key
            result_row["message"] = json.dumps(
                {
                    "summary": payload["fields"].get("summary", ""),
                    "labels": payload["fields"].get("labels", []),
                    "project": payload["fields"].get("project", {}),
                    "issuetype": payload["fields"].get("issuetype", {}),
                    "priority": payload["fields"].get("priority", {}),
                    "parent": payload["fields"].get("parent", {}),
                    "target_status": target_status,
                },
                sort_keys=True,
            )

            planned_create_count += 1
            results.append(result_row)
            continue

        if args.max_create is not None and created_count >= args.max_create:
            result_row["action"] = "skip_max_create_reached"
            result_row["message"] = f"--max-create {args.max_create} reached"
            results.append(result_row)
            continue

        try:
            created = jira_client.create_issue(payload)
            issue_key = str(created.get("key") or "")
            issue_keys_by_external_id[external_id] = issue_key

            result_row["action"] = "created"
            result_row["issue_key"] = issue_key
            result_row["jira_status"] = "created"
            result_row["message"] = f"Created Jira issue {issue_key}"

            if target_status and issue_key:
                try:
                    transitioned_status = jira_client.transition_issue_to_status(
                        issue_key=issue_key,
                        target_status=target_status,
                    )
                    result_row["jira_status"] = transitioned_status
                    result_row["message"] = (
                        f"Created Jira issue {issue_key} and moved to {transitioned_status}"
                    )
                except RuntimeError as transition_error:
                    result_row["action"] = "created_transition_error"
                    result_row["message"] = (
                        f"Created Jira issue {issue_key}, but failed moving it to "
                        f"{target_status}: {transition_error}"
                    )
                    error_count += 1

            update_state_issue(
                state=state,
                external_id=external_id,
                rollup_key=node_rollup_key(node),
                rollup_label_value=lookup_label,
                issue_key=issue_key,
                status=str(result_row.get("jira_status") or "created"),
                action=str(result_row.get("action") or "created"),
                node_type=str(node.get("node_type") or ""),
                summary=str(node.get("summary") or ""),
            )

            created_count += 1

        except RuntimeError as error:
            result_row["action"] = "error"
            result_row["message"] = str(error)
            error_count += 1

        results.append(result_row)

    hierarchy_config = config.get("hierarchy", {})
    issue_link_type = str(hierarchy_config.get("issue_link_type") or "Relates")

    for node in nodes:
        if not hierarchy_node_needs_issue_link(node, config):
            continue

        child_external_id = node_external_id(node)
        parent_external_id = node_parent_external_id(node)

        if not parent_external_id:
            continue

        parent_issue_key = issue_keys_by_external_id.get(parent_external_id, "")
        child_issue_key = issue_keys_by_external_id.get(child_external_id, "")

        context = node_context(node)
        link_key = hierarchy_link_state_key(
            parent_external_id=parent_external_id,
            child_external_id=child_external_id,
            issue_link_type=issue_link_type,
        )

        link_result_row: dict[str, Any] = {
            "action": "",
            "issue_key": child_issue_key,
            "jira_status": "",
            "node_type": node.get("node_type", ""),
            "external_id": child_external_id,
            "parent_external_id": parent_external_id,
            "lookup_label": node_lookup_label(node),
            "summary": str(node.get("summary") or ""),
            "parent_project": context.get("parent_project", ""),
            "parent_version": context.get("parent_version", ""),
            "subproject": context.get("subproject", ""),
            "subproject_version": context.get("subproject_version", ""),
            "component": context.get("component", ""),
            "component_version": context.get("component_version", ""),
            "vulnerability": context.get("vulnerability", ""),
            "severity": context.get("severity", ""),
            "score": context.get("score", ""),
            "message": "",
        }

        if not parent_issue_key or not child_issue_key:
            link_result_row["action"] = "skip_link_missing_issue_key"
            link_result_row["message"] = (
                f"Missing parent or child issue key. "
                f"parent={parent_issue_key}, child={child_issue_key}"
            )
            skipped_link_count += 1
            results.append(link_result_row)
            continue

        if state_link_exists(state, link_key) and not args.refresh_existing:
            link_result_row["action"] = "skip_link_existing_state"
            link_result_row["message"] = "Issue link found in local state cache"
            skipped_link_count += 1
            results.append(link_result_row)
            continue

        if dry_run:
            link_result_row["action"] = "would_link"
            link_result_row["message"] = (
                f"{child_issue_key} {issue_link_type} {parent_issue_key}"
            )
            planned_link_count += 1
            results.append(link_result_row)
            continue

        try:
            jira_client.create_issue_link(
                link_type=issue_link_type,
                parent_issue_key=parent_issue_key,
                child_issue_key=child_issue_key,
            )

            update_state_link(
                state=state,
                link_key=link_key,
                parent_external_id=parent_external_id,
                child_external_id=child_external_id,
                parent_issue_key=parent_issue_key,
                child_issue_key=child_issue_key,
                issue_link_type=issue_link_type,
                action="linked",
            )

            link_result_row["action"] = "linked"
            link_result_row["jira_status"] = "linked"
            link_result_row["message"] = (
                f"Linked {child_issue_key} to {parent_issue_key} using {issue_link_type}"
            )
            linked_count += 1

        except RuntimeError as error:
            link_result_row["action"] = "error"
            link_result_row["message"] = str(error)
            error_count += 1

        results.append(link_result_row)

    if args.plan_out:
        planned_payload = {
            "generated_at": now_iso(),
            "dry_run": dry_run,
            "hierarchy_plan": args.hierarchy_plan,
            "input_node_count": len(all_nodes),
            "processed_node_count": len(nodes),
            "results": results,
        }
        save_json_file(args.plan_out, planned_payload)

    if args.results_out:
        write_hierarchy_results_csv(args.results_out, results)

    if not dry_run:
        save_json_file(args.state, state)

    node_type_counts = {
        "epic": sum(1 for node in nodes if node.get("node_type") == "epic"),
        "story": sum(1 for node in nodes if node.get("node_type") == "story"),
        "vulnerability": sum(1 for node in nodes if node.get("node_type") == "vulnerability"),
    }

    print()
    print("Jira hierarchy publish summary")
    print("==============================")
    print(f"Hierarchy plan:          {args.hierarchy_plan}")
    print(f"Input nodes:             {len(all_nodes)}")
    print(f"Processed nodes:         {len(nodes)}")
    print(f"Epic nodes:              {node_type_counts['epic']}")
    print(f"Story nodes:             {node_type_counts['story']}")
    print(f"Vulnerability nodes:     {node_type_counts['vulnerability']}")
    print(f"Dry run:                 {dry_run}")
    print(f"Would create:            {planned_create_count}")
    print(f"Created:                 {created_count}")
    print(f"Skipped existing:        {skipped_existing_count}")
    print(f"Would link:              {planned_link_count}")
    print(f"Linked:                  {linked_count}")
    print(f"Skipped links:           {skipped_link_count}")
    print(f"Errors:                  {error_count}")

    if args.results_out:
        print(f"Results CSV:             {args.results_out}")

    if args.plan_out:
        print(f"Plan JSON:               {args.plan_out}")

    if dry_run:
        print()
        print("No Jira issues or links were created. Add --apply when ready.")

    return 1 if error_count else 0


def process_findings(args: argparse.Namespace) -> int:
    config = load_json_file(args.config, DEFAULT_CONFIG)
    state = load_state(args.state)

    findings = read_findings(args.findings)

    if args.only_parent_project:
        findings = [
            finding
            for finding in findings
            if finding["parent_project"] == args.only_parent_project
        ]

    if args.only_parent_version:
        findings = [
            finding
            for finding in findings
            if finding["parent_version"] == args.only_parent_version
        ]

    if args.only_subproject:
        findings = [
            finding
            for finding in findings
            if finding["subproject"] == args.only_subproject
        ]

    if args.only_vulnerability:
        findings = [
            finding
            for finding in findings
            if finding["vulnerability"] == args.only_vulnerability
        ]

    if args.only_rollup_key:
        rollup_key_filter = str(args.only_rollup_key).strip()
        findings_before_filter = len(findings)

        findings = [
            finding
            for finding in findings
            if finding["rollup_key"] == rollup_key_filter
        ]

        if not findings:
            raise RuntimeError(
                f"No findings matched --only-rollup-key {json.dumps(rollup_key_filter)} "
                f"in {args.findings}. Searched {findings_before_filter} finding(s) "
                "after prior filters."
            )

    if args.only_rollup_key_hash:
        rollup_key_hash_filter = validate_rollup_key_hash(args.only_rollup_key_hash)
        findings_before_filter = len(findings)

        findings = [
            finding
            for finding in findings
            if rollup_external_id(finding["rollup_key"]).lower() == rollup_key_hash_filter
        ]

        if not findings:
            raise RuntimeError(
                f"No findings matched --only-rollup-key-hash "
                f"{json.dumps(rollup_key_hash_filter)} in {args.findings}. "
                f"Searched {findings_before_filter} finding(s) after prior filters. "
                "This usually means the Jira issue was created from a different/older "
                "findings.csv, or the hash was copied from a different rollup."
            )

    if args.limit is not None:
        findings = findings[: args.limit]

    jira_config = config.get("jira", {})
    project_key = str(jira_config.get("project_key") or "").strip()

    if not project_key:
        raise RuntimeError("jira.project_key must be set in the config file")

    jira_client = build_jira_client(
        config=config,
        timeout=args.timeout,
        retries=args.retries,
        retry_delay=args.retry_delay,
        debug=args.debug,
    )

    dry_run = args.dry_run or not args.apply

    if not jira_client.enabled():
        dry_run = True
        print(
            "Jira URL/auth not fully configured; running in dry-run mode.",
            file=sys.stderr,
        )

    labels_by_external_id: dict[str, str] = {}
    findings_by_external_id: dict[str, dict[str, str]] = {}
    payloads_by_external_id: dict[str, dict[str, Any]] = {}

    for finding in findings:
        context = finding_context(finding, config)
        external_id = str(context["rollup_external_id"])
        label = str(context["rollup_label"])

        payload, _ = build_issue_payload(
            finding=finding,
            config=config,
            description_format=args.description_format,
            timeout=args.timeout,
            debug=args.debug,
        )

        labels_by_external_id[external_id] = label
        findings_by_external_id[external_id] = finding
        payloads_by_external_id[external_id] = payload

    missing_external_ids: list[str] = []

    for external_id in findings_by_external_id:
        cached_issue = state_issue_for_external_id(state, external_id)

        if cached_issue and not args.refresh_existing:
            continue

        missing_external_ids.append(external_id)

    existing_by_label: dict[str, dict[str, Any]] = {}

    if missing_external_ids and not dry_run:
        labels_to_search = [labels_by_external_id[external_id] for external_id in missing_external_ids]
        existing_by_label = jira_client.search_by_labels(
            project_key=project_key,
            labels=labels_to_search,
            batch_size=args.jql_label_batch_size,
        )

    results: list[dict[str, Any]] = []
    created_count = 0
    skipped_existing_count = 0
    planned_create_count = 0
    error_count = 0

    for external_id, finding in findings_by_external_id.items():
        label = labels_by_external_id[external_id]
        payload = payloads_by_external_id[external_id]
        target_status = configured_status_for_severity(finding["severity"], config)

        result_row = {
            **finding,
            "rollup_label": label,
            "issue_key": "",
            "jira_status": "",
            "action": "",
            "message": "",
        }

        cached_issue = state_issue_for_external_id(state, external_id)

        if cached_issue and not args.refresh_existing:
            result_row["action"] = "skip_existing_state"
            result_row["issue_key"] = cached_issue.get("issue_key", "")
            result_row["jira_status"] = cached_issue.get("status", "")
            result_row["message"] = "Found in local state cache"
            skipped_existing_count += 1
            results.append(result_row)
            continue

        existing_issue = existing_by_label.get(label)

        if existing_issue:
            issue_key = str(existing_issue.get("key", ""))

            result_row["action"] = "skip_existing_jira"
            result_row["issue_key"] = issue_key
            result_row["jira_status"] = existing_issue.get("status", "")
            result_row["message"] = "Found in Jira by rollup label"

            if target_status and issue_key:
                try:
                    transitioned_status = jira_client.transition_issue_to_status(
                        issue_key=issue_key,
                        target_status=target_status,
                    )
                    result_row["action"] = "updated_existing_status"
                    result_row["jira_status"] = transitioned_status
                    result_row["message"] = (
                        f"Found in Jira by rollup label and moved to {transitioned_status}"
                    )
                except RuntimeError as transition_error:
                    result_row["action"] = "existing_status_error"
                    result_row["message"] = (
                        f"Found in Jira by rollup label, but failed moving it to "
                        f"{target_status}: {transition_error}"
                    )
                    error_count += 1

            update_state_issue(
                state=state,
                external_id=external_id,
                rollup_key=finding["rollup_key"],
                rollup_label_value=label,
                issue_key=issue_key,
                status=str(result_row.get("jira_status") or ""),
                action=str(result_row.get("action") or "skip_existing_jira"),
            )

            skipped_existing_count += 1
            results.append(result_row)
            continue

        if dry_run:
            result_row["action"] = "would_create"
            result_row["message"] = json.dumps(
                {
                    "summary": payload["fields"].get("summary", ""),
                    "labels": payload["fields"].get("labels", []),
                    "project": payload["fields"].get("project", {}),
                    "issuetype": payload["fields"].get("issuetype", {}),
                    "priority": payload["fields"].get("priority", {}),
                    "target_status": target_status,
                },
                sort_keys=True,
            )
            planned_create_count += 1
            results.append(result_row)
            continue

        if args.max_create is not None and created_count >= args.max_create:
            result_row["action"] = "skip_max_create_reached"
            result_row["message"] = f"--max-create {args.max_create} reached"
            results.append(result_row)
            continue

        try:
            created = jira_client.create_issue(payload)
            issue_key = str(created.get("key") or "")

            result_row["action"] = "created"
            result_row["issue_key"] = issue_key
            result_row["jira_status"] = "created"
            result_row["message"] = f"Created Jira issue {issue_key}"

            if target_status and issue_key:
                try:
                    transitioned_status = jira_client.transition_issue_to_status(
                        issue_key=issue_key,
                        target_status=target_status,
                    )
                    result_row["jira_status"] = transitioned_status
                    result_row["message"] = (
                        f"Created Jira issue {issue_key} and moved to {transitioned_status}"
                    )
                except RuntimeError as transition_error:
                    result_row["action"] = "created_transition_error"
                    result_row["message"] = (
                        f"Created Jira issue {issue_key}, but failed moving it to "
                        f"{target_status}: {transition_error}"
                    )
                    error_count += 1

            update_state_issue(
                state=state,
                external_id=external_id,
                rollup_key=finding["rollup_key"],
                rollup_label_value=label,
                issue_key=issue_key,
                status=str(result_row.get("jira_status") or "created"),
                action=str(result_row.get("action") or "created"),
            )

            created_count += 1

        except RuntimeError as error:
            result_row["action"] = "error"
            result_row["message"] = str(error)
            error_count += 1

        results.append(result_row)

    if args.plan_out:
        planned_payload = {
            "generated_at": now_iso(),
            "dry_run": dry_run,
            "finding_count": len(findings_by_external_id),
            "results": results,
        }
        save_json_file(args.plan_out, planned_payload)

    if args.results_out:
        write_results_csv(args.results_out, results)

    if not dry_run:
        save_json_file(args.state, state)

    print()
    print("Jira rollup publish summary")
    print("===========================")
    print(f"Input findings:          {len(findings)}")
    print(f"Unique rollup findings:  {len(findings_by_external_id)}")
    print(f"Dry run:                 {dry_run}")
    print(f"Would create:            {planned_create_count}")
    print(f"Created:                 {created_count}")
    print(f"Skipped existing:        {skipped_existing_count}")
    print(f"Errors:                  {error_count}")

    if args.results_out:
        print(f"Results CSV:             {args.results_out}")

    if args.plan_out:
        print(f"Plan JSON:               {args.plan_out}")

    if dry_run:
        print()
        print("No Jira issues were created. Add --apply when ready.")

    return 1 if error_count else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create Jira issues from Black Duck subproject vulnerability rollup findings "
            "or from a generated hierarchy plan."
        )
    )

    parser.add_argument(
        "--findings",
        default="findings.csv",
        help="Input findings CSV from subp_vuln_rollup.py. Default: findings.csv.",
    )
    parser.add_argument(
        "--hierarchy-plan",
        help=(
            "Optional hierarchy plan JSON from findings_hierarchy_plan.py. "
            "When supplied, this script publishes Epic/Story/Vulnerability nodes instead "
            "of flat findings."
        ),
    )
    parser.add_argument(
        "--config",
        default="jira-rollup-config.json",
        help="Jira publisher config JSON. Default: jira-rollup-config.json.",
    )
    parser.add_argument(
        "--state",
        default="jira-rollup-state.json",
        help="Local state/cache file for issue dedupe. Default: jira-rollup-state.json.",
    )
    parser.add_argument(
        "--results-out",
        default="jira-rollup-results.csv",
        help="CSV report of actions taken. Default: jira-rollup-results.csv.",
    )
    parser.add_argument(
        "--plan-out",
        default="jira-rollup-plan.json",
        help="JSON dry-run/create plan output. Default: jira-rollup-plan.json.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually create Jira issues. Without this flag, the script is dry-run only.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force dry-run mode even if --apply is passed.",
    )
    parser.add_argument(
        "--description-format",
        choices=["wiki", "adf"],
        default="wiki",
        help="Jira description format. Use adf for Jira Cloud API v3 if needed. Default: wiki.",
    )
    parser.add_argument(
        "--refresh-existing",
        action="store_true",
        help="Query Jira even for findings already present in local state.",
    )
    parser.add_argument(
        "--jql-label-batch-size",
        type=int,
        default=50,
        help="How many rollup labels to include in each Jira search batch. Default: 50.",
    )
    parser.add_argument(
        "--max-create",
        type=int,
        help="Safety limit for the number of Jira issues to create in this run.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of input findings or hierarchy nodes processed. Useful for POC testing.",
    )
    parser.add_argument(
        "--only-parent_project",
        dest="only_parent_project",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--only-parent-project",
        help="Only process findings or hierarchy nodes for this parent project.",
    )
    parser.add_argument(
        "--only-parent-version",
        help="Only process findings or hierarchy nodes for this parent version.",
    )
    parser.add_argument(
        "--only-subproject",
        help="Only process findings or hierarchy nodes for this subproject.",
    )
    parser.add_argument(
        "--only-vulnerability",
        help="Only process findings or hierarchy nodes for this vulnerability ID.",
    )
    parser.add_argument(
        "--only-rollup-key",
        help="Only process one exact raw pipe-delimited rollup_key.",
    )
    parser.add_argument(
        "--only-rollup-key-hash",
        help=(
            "Only process one finding by full SHA-256 hash of the rollup_key. "
            "This is the value shown as Rollup key hash / Black Duck Rollup ID."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout seconds. Default: 30.",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry count for transient Jira/AI failures. Default: 2.",
    )
    parser.add_argument(
        "--retry-delay",
        type=float,
        default=2.0,
        help="Base retry delay seconds. Default: 2.0.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debug output to stderr.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        if args.hierarchy_plan:
            return process_hierarchy_plan(args)

        return process_findings(args)
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())