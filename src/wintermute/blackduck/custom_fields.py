from __future__ import annotations

import threading
from typing import Any
from urllib.parse import urlsplit

from wintermute.blackduck.lineage import (
    project_href_from_version_href,
)
from wintermute.blackduck.models import CollectionTarget
from wintermute.blackduck.resources import (
    canonical_href,
    get_link,
)
from wintermute.concurrency import SingleFlight


OPTION_TYPES = {"DROPDOWN", "RADIO", "MULTISELECT"}


def custom_field_value_text(value: Any) -> str:
    if value in (None, ""):
        return ""

    if isinstance(value, bool):
        return str(value).lower()

    if isinstance(value, (str, int, float)):
        return str(value).strip()

    if isinstance(value, list):
        values = {
            custom_field_value_text(item)
            for item in value
        }
        return ";".join(
            sorted(item for item in values if item)
        )

    if isinstance(value, dict):
        for key in (
            "displayValue",
            "displayName",
            "value",
            "label",
            "name",
        ):
            if key in value:
                rendered = custom_field_value_text(
                    value[key]
                )

                if rendered:
                    return rendered

        values = {
            custom_field_value_text(item)
            for item in value.values()
        }
        return ";".join(
            sorted(item for item in values if item)
        )

    return str(value).strip()


def custom_field_candidate_name(
    item: dict[str, Any],
) -> str:
    for key in (
        "fieldName",
        "customFieldName",
        "name",
        "label",
        "displayName",
    ):
        value = item.get(key)

        if value not in (None, "") and not isinstance(
            value,
            (dict, list),
        ):
            return str(value).strip()

    for key in (
        "customField",
        "field",
        "definition",
        "customFieldDefinition",
    ):
        nested = item.get(key)

        if not isinstance(nested, dict):
            continue

        name = custom_field_candidate_name(nested)

        if name:
            return name

    return ""


def custom_field_candidate_value(
    item: dict[str, Any],
) -> str:
    for key in (
        "values",
        "value",
        "fieldValue",
        "customFieldValue",
        "selectedValues",
        "selectedValue",
        "displayValue",
    ):
        if key not in item:
            continue

        rendered = custom_field_value_text(
            item[key]
        )

        if rendered:
            return rendered

    return ""


def find_named_custom_field(
    value: Any,
    field_name: str,
) -> tuple[bool, str]:
    wanted = str(field_name or "").strip().casefold()

    if not wanted:
        return False, ""

    if isinstance(value, dict):
        candidate_name = custom_field_candidate_name(
            value
        )

        if candidate_name.casefold() == wanted:
            return (
                True,
                custom_field_candidate_value(value),
            )

        for key, item in value.items():
            if str(key).strip().casefold() == wanted:
                return (
                    True,
                    custom_field_value_text(item),
                )

        for item in value.values():
            found, rendered = find_named_custom_field(
                item,
                field_name,
            )

            if found:
                return found, rendered

    elif isinstance(value, list):
        for item in value:
            found, rendered = find_named_custom_field(
                item,
                field_name,
            )

            if found:
                return found, rendered

    return False, ""


def _option_href(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    path = urlsplit(value).path
    return (
        path.startswith("/api/custom-fields/objects/")
        and "/options/" in path
    )


def _same_instance_option_url(
    client: Any,
    value: Any,
) -> str:
    if not isinstance(value, str):
        return ""

    base = urlsplit(
        str(getattr(client, "base_url", "")).rstrip("/")
    )
    candidate = urlsplit(value)

    if (
        base.scheme not in {"https", "http"}
        or candidate.scheme != base.scheme
        or candidate.netloc != base.netloc
        or candidate.username is not None
        or candidate.password is not None
        or candidate.query
        or candidate.fragment
        or not candidate.path.startswith(
            "/api/custom-fields/objects/"
        )
        or any(ord(character) < 32 for character in value)
    ):
        return ""

    return canonical_href(value)


def resolved_field_value(
    client: Any,
    field: dict[str, Any],
) -> str:
    field_type = str(
        field.get("type") or ""
    ).strip().upper()
    raw = field.get(
        "values",
        field.get("value"),
    )

    if raw in (None, "", []):
        return ""

    if field_type not in OPTION_TYPES:
        rendered = custom_field_candidate_value(field)

        if any(
            _option_href(part)
            for part in rendered.split(";")
        ):
            return ""

        return rendered

    if not isinstance(raw, list) or not all(
        isinstance(value, str) and value.strip()
        for value in raw
    ):
        return ""

    selected = [
        _same_instance_option_url(client, value)
        for value in raw
    ]

    if not all(
        value and _option_href(value)
        for value in selected
    ):
        return ""

    metadata = field.get("_meta")
    links = (
        metadata.get("links")
        if isinstance(metadata, dict)
        else None
    )
    links = links if isinstance(links, list) else []
    option_lists = [
        _same_instance_option_url(
            client,
            link.get("href"),
        )
        for link in links
        if isinstance(link, dict)
        and link.get("rel") == "custom-field-option-list"
    ]
    option_lists = [
        value for value in option_lists if value
    ]

    if len(option_lists) != 1:
        return ""

    try:
        options = client.paged_get(option_lists[0])
    except RuntimeError:
        return ""

    if not isinstance(options, list):
        return ""

    labels: list[str] = []

    for selected_href in selected:
        matches = [
            option
            for option in options
            if isinstance(option, dict)
            and isinstance(option.get("_meta"), dict)
            and _same_instance_option_url(
                client,
                option["_meta"].get("href"),
            ) == selected_href
        ]

        if len(matches) != 1:
            return ""

        option = matches[0]
        label = next(
            (
                option[key].strip()
                for key in (
                    "label",
                    "displayValue",
                    "displayName",
                    "value",
                    "name",
                )
                if isinstance(option.get(key), str)
                and option[key].strip()
            ),
            "",
        )

        if (
            not label
            or _option_href(label)
            or urlsplit(label).scheme
        ):
            return ""

        labels.append(label)

    return ";".join(sorted(set(labels)))


def find_named_custom_field_resolved(
    client: Any,
    fields: Any,
    field_name: str,
) -> tuple[bool, str]:
    wanted = str(
        field_name or ""
    ).strip().casefold()

    if not wanted:
        return False, ""

    if isinstance(fields, list):
        matches = [
            field
            for field in fields
            if isinstance(field, dict)
            and custom_field_candidate_name(
                field
            ).casefold() == wanted
        ]

        if len(matches) > 1:
            raise RuntimeError(
                f"Ambiguous custom field: {field_name}"
            )

        if matches:
            return True, resolved_field_value(
                client,
                matches[0],
            )

        return False, ""

    found, rendered = find_named_custom_field(
        fields,
        field_name,
    )

    if found and _option_href(rendered):
        return True, ""

    return found, rendered


class ProjectCustomFieldResolver:
    def __init__(self, field_name: str) -> None:
        self.field_name = str(
            field_name or ""
        ).strip()
        self._lock = threading.RLock()
        self._cache: dict[str, str] = {}
        self._singleflight: SingleFlight[
            str,
            str,
        ] = SingleFlight()

    def __call__(
        self,
        client: Any,
        target: CollectionTarget,
    ) -> str:
        if not self.field_name:
            return ""

        project_version = target.project_version
        project_href = (
            project_version.project_href
            or project_href_from_version_href(
                project_version.version_href
            )
        )
        project_href = canonical_href(project_href)

        if not project_href:
            return ""

        cache_key = (
            f"{project_href}|"
            f"{self.field_name.casefold()}"
        )

        with self._lock:
            if cache_key in self._cache:
                return self._cache[cache_key]

        def load() -> str:
            with self._lock:
                if cache_key in self._cache:
                    return self._cache[cache_key]

            value = self._load_value(
                client,
                project_href,
                project_version.version_href,
            )

            with self._lock:
                self._cache[cache_key] = value

            return value

        return self._singleflight.run(
            cache_key,
            load,
        )

    def _load_value(
        self,
        client: Any,
        project_href: str,
        version_href: str,
    ) -> str:
        try:
            project = client.get(project_href)
        except RuntimeError:
            return ""

        version: dict[str, Any] = {}

        if version_href:
            try:
                version = client.get(version_href)
            except RuntimeError:
                version = {}

        for resource in (project, version):
            found, rendered = find_named_custom_field(
                resource,
                self.field_name,
            )

            if found and rendered and not _option_href(
                rendered
            ):
                return rendered

        linked_url = get_link(
            project,
            (
                "custom-fields",
                "customFields",
                "custom-field-values",
                "customFieldValues",
            ),
        )
        candidate_urls = [
            value
            for value in (
                linked_url,
                f"{project_href}/custom-fields",
            )
            if value
        ]

        for url in dict.fromkeys(candidate_urls):
            try:
                fields = client.paged_get(url)
            except RuntimeError:
                continue

            found, rendered = (
                find_named_custom_field_resolved(
                    client,
                    fields,
                    self.field_name,
                )
            )

            if found:
                return rendered

        return ""
