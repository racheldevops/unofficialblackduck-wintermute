from __future__ import annotations

import copy
import re
from urllib.parse import quote


TEXT_FIELD = "com.atlassian.jira.plugin.system.customfieldtypes:textfield"


def metadata_items(client, path, collection_keys):
    """Read Jira Cloud/Data Center paginated creation metadata."""
    result = []
    offset = 0
    seen_pages = set()

    for _ in range(1000):
        payload = client.request_json(
            "GET",
            path,
            query={"startAt": offset, "maxResults": 100},
            expected_statuses={200},
        )
        if not isinstance(payload, dict):
            raise RuntimeError("Jira creation metadata must be an object")

        keys = [key for key in collection_keys if key in payload]
        if len(keys) != 1:
            raise RuntimeError("Unrecognized Jira creation metadata collection")
        page = payload[keys[0]]
        if not isinstance(page, list) or not all(
            isinstance(item, dict) for item in page
        ):
            raise RuntimeError("Invalid Jira creation metadata items")

        returned = payload.get("startAt", offset)
        if type(returned) is not int or returned != offset:
            raise RuntimeError("Jira metadata pagination offset mismatch")

        total = payload.get("total")
        if total is not None and (type(total) is not int or total < 0):
            raise RuntimeError("Invalid Jira metadata total")
        is_last = payload.get("isLast")
        if is_last is not None and type(is_last) is not bool:
            raise RuntimeError("Invalid Jira metadata isLast")

        if not page:
            if is_last is False or (total is not None and offset < total):
                raise RuntimeError("Jira metadata pagination ended early")
            return result

        signature = tuple(
            str(item.get("fieldId") or item.get("id") or item.get("key"))
            for item in page
        )
        if signature in seen_pages:
            raise RuntimeError("Jira metadata pagination repeated a page")
        seen_pages.add(signature)

        result.extend(page)
        offset += len(page)
        if total is not None and offset > total:
            raise RuntimeError("Jira metadata exceeds reported total")
        if is_last is True:
            if total is not None and offset < total:
                raise RuntimeError("Jira metadata reported an early final page")
            return result
        if total is not None and offset == total:
            if is_last is False:
                raise RuntimeError("Jira metadata pagination is inconsistent")
            return result

    raise RuntimeError("Jira metadata pagination limit exceeded")


def resolve_entity_mapping(client, config, nodes, deployment):
    """Resolve once per publish run; never modify the caller's config."""
    from wintermute.jira import findings_to_jira as publisher

    prepared = copy.deepcopy(config)
    tasks = [node for node in nodes if node.get("node_type") == "story"]
    if not tasks:
        return prepared

    mappings = prepared.setdefault("hierarchy", {}).setdefault("field_mappings", {})
    raw = mappings.get("entity", {})
    if isinstance(raw, str):
        mapping = {"field_id": raw}
    elif isinstance(raw, dict):
        mapping = dict(raw)
    else:
        raise RuntimeError("Entity mapping must be an object or field ID")

    configured_id = str(mapping.get("field_id") or "").strip()
    wanted_name = str(mapping.get("field_name") or "Entity").strip()

    if configured_id and re.fullmatch(r"customfield_[0-9]+", configured_id) is None:
        raise RuntimeError("Invalid configured Jira Entity field ID")
    if mapping.get("source", "entity") not in {"entity", "context.entity"}:
        raise RuntimeError("Entity mapping must use the product entity source")
    if mapping.get("value_type", "text") != "text":
        raise RuntimeError("Entity discovery currently supports text mappings only")

    mapping.update(source="entity", node_types=["story"], value_type="text")

    if not deployment:
        if not configured_id:
            raise RuntimeError(
                "Automatic Entity discovery requires Jira URL/authentication, "
                "including for dry-run. Offline rendering requires an explicit field ID."
            )
        mapping["field_id"] = configured_id
        mappings["entity"] = mapping
        return prepared

    if deployment not in {"cloud", "datacenter"}:
        raise RuntimeError("Unsupported Jira deployment for Entity discovery")

    project = str(prepared["jira"]["project_key"]).strip()
    version = "3" if deployment == "cloud" else "2"
    root = (
        f"/rest/api/{version}/issue/createmeta/"
        f"{quote(project, safe='')}/issuetypes"
    )
    types = metadata_items(client, root, ("issueTypes", "values"))
    names = {
        publisher.hierarchy_issue_type_for_node(node, prepared)
        for node in tasks
    }
    resolved_ids = set()

    for type_name in sorted(names):
        matching_types = [item for item in types if item.get("name") == type_name]
        if len(matching_types) != 1 or not matching_types[0].get("id"):
            raise RuntimeError(
                f"Jira project {project}: issue type {type_name!r} "
                "is unavailable or ambiguous"
            )

        type_id = str(matching_types[0]["id"])
        descriptors = metadata_items(
            client, f"{root}/{quote(type_id, safe='')}", ("fields", "values")
        )
        field_map = {}
        for descriptor in descriptors:
            field_id = descriptor.get("fieldId") or descriptor.get("key")
            if not isinstance(field_id, str) or not field_id or field_id in field_map:
                raise RuntimeError("Invalid or duplicate Jira metadata field identity")
            field_map[field_id] = descriptor

        if configured_id:
            matches = (
                [(configured_id, field_map[configured_id])]
                if configured_id in field_map else []
            )
        else:
            matches = [
                (field_id, descriptor)
                for field_id, descriptor in field_map.items()
                if re.fullmatch(r"customfield_[0-9]+", field_id)
                and str(descriptor.get("name", "")).strip().casefold()
                == wanted_name.casefold()
            ]

        if len(matches) != 1:
            candidates = ", ".join(field_id for field_id, _ in matches)
            raise RuntimeError(
                f"Jira {project}/{type_name}: expected one available Entity field "
                f"({configured_id or wanted_name!r}); found {len(matches)}"
                + (f": {candidates}" if candidates else "")
                + ". Check field context/screens or configure an explicit field ID."
            )

        field_id, descriptor = matches[0]
        schema = descriptor.get("schema") or {}
        if schema.get("type") != "string" or schema.get("custom") != TEXT_FIELD:
            raise RuntimeError(
                f"Jira Entity field {field_id} is not a single-line text field. "
                "No issues were created by Entity discovery."
            )
        operations = descriptor.get("operations")
        if operations is not None and (
            not isinstance(operations, list) or "set" not in operations
        ):
            raise RuntimeError(f"Jira Entity field {field_id} cannot be set")

        resolved_ids.add(field_id)

    if len(resolved_ids) != 1:
        raise RuntimeError("Product Task issue types resolve to different Entity fields")

    mapping["field_id"] = resolved_ids.pop()
    mappings["entity"] = mapping
    print(
        f"Jira Entity mapping: {project} / {', '.join(sorted(names))} "
        f"-> {mapping['field_id']}",
        flush=True,
    )
    return prepared
