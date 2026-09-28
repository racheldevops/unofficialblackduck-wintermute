from __future__ import annotations

import copy
import json
import os
import uuid
from pathlib import Path
from urllib.parse import quote

from wintermute.jira import findings_to_jira as publisher
from wintermute.jira.lookup_identity import own_lookup_labels, search_by_labels


def save(path: Path, payload) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def mutate(client, operation):
    retries = client.retries
    client.retries = 0
    try:
        return operation()
    finally:
        client.retries = retries


def validate_nodes(nodes):
    identities = {}
    labels = set()
    for node in nodes:
        external_id = node.get("external_id")
        label = node.get("lookup_label")
        if not isinstance(external_id, str) or not external_id:
            raise RuntimeError("Hierarchy node has no external identity")
        if not isinstance(label, str) or not label:
            raise RuntimeError("Hierarchy node has no lookup label")
        if external_id in identities or label in labels:
            raise RuntimeError("Hierarchy contains duplicate identities")
        if node.get("node_type") not in {"epic", "story"}:
            raise RuntimeError("Product hierarchy permits only Epics and Tasks")
        identities[external_id] = node
        labels.add(label)
    for node in nodes:
        parent_id = node.get("parent_external_id")
        if node["node_type"] == "epic":
            if parent_id:
                raise RuntimeError("Product Epic must not have a parent")
        elif (
            parent_id not in identities
            or identities[parent_id]["node_type"] != "epic"
        ):
            raise RuntimeError("Product Task must reference a planned Epic")


def read_existing(client, project, node, key, config):
    epic_field = str(config["hierarchy"].get("epic_link_field") or "")
    fields_requested = "project,issuetype,labels,parent,status"
    if epic_field:
        fields_requested += "," + epic_field
    issue = client.request_json(
        "GET",
        f"/rest/api/2/issue/{quote(key, safe='')}",
        query={"fields": fields_requested},
        expected_statuses={200},
    )
    fields = issue.get("fields") if isinstance(issue, dict) else None
    if not isinstance(fields, dict):
        raise RuntimeError(f"Jira issue {key} returned no fields")
    project_field = fields.get("project")
    issue_type = fields.get("issuetype")
    issue_labels = fields.get("labels")
    if not isinstance(project_field, dict) or project_field.get("key") != project:
        raise RuntimeError(f"Jira issue {key} belongs to another project")
    if not isinstance(issue_labels, list) or not all(
        isinstance(label, str) for label in issue_labels
    ):
        raise RuntimeError(f"Jira issue {key} has invalid labels")
    if node["lookup_label"] not in own_lookup_labels(issue_labels):
        raise RuntimeError(f"Jira issue {key} does not own the expected identity")
    if (
        not isinstance(issue_type, dict)
        or issue_type.get("name") != publisher.hierarchy_issue_type_for_node(node, config)
        or issue_type.get("subtask") is True
    ):
        raise RuntimeError(f"Jira issue {key} has an unexpected issue type")
    return fields


def publish(args, config, nodes, state_path, run_dir, legacy_labels, settings):
    validate_nodes(nodes)
    state_path = Path(state_path)
    run_dir = Path(run_dir)
    apply = bool(args.apply and not args.dry_run)
    if apply and (type(args.max_create) is not int or args.max_create < 1):
        raise RuntimeError("Product apply requires a positive --max-create")

    client = publisher.build_jira_client(
        config, args.timeout, args.retries, args.retry_delay, args.debug
    )
    if apply and not client.enabled():
        raise RuntimeError("Jira URL and authentication are required for apply")

    prepared = copy.deepcopy(config)
    prepared["hierarchy"].setdefault("summary_templates", {}).update({
        "epic": "",
        "story": "",
    })
    project = str(prepared["jira"]["project_key"]).strip()
    if not project:
        raise RuntimeError("jira.project_key is required")
    remote_lookup = bool(client.enabled())
    deployment = publisher.detect_jira_deployment(client) if remote_lookup else ""
    if deployment:
        client.api_version = "3" if deployment == "cloud" else "2"
        prepared["jira"]["api_version"] = client.api_version
    description_format = (
        "wiki" if deployment == "datacenter"
        else "adf" if str(client.api_version) == "3"
        else args.description_format
    )

    from wintermute.jira.entity_mapping import resolve_entity_mapping

    prepared = resolve_entity_mapping(client, prepared, nodes, deployment)
    save(run_dir / "jira-entity-mapping.json", {
        "project_key": project,
        "deployment": deployment,
        "remote_validation_performed": remote_lookup,
        "mapping": prepared["hierarchy"].get("field_mappings", {}).get("entity"),
    })
    if prepared["hierarchy"].get("story_parent_mode") not in {
        "jira_parent", "epic_link_field"
    }:
        raise RuntimeError("Product Tasks require actual Epic membership")
    if deployment:
        prepared = publisher.prepare_datacenter_hierarchy(
            client, prepared, nodes, description_format
        )

    state = publisher.load_state(str(state_path))
    destination = {"url": client.base_url, "project_key": project}
    stored_destination = state.get("product_reporting_destination")
    if remote_lookup and stored_destination is not None and stored_destination != destination:
        raise RuntimeError("Product state belongs to another Jira destination")

    pending = state.setdefault("product_pending_creates", {})
    if not isinstance(pending, dict) or not all(
        isinstance(key, str) and isinstance(value, dict)
        and isinstance(value.get("lookup_label"), str)
        and value["lookup_label"]
        for key, value in pending.items()
    ):
        raise RuntimeError("Invalid product_pending_creates state")

    labels = [node["lookup_label"] for node in nodes]
    found = (
        search_by_labels(client, deployment, project, labels)
        if remote_lookup and labels else {}
    )
    remote_legacy = (
        search_by_labels(client, deployment, project, legacy_labels)
        if remote_lookup and legacy_labels else {}
    )
    legacy_set = set(legacy_labels)
    local_legacy = {
        external_id: value
        for external_id, value in state["issues_by_external_id"].items()
        if isinstance(value, dict)
        and value.get("rollup_label") in legacy_set
    }
    migration = {
        "automatic_migration": False,
        "coexistence_allowed": settings["allow_task_identity_migration"],
        "remote_lookup_performed": remote_lookup,
        "legacy_tasks_in_state": local_legacy,
        "legacy_tasks_in_jira": remote_legacy,
    }
    save(run_dir / "product-identity-review.json", migration)

    if apply and (local_legacy or remote_legacy) and not settings[
        "allow_task_identity_migration"
    ]:
        raise RuntimeError(
            "Legacy child Tasks exist. Review product-identity-review.json. "
            "allow_task_identity_migration permits coexistence, not automatic migration."
        )

    payloads = {}
    for node in nodes:
        payload = publisher.build_hierarchy_issue_payload(
            node, prepared, description_format
        )
        fields = payload["fields"]
        if fields.get("project") != {"key": project}:
            raise RuntimeError("Additional fields override the planned Jira project")
        if fields.get("issuetype") != {
            "name": publisher.hierarchy_issue_type_for_node(node, prepared)
        }:
            raise RuntimeError("Additional fields override the planned issue type")
        issue_labels = fields.get("labels")
        if not isinstance(issue_labels, list) or not all(
            isinstance(label, str) for label in issue_labels
        ):
            raise RuntimeError("Payload labels are invalid")
        if node["lookup_label"] not in own_lookup_labels(issue_labels):
            raise RuntimeError("Payload does not own the planned identity")
        if fields.get("summary") != node["summary"]:
            raise RuntimeError("Additional fields override the product summary")
        if node["parent_external_id"]:
            validation = copy.deepcopy(payload)
            publisher.apply_parent_to_hierarchy_payload(
                validation, node, "PREFLIGHT-1", prepared
            )
        payloads[node["external_id"]] = payload

    keys = {}
    remote_fields = {}
    results = []
    created_count = 0

    def checkpoint_results():
        save(run_dir / "jira-rollup-plan.json", {
            "dry_run": not apply,
            "remote_lookup_performed": remote_lookup,
            "description_format": description_format,
            "migration": migration,
            "results": results,
        })
        publisher.write_hierarchy_results_csv(
            str(run_dir / "jira-rollup-results.csv"), results
        )

    for node in nodes:
        external_id = node["external_id"]
        remote = found.get(node["lookup_label"])
        cached = publisher.state_issue_for_external_id(state, external_id)
        cached_key = str((cached or {}).get("issue_key") or "")
        remote_key = str((remote or {}).get("key") or "")
        if cached_key and remote_key and cached_key != remote_key:
            raise RuntimeError("Cached and searched Jira identities disagree")
        pending_record = pending.get(external_id)
        if pending_record and pending_record["lookup_label"] != node["lookup_label"]:
            raise RuntimeError("Pending creation label differs from planned identity")
        key = remote_key or cached_key

        if pending_record and not key and apply:
            raise RuntimeError(
                f"Uncertain previous creation for {external_id}; no issue was found. "
                "Reconcile Jira before clearing product_pending_creates."
            )
        if not key:
            continue
        if remote_lookup:
            remote_fields[external_id] = read_existing(
                client, project, node, key, prepared
            )
        keys[external_id] = key

    for node in nodes:
        external_id = node["external_id"]
        parent_id = node["parent_external_id"]
        if external_id not in remote_fields or not parent_id:
            continue
        parent_key = keys.get(parent_id)
        if not parent_key:
            raise RuntimeError("Existing Task has no reconciled planned Epic")
        fields = remote_fields[external_id]
        if prepared["hierarchy"]["story_parent_mode"] == "epic_link_field":
            actual = fields.get(prepared["hierarchy"]["epic_link_field"])
        else:
            parent = fields.get("parent")
            actual = parent.get("key") if isinstance(parent, dict) else None
        if actual != parent_key:
            raise RuntimeError(
                f"Existing Task {keys[external_id]} is not under Epic {parent_key}"
            )

    if apply:
        state["product_reporting_destination"] = destination

    try:
        for node in sorted(nodes, key=publisher.hierarchy_node_sort_key):
            external_id = node["external_id"]
            parent_id = node["parent_external_id"]
            base_result = {
                "external_id": external_id,
                "parent_external_id": parent_id,
                "lookup_label": node["lookup_label"],
                "node_type": node["node_type"],
                "summary": node["summary"],
            }

            if external_id in keys:
                key = keys[external_id]
                status_field = remote_fields.get(external_id, {}).get("status")
                status = (
                    status_field.get("name", "")
                    if isinstance(status_field, dict) else ""
                )
                if apply:
                    publisher.update_state_issue(
                        state, external_id, "", node["lookup_label"], key,
                        status, "reconciled", node["node_type"], node["summary"],
                    )
                    pending.pop(external_id, None)
                    save(state_path, state)

                managed_fields = publisher.hierarchy_managed_fields_for_node(
                    node, prepared
                )
                sync = bool(
                    args.sync_existing_fields
                    or prepared["hierarchy"].get("sync_existing_fields")
                )
                action = "skip_existing_jira" if remote_lookup else "skip_existing_state"
                if sync and node.get("product_report") is not None:
                    managed_fields["description"] = copy.deepcopy(
                        payloads[external_id]["fields"]["description"]
                    )
                if sync and managed_fields:
                    action = (
                        "updated_existing_fields" if apply
                        else "would_update_existing_fields"
                    )
                    if apply:
                        mutate(
                            client,
                            lambda: client.update_issue_fields(key, managed_fields),
                        )
                results.append({
                    **base_result,
                    "issue_key": key,
                    "jira_status": status,
                    "action": action,
                })
                if apply:
                    publisher.update_state_issue(
                        state, external_id, "", node["lookup_label"], key,
                        status, action, node["node_type"], node["summary"],
                    )
                    save(state_path, state)
                checkpoint_results()
                continue

            if external_id in pending:
                results.append({
                    **base_result,
                    "action": "pending_creation_requires_reconciliation",
                })
                checkpoint_results()
                continue

            if apply and created_count >= args.max_create:
                results.append({**base_result, "action": "skip_max_create_reached"})
                checkpoint_results()
                continue

            payload = copy.deepcopy(payloads[external_id])
            if parent_id:
                parent_key = keys.get(parent_id)
                if not parent_key:
                    results.append({**base_result, "action": "skip_parent_not_created"})
                    checkpoint_results()
                    continue
                publisher.apply_parent_to_hierarchy_payload(
                    payload, node, parent_key, prepared
                )

            if not apply:
                key = f"DRY-{len(results) + 1}"
                keys[external_id] = key
                results.append({
                    **base_result,
                    "issue_key": key,
                    "action": "would_create" if remote_lookup else "would_create_or_reuse",
                    "message": json.dumps(payload, sort_keys=True),
                })
                checkpoint_results()
                continue

            pending[external_id] = {
                "lookup_label": node["lookup_label"],
                "started_at": publisher.now_iso(),
                "summary": node["summary"],
            }
            save(state_path, state)
            results.append({**base_result, "action": "create_attempt"})
            checkpoint_results()

            try:
                response = mutate(client, lambda: client.create_issue(payload))
            except Exception as error:
                message = str(error)
                for secret_name in ("JIRA_API_TOKEN", "JIRA_PAT"):
                    secret = os.getenv(secret_name, "")
                    if secret:
                        message = message.replace(secret, "[REDACTED]")
                results[-1].update({
                    "action": "create_failed_or_uncertain",
                    "error_type": type(error).__name__,
                    "error": message,
                })
                pending[external_id].update({
                    "error_type": type(error).__name__,
                    "error": message,
                })
                save(state_path, state)
                checkpoint_results()
                raise
            key = response.get("key") if isinstance(response, dict) else None
            if not isinstance(key, str) or not key.strip():
                raise RuntimeError("Jira creation returned no key; pending creation retained")
            keys[external_id] = key
            created_count += 1
            publisher.update_state_issue(
                state, external_id, "", node["lookup_label"], key,
                "created", "created", node["node_type"], node["summary"],
            )
            pending.pop(external_id, None)
            save(state_path, state)
            results[-1].update(action="created", issue_key=key)
            checkpoint_results()
    finally:
        checkpoint_results()

    return results
