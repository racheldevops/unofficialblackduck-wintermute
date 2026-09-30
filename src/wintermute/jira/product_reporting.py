from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import sys
import time
import uuid
from collections import Counter, defaultdict

from wintermute.blackduck.cache import ApiResponseCache
from wintermute.blackduck.circuit_recovery import run_with_circuit_recovery
from wintermute.blackduck.client import BlackDuckClient
from wintermute.blackduck.collector import collect_targets
from wintermute.blackduck.criteria import CollectionCriteria
from wintermute.blackduck.custom_fields import find_named_custom_field
from wintermute.blackduck.inventory import build_project_version_inventory
from wintermute.blackduck.models import CollectionTarget, LineageContext
from wintermute.blackduck.occurrences import same_instance_url
from wintermute.blackduck.product_lineage import ProductLineageCache
from wintermute.blackduck.serialization import normalized_finding_payload
from wintermute.jira import findings_hierarchy_plan as hierarchy
from wintermute.jira import findings_to_jira as publisher
from wintermute.jira import pipeline_workflow as workflow
from wintermute.jira.pipeline_lock import PipelineLock
from wintermute.jira.product_publishing import publish, save
from wintermute.paths import output_root


ROLES = ("maintainer", "owner", "supporter", "securitymanager")
DEFAULT_STATUSES = ("NEW",)


def normalize(value):
    return re.sub(r"[\s-]+", "_", str(value or "").strip().upper())


def normalize_phase(value):
    phase = normalize(value)
    return "LTS" if phase == "LONG_TERM_SUPPORT" else phase


def settings_from(config):
    raw = config.get("product_reporting", {})
    if not isinstance(raw, dict):
        raise RuntimeError("product_reporting must be an object")
    if type(raw.get("enabled", False)) is not bool:
        raise RuntimeError("product_reporting.enabled must be boolean")
    if not raw.get("enabled", False):
        return None
    settings = copy.deepcopy(raw)
    for key in ("policy_custom_field", "entity_custom_field"):
        value = settings.get(key)
        if not isinstance(value, str) or not value.strip():
            raise RuntimeError(f"product_reporting.{key} must be configured")
        settings[key] = value.strip()

    for key, default in (
        ("phases", ["RELEASED", "LTS"]),
        ("remediation_statuses", list(DEFAULT_STATUSES)),
        ("exploit_maturity_available_values", ["PROOF_OF_CONCEPT", "FUNCTIONAL", "HIGH"]),
        ("exploit_maturity_unavailable_values", ["UNPROVEN"]),
    ):
        values = settings.get(key, default)
        if not isinstance(values, list) or not all(
            isinstance(value, str) and value.strip() for value in values
        ):
            raise RuntimeError(f"product_reporting.{key} must be a string list")
        if key in {"phases", "remediation_statuses"} and not values:
            raise RuntimeError(f"product_reporting.{key} must not be empty")
        convert = normalize_phase if key == "phases" else normalize
        settings[key] = sorted({convert(value) for value in values})

    for key, default in (("minimum_score", 7.0), ("exploit_minimum_score", 4.0)):
        value = settings.get(key, default)
        if (
            type(value) not in (int, float)
            or not math.isfinite(value)
            or not 0 <= value <= 10
        ):
            raise RuntimeError(f"product_reporting.{key} must be between 0 and 10")
        settings[key] = float(value)
    if settings["exploit_minimum_score"] > settings["minimum_score"]:
        raise RuntimeError("Exploit threshold exceeds ordinary threshold")

    depth = settings.get("added_project_depth", 1)
    if type(depth) is not int or not 0 <= depth <= 10:
        raise RuntimeError("added_project_depth must be between 0 and 10")
    settings["added_project_depth"] = depth
    settings.setdefault("allow_task_identity_migration", False)
    if type(settings["allow_task_identity_migration"]) is not bool:
        raise RuntimeError("allow_task_identity_migration must be boolean")

    settings.setdefault("exploit_maturity_field", "cvss3.temporalMetrics.exploitability")
    if settings["exploit_maturity_field"] not in {
        "", "cvss2.temporalMetrics.exploitability",
        "cvss3.temporalMetrics.exploitability", "cvss4.exploitMaturity",
    }:
        raise RuntimeError("Unsupported exploit_maturity_field")
    if set(settings["exploit_maturity_available_values"]) & set(
        settings["exploit_maturity_unavailable_values"]
    ):
        raise RuntimeError("Exploit maturity value lists overlap")

    names = settings.get("product_display_names", {})
    if not isinstance(names, dict) or not all(
        isinstance(key, str) and key.strip()
        and isinstance(value, str) and value.strip()
        and not any(ord(character) < 32 for character in value)
        for key, value in names.items()
    ):
        raise RuntimeError("product_display_names must map names to display names")
    settings["product_display_names"] = names
    return settings


def responsibility_metadata(description):
    empty = {"roles": {}, "missing_roles": list(ROLES)}
    if description is None or description == "":
        return {"status": "missing", **empty}
    if not isinstance(description, str):
        return {"status": "invalid-schema", **empty}
    if not description.strip():
        return {"status": "missing", **empty}
    if len(description.encode("utf-8")) > 65536:
        return {"status": "too-large", **empty}

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    try:
        payload = json.loads(description, object_pairs_hook=unique)
    except (ValueError, RecursionError):
        return {"status": "invalid-json", **empty}
    info = payload.get("info") if isinstance(payload, dict) else None
    if not isinstance(info, dict):
        return {"status": "invalid-schema", **empty}
    roles = {
        role: info[role].strip()
        for role in ROLES
        if isinstance(info.get(role), str)
        and info[role].strip()
        and len(info[role]) <= 512
        and not any(ord(character) < 32 for character in info[role])
    }
    missing = [role for role in ROLES if role not in roles]
    return {
        "status": "incomplete" if missing else "complete",
        "roles": roles,
        "missing_roles": missing,
    }


class ProductClient(BlackDuckClient):
    product_occurrence_evidence = True
    cache_raw_gets = False

    def _make_url(self, url_or_path, params=None):
        return same_instance_url(
            self, super()._make_url(url_or_path, params)
        )

    def _fetch_paged_items(self, url_or_path, params, page_limit):
        rows = []
        seen_pages = set()
        total = None
        offset = 0
        for _ in range(10000):
            parameters = dict(params or {})
            parameters.update(offset=offset, limit=page_limit)
            payload = self.get(url_or_path, parameters)
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise RuntimeError("Black Duck collection has no items array")
            page = payload["items"]
            if not all(isinstance(item, dict) for item in page):
                raise RuntimeError("Black Duck collection contains invalid items")
            reported_total = payload.get("totalCount")
            if reported_total is not None:
                if type(reported_total) is not int or reported_total < 0:
                    raise RuntimeError("Black Duck totalCount is invalid")
                if total is not None and total != reported_total:
                    raise RuntimeError("Black Duck collection changed during pagination")
                total = reported_total
            if not page:
                if total is not None and offset < total:
                    raise RuntimeError("Black Duck pagination ended before totalCount")
                return rows, total
            digest = hashlib.sha256(
                json.dumps(page, sort_keys=True).encode()
            ).hexdigest()
            if digest in seen_pages:
                raise RuntimeError("Black Duck pagination repeated a page")
            seen_pages.add(digest)
            rows.extend(page)
            offset += len(page)
            if total is not None and offset >= total:
                if offset != total:
                    raise RuntimeError("Black Duck collection exceeds totalCount")
                return rows, total
        raise RuntimeError("Black Duck pagination limit exceeded")

    def paged_get(self, url_or_path, params=None, limit=None):
        from urllib.parse import urlsplit
        path = urlsplit(url_or_path).path
        if path.rstrip("/").endswith("/vulnerable-bom-components"):
            rows, _ = self._fetch_paged_items(
                url_or_path, params,
                limit if limit is not None else self.page_limit,
            )
            return rows
        return super().paged_get(url_or_path, params=params, limit=limit)


class EvidenceCriteria(CollectionCriteria):
    def score_passes(self, value):
        return True


class ProductLock(PipelineLock):
    def lock_held_exception(self, message):
        return workflow.PipelineFailure(message, workflow.EXIT_LOCKED)


def field_value(fields, name):
    matches = []
    for field in fields:
        found, value = find_named_custom_field(field, name)
        if found:
            matches.append(value)
    if len(matches) > 1:
        raise RuntimeError(f"Ambiguous custom field: {name}")
    return matches[0] if matches else ""


def select_products(client, inventory, args, settings, report):
    selected = []
    metadata = {}
    excluded_projects = set()
    for item in inventory.items:
        ref = item.project_version
        if ref.project in args.exclude_parent_project:
            continue
        if args.only_parent_project and ref.project != args.only_parent_project:
            continue
        if (
            args.project_name_contains
            and args.project_name_contains.casefold() not in ref.project.casefold()
        ):
            continue
        if args.only_parent_version and ref.version != args.only_parent_version:
            continue
        if not ref.project_href:
            raise RuntimeError("Inventory project has no resource URL")

        if ref.project_href not in metadata:
            project = client.get(ref.project_href)
            if not isinstance(project, dict) or project.get("name") != ref.project:
                raise RuntimeError("Project metadata does not match inventory")
            fields = client.paged_get(ref.project_href + "/custom-fields")
            metadata[ref.project_href] = {
                "policy": field_value(fields, settings["policy_custom_field"]),
                "entity": field_value(fields, settings["entity_custom_field"]),
                "people": responsibility_metadata(project.get("description")),
            }
            report["responsibility_metadata"].append({
                "project": ref.project,
                **metadata[ref.project_href]["people"],
            })

        data = metadata[ref.project_href]
        policy_active = data["policy"].strip().casefold() == "true"
        if not policy_active or not data["entity"].strip():
            if ref.project_href not in excluded_projects:
                report["excluded_products"].append({
                    "project": ref.project,
                    "reason": "policy-not-active" if not policy_active else "entity-missing",
                })
                excluded_projects.add(ref.project_href)
            continue
        if not ref.phase:
            raise RuntimeError(f"Version phase is missing: {ref.project} / {ref.version}")
        phase = normalize_phase(ref.phase)
        if phase not in settings["phases"]:
            report["excluded_versions"].append({
                "project": ref.project,
                "version": ref.version,
                "phase": phase,
                "reason": "phase-not-eligible",
            })
            continue
        selected.append({
            "ref": ref,
            "project": ref.project,
            "version": ref.version,
            "href": ref.version_href,
            "display_name": settings["product_display_names"].get(ref.project, ref.project),
            "phase": phase,
            "entity": data["entity"],
            "people": data["people"],
        })
    return selected


def collection_targets(lineage, products, args, settings, report):
    targets = {}
    for product in products:
        root = product["ref"]
        queue = [(root, 0)]
        seen = set()
        while queue:
            ref, depth = queue.pop(0)
            if ref.version_href in seen:
                continue
            seen.add(ref.version_href)
            if len(seen) > 10000:
                raise RuntimeError("Added-project traversal exceeded 10000 versions")
            if depth and ref.project in args.exclude_child_project:
                continue
            context = LineageContext(
                parent=root,
                child=ref,
                detection_method="direct-product" if depth == 0 else "added-project",
            )
            previous = targets.get(ref.identity_key, CollectionTarget(ref))
            targets[ref.identity_key] = previous.with_contexts([context])
            report["relationships"].append({
                "product_href": root.version_href,
                "source_href": ref.version_href,
                "source_project": ref.project,
                "source_version": ref.version,
                "depth": depth,
            })
            if depth < settings["added_project_depth"]:
                queue.extend(
                    (context.child, depth + 1)
                    for context in lineage.load(ref)
                )
    report["lineage_cache"] = {
        "reused": lineage.reused,
        "scanned": lineage.scanned,
        "path": str(lineage.path),
    }
    return [targets[key] for key in sorted(targets)]


def exploit_decision(evidence, settings):
    exploit = evidence["exploit"]
    if exploit["status"] == "known":
        return exploit["available"], "explicit availability field"
    if exploit["status"] == "invalid-or-conflicting":
        return None, "invalid or conflicting explicit availability"

    field = settings["exploit_maturity_field"]
    value = exploit["maturity_metrics"].get(field) if field else None
    if value is None:
        return None, "exploit availability not provided"
    normalized = normalize(value)
    if normalized in settings["exploit_maturity_available_values"]:
        return True, f"{field}={value}"
    if normalized in settings["exploit_maturity_unavailable_values"]:
        return False, f"{field}={value}"
    return None, f"unmapped {field}={value}"


def qualifies(score, exploit, settings):
    if type(score) not in (int, float):
        return False
    if not 0 <= score <= 10 or not math.isfinite(score):
        return False
    return score >= settings["minimum_score"] or (
        score >= settings["exploit_minimum_score"] and exploit is True
    )


def project_findings(findings, products, args, settings, report):
    products_by_href = {product["href"]: product for product in products}
    rows = []
    legacy = set()
    unresolved = []
    exclusions = Counter()

    for finding in findings:
        if args.only_vulnerability and finding.vulnerability != args.only_vulnerability:
            continue
        occurrences = finding.attributes.get("blackduck_occurrences")
        if not isinstance(occurrences, list) or not occurrences:
            raise RuntimeError("Shared collector did not preserve occurrence evidence")

        legacy_id = hierarchy.node_external_id("bd_cve_project", [
            finding.vulnerability,
            finding.project_version.project,
            finding.project_version.version,
            finding.project_version.version_href,
        ])
        legacy.add(hierarchy.node_lookup_label(legacy_id, 24))

        for occurrence in occurrences:
            if occurrence["project_version_href"] != finding.project_version.version_href:
                raise RuntimeError("Occurrence belongs to another source version")
            if occurrence["vulnerability"] != finding.vulnerability:
                raise RuntimeError("Occurrence advisory differs from normalized finding")

            status = normalize(occurrence["remediation_status"])
            if (
                occurrence["remediation_evidence_status"] == "known"
                and status not in settings["remediation_statuses"]
            ):
                exclusions["remediation-not-selected"] += 1
                continue

            score_data = occurrence["overall_score"]
            if score_data["status"] != "known":
                unresolved.append({
                    "occurrence": occurrence["occurrence_href"],
                    "reason": "overall-score-" + score_data["status"],
                })
                continue
            score = score_data["value"]
            if score < settings["exploit_minimum_score"]:
                exclusions["score-below-minimum"] += 1
                continue

            exploit, exploit_source = exploit_decision(occurrence, settings)
            if score < settings["minimum_score"] and exploit is None:
                unresolved.append({
                    "occurrence": occurrence["occurrence_href"],
                    "reason": exploit_source,
                })
                continue
            if not qualifies(score, exploit, settings):
                exclusions["score-exploit-rule"] += 1
                continue
            if occurrence["remediation_evidence_status"] != "known":
                unresolved.append({
                    "occurrence": occurrence["occurrence_href"],
                    "reason": "remediation-" + occurrence["remediation_evidence_status"],
                })
                continue

            for context in finding.lineage_contexts:
                product = products_by_href.get(context.parent.version_href)
                if product is None:
                    continue
                rows.append({
                    "product": product["project"],
                    "product_display_name": product["display_name"],
                    "product_version": product["version"],
                    "product_href": product["href"],
                    "phase": product["phase"],
                    "entity": product["entity"],
                    "people": product["people"],
                    "source_project": finding.project_version.project,
                    "source_version": finding.project_version.version,
                    "source_href": finding.project_version.version_href,
                    "component": finding.component,
                    "component_version": finding.component_version,
                    "component_href": finding.component_href,
                    "vulnerability": finding.vulnerability,
                    "severity": occurrence.get("severity") or finding.severity,
                    "score": score,
                    "exploit_available": exploit,
                    "exploit_source": exploit_source,
                    "remediation_status": status,
                    "evidence": occurrence,
                })

    report["unresolved_product_evidence"] = unresolved
    report["excluded_occurrence_counts"] = dict(exclusions)
    unique = {}
    for row in rows:
        identity = (
            row["product_href"],
            row["vulnerability"],
            row["evidence"]["occurrence_href"],
        )
        previous = unique.get(identity)
        if previous is not None and previous != row:
            raise RuntimeError("Conflicting evidence for the same occurrence")
        unique[identity] = row
    return [unique[key] for key in sorted(unique)], sorted(legacy)


def literal(value):
    return re.sub(
        r"[{}\[\]|]", " ", " ".join(str(value or "").splitlines())
    ).strip()


def group_stats(rows):
    counts = Counter(row["severity"] for row in rows)
    severity = next(
        (value for value in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[value]),
        "UNKNOWN",
    )
    return severity, {
        "finding_count": len(rows),
        "component_count": len({
            row["component_href"] or (row["component"], row["component_version"])
            for row in rows
        }),
        "vulnerability_count": len({row["vulnerability"] for row in rows}),
        "affected_project_version_count": len({row["product_href"] for row in rows}),
        "max_score": max(row["score"] for row in rows),
        "min_score": min(row["score"] for row in rows),
        **{
            f"{level.lower()}_count": counts[level]
            for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        },
    }


def task_description(rows):
    first = rows[0]
    people = first["people"]
    lines = [
        "Black Duck affected-product report.",
        f"Product: {literal(first['product_display_name'])}",
        f"Black Duck project: {literal(first['product'])}",
        f"Version: {literal(first['product_version'])}",
        f"Phase: {literal(first['phase'])}",
        f"Vulnerability: {literal(first['vulnerability'])}",
        f"Entity: {literal(first['entity'])}",
        f"Product version URL: {literal(first['product_href'])}",
        "",
        "Product responsibilities:",
        f"Metadata status: {people['status']}",
        *[
            f"- {role}: {literal(people['roles'].get(role, 'not provided'))}"
            for role in ROLES
        ],
        "",
        "Remediation states belong to the named source occurrences.",
        "Child states are not asserted to be independent product decisions.",
        "Exploit maturity does not establish reachability or exploitation in this product.",
        "",
        "||Source project/version||Component/version||Overall Score||Exploit evidence||Remediation||",
    ]
    for row in rows:
        lines.append("|" + "|".join(literal(value) for value in (
            f"{row['source_project']} / {row['source_version']}",
            f"{row['component']} / {row['component_version']}",
            row["score"],
            row["exploit_source"],
            row["remediation_status"],
        )) + "|")
        lines.append("Occurrence: " + literal(row["evidence"]["occurrence_href"]))
        lines.append("Advisory: " + literal(row["evidence"]["advisory_href"]))
        if row["evidence"]["origin_href"]:
            lines.append("Origin: " + literal(row["evidence"]["origin_href"]))
    return "\n".join(lines)


def build_nodes(rows, config):
    groups = defaultdict(list)
    for row in rows:
        groups[row["vulnerability"]].append(row)
    nodes = []
    for vulnerability, findings in sorted(groups.items()):
        epic_id = hierarchy.vulnerability_epic_external_id(vulnerability)
        epic_label = hierarchy.node_lookup_label(epic_id, 24)
        severity, stats = group_stats(findings)
        products = defaultdict(list)
        for row in findings:
            products[row["product_href"]].append(row)
        nodes.append({
            "node_type": "epic",
            "external_id": epic_id,
            "lookup_label": epic_label,
            "parent_external_id": "",
            "summary": hierarchy.build_cve_epic_summary(vulnerability),
            "description": "\n".join([
                f"Vulnerability: {literal(vulnerability)}",
                "Affected product versions:",
                *[
                    f"- {literal(group[0]['product_display_name'])} / "
                    f"{literal(group[0]['product_version'])}"
                    for _, group in sorted(products.items())
                ],
            ]),
            "labels": ["blackduck", "bd_rollup_cve", epic_label],
            "context": {"vulnerability": vulnerability, "severity": severity},
            "stats": stats,
        })
        for href, group in sorted(products.items()):
            first = group[0]
            severity, stats = group_stats(group)
            task_id = hierarchy.node_external_id("bd_cve_product", [vulnerability, href])
            label = hierarchy.node_lookup_label(task_id, 24)
            alert = publisher.configured_alert_severity(severity, config)
            nodes.append({
                "node_type": "story",
                "external_id": task_id,
                "lookup_label": label,
                "parent_external_id": epic_id,
                "summary": hierarchy.truncate(
                    f"Black Duck: {alert} Alert - {first['product_display_name']} "
                    f"- version {first['product_version']}", 255,
                ),
                "description": task_description(group),
                "product_report": {
                    "schema_version": 1,
                    "rows": copy.deepcopy(group),
                },
                "labels": ["blackduck", "bd_rollup_product_version", label, epic_label],
                "context": {
                    "vulnerability": vulnerability,
                    "severity": severity,
                    "affected_project": first["product_display_name"],
                    "affected_version": first["product_version"],
                    "affected_project_version_href": href,
                    "parent_project": first["product"],
                    "parent_version": first["product_version"],
                    "parent_version_href": href,
                    "entity": first["entity"],
                    "product_phase": first["phase"],
                    "responsibilities": first["people"],
                    "components": sorted({row["component"] for row in group}),
                    "component_versions": sorted({row["component_version"] for row in group}),
                    "cvss_vector": ";".join(sorted({
                        vector for row in group
                        for vector in row["evidence"]["cvss_vectors"].values()
                    })),
                },
                "stats": stats,
            })
    return sorted(nodes, key=publisher.hierarchy_node_sort_key)


def validate_run_options(args):
    if args.hierarchy_limit is not None:
        raise RuntimeError("Remove --hierarchy-limit for complete product aggregation")
    if args.only_subproject:
        raise RuntimeError("Select product scope rather than --only-subproject")
    if args.threshold != 7.0 or args.score_field != "overallScore":
        raise RuntimeError("Configure product thresholds in product_reporting")
    if args.entity_custom_field or args.require_entity:
        raise RuntimeError("Configure product entity in product_reporting")
    if args.apply and not args.dry_run and (
        args.max_create is None or args.max_create < 1
    ):
        raise RuntimeError("Product apply requires --max-create")


def run(args, config):
    settings = settings_from(config)
    if settings is None:
        raise RuntimeError("Product reporting is not enabled")
    workflow.validate_args(args)
    validate_run_options(args)
    root = output_root() / "jira"
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    report = {
        "run_id": run_id,
        "status": "started",
        "reporting_mode": "product-vulnerability",
        "mode": "apply" if args.apply and not args.dry_run else "dry-run",
        "remediation_policy": "originating-occurrence",
        "exploit_maturity_field": settings["exploit_maturity_field"],
        "excluded_products": [],
        "excluded_versions": [],
        "responsibility_metadata": [],
        "relationships": [],
        "unresolved_product_evidence": [],
        "finalization_errors": [],
    }
    with ProductLock(root / "pipeline.lock", run_id, args.lock_stale_seconds):
        cache = None
        lineage = None
        primary_error = None
        successful = False
        try:
            save(root / "pipeline-run-summary.json", report)
            workflow.validate_environment(args, output_root())
            prepared = publisher.deep_merge(
                copy.deepcopy(publisher.DEFAULT_CONFIG), copy.deepcopy(config)
            )
            if args.preflight_only:
                report["status"] = "configuration-validated"
                report["exit_code"] = 0
                successful = True
                return 0

            cache = ApiResponseCache.load(
                path=str(root / "cache" / "product-advisories.json"),
                base_url=os.environ["BLACKDUCK_URL"],
                max_age_hours=20,
                refresh=args.refresh_blackduck_cache,
                max_entries=5000,
                debug=args.debug,
            )
            client = ProductClient(
                base_url=os.environ["BLACKDUCK_URL"],
                api_token=os.environ["BLACKDUCK_API_TOKEN"],
                insecure=args.insecure,
                ca_bundle=args.ca_bundle,
                timeout=args.rollup_timeout,
                retries=args.rollup_retries,
                retry_delay=args.retry_delay,
                page_limit=args.page_limit,
                debug=args.debug,
                api_cache=cache,
            )
            run_with_circuit_recovery(client.authenticate)
            discovery_client = client.clone_for_uncached_reads()
            inventory = run_with_circuit_recovery(
                lambda: build_project_version_inventory(
                    discovery_client, workers=args.parent_workers, debug=args.debug
                )
            )
            if inventory.failures:
                save(run_dir / "inventory-failures.json", [
                    vars(failure) for failure in inventory.failures
                ])
                raise RuntimeError("Black Duck inventory is incomplete")

            products = select_products(
                discovery_client, inventory, args, settings, report
            )
            lineage = ProductLineageCache(
                root / "cache" / "product-lineage.json",
                discovery_client,
                inventory,
                resolve_bom_names=args.resolve_bom_names,
                refresh=args.refresh_parents,
            )
            targets = collection_targets(
                lineage, products, args, settings, report
            )
            lineage.save()
            collection = run_with_circuit_recovery(
                lambda: collect_targets(
                    client, targets, EvidenceCriteria(),
                    workers=args.rollup_workers, component_workers=1,
                )
            )
            save(run_dir / "normalized-findings.json", [
                normalized_finding_payload(finding)
                for finding in collection.findings
            ])
            failures = list(collection.failures)
            save(run_dir / "collection-failures.json", [
                vars(failure) for failure in failures
            ])
            report["collection_failure_count"] = len(failures)
            report["collection_partial"] = bool(failures)

            if failures and args.strict:
                raise RuntimeError("Black Duck collection is incomplete")

            target_hrefs = {
                target.project_version.version_href
                for target in targets
            }
            failed_hrefs = {
                failure.project_version_href
                for failure in failures
            }
            if failures and (
                not all(failed_hrefs)
                or not failed_hrefs.issubset(target_hrefs)
            ):
                raise RuntimeError(
                    "Cannot safely exclude failed Black Duck targets "
                    "without valid project-version URLs"
                )

            selected_findings = [
                finding for finding in collection.findings
                if finding.project_version.version_href not in failed_hrefs
            ]
            report["excluded_failed_source_versions"] = sorted(failed_hrefs)
            if failures:
                print(
                    f"PARTIAL COLLECTION: excluded {len(failed_hrefs)} "
                    "failed source version(s); details are in "
                    f"{run_dir / 'collection-failures.json'}",
                    file=sys.stderr,
                    flush=True,
                )

            rows, legacy_labels = project_findings(
                selected_findings, products, args, settings, report
            )
            save(run_dir / "product-findings.json", rows)
            nodes = build_nodes(rows, prepared)
            save(run_dir / "jira-hierarchy-plan.json", {
                "schema_version": hierarchy.SCHEMA_VERSION,
                "hierarchy_mode": "product-vulnerability",
                "nodes": nodes,
                "node_counts": hierarchy.count_nodes(nodes),
            })
            hierarchy.write_summary_csv(str(run_dir / "jira-hierarchy-summary.csv"), nodes)
            hierarchy.write_nodes_csv(str(run_dir / "jira-hierarchy-nodes.csv"), nodes)
            report["selected_product_versions"] = len(products)
            report["qualified_occurrences"] = len(rows)
            report["node_counts"] = hierarchy.count_nodes(nodes)
            report["source_counts"] = {
                "products": len(products),
                "targets": len(targets),
                "findings": len(selected_findings),
                "hierarchy_nodes": len(nodes),
            }

            unresolved = bool(report["unresolved_product_evidence"])
            report["evidence_complete"] = not unresolved and not failures
            report["unresolved_occurrence_count"] = len(
                report["unresolved_product_evidence"]
            )
            if unresolved and args.apply and not args.dry_run:
                raise RuntimeError(
                    "Apply blocked: decision-critical evidence is incomplete; "
                    "see product-selection.json"
                )
            if unresolved:
                print(
                    "INCOMPLETE DRY RUN: unresolved occurrences are excluded "
                    "from the preview. Apply remains blocked.",
                    file=sys.stderr,
                    flush=True,
                )
            if not nodes and not args.allow_empty and not unresolved:
                raise RuntimeError("No eligible product findings")

            results = publish(
                args, prepared, nodes,
                root / "state" / "jira-rollup-state.json",
                run_dir, legacy_labels, settings,
            )
            report["created"] = sum(row["action"] == "created" for row in results)
            report["creation_cap_reached"] = any(
                row["action"] == "skip_max_create_reached" for row in results
            )
            publish_plan_path = run_dir / "jira-rollup-plan.json"
            with publish_plan_path.open(encoding="utf-8") as input_file:
                publish_plan = json.load(input_file)
            publish_plan.update({
                "evidence_complete": report["evidence_complete"],
                "collection_partial": bool(failures),
                "collection_failure_count": len(failures),
                "unresolved_occurrence_count": len(
                    report["unresolved_product_evidence"]
                ),
                "selection_report": "product-selection.json",
                "excluded_unresolved_occurrences": unresolved,
            })
            save(publish_plan_path, publish_plan)

            if unresolved:
                report["status"] = "planned-incomplete"
                report["promoted_outputs"] = []
                report["exit_code"] = 2
                successful = False
                return 2

            report["status"] = (
                "partial" if failures
                else "succeeded" if args.apply and not args.dry_run
                else "planned"
            )
            report["promoted_outputs"] = workflow.promote_outputs(run_dir, root)
            report["exit_code"] = 0
            successful = True
            return 0
        except BaseException as error:
            primary_error = error
            report["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
            report["error_type"] = type(error).__name__
            report["error"] = str(error)
            report["exit_code"] = 130 if isinstance(error, KeyboardInterrupt) else 2
            raise
        finally:
            for name, operation in (
                ("api-cache", cache.save if cache is not None else None),
                ("lineage-cache", lineage.save if lineage is not None else None),
            ):
                if operation is None:
                    continue
                try:
                    operation()
                except Exception as error:
                    report["finalization_errors"].append({
                        "stage": name, "error_type": type(error).__name__,
                    })

            report["elapsed_seconds"] = round(time.monotonic() - started, 3)
            if report["finalization_errors"] and primary_error is None:
                report["status"] = "finalization-failed"
                report["exit_code"] = 2

            final_error = None
            try:
                save(run_dir / "product-selection.json", report)
                save(run_dir / "pipeline-run-summary.json", report)
                save(root / "pipeline-run-summary.json", report)
                save(run_dir / "checksums.json", {
                    "sha256": {
                        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in run_dir.iterdir()
                        if path.is_file() and path.name != "checksums.json"
                    }
                })
                if successful and not report["finalization_errors"]:
                    workflow.prune_run_directories(
                        root / "runs", run_id, args.retain_runs
                    )
            except Exception as error:
                final_error = error
                print(
                    f"Failed to finalize product artifacts: {type(error).__name__}",
                    file=sys.stderr,
                )
            print(f"Product reporting artifacts: {run_dir}", flush=True)
            if primary_error is None:
                if final_error is not None:
                    raise final_error
                if report["finalization_errors"]:
                    raise RuntimeError("Product run cache finalization failed")
