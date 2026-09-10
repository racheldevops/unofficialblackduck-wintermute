from __future__ import annotations

import copy
from typing import Any

from wintermute.ai.models import stable_digest
from wintermute.scan.security import redact_text


class SetupExecutionError(RuntimeError):
    pass


PLAN_FIELDS = {
    "central-upgrade": (
        "provider",
        "project",
        "project_id",
        "branch",
        "previous_source_bundle_digest",
        "source_bundle_digest",
        "observation",
        "observation_digest",
        "actions",
        "desired_files",
        "rollback_files",
        "estimated_writes",
    ),
    "central-variables": (
        "provider",
        "project",
        "project_id",
        "branch",
        "variable_names",
        "desired_variables",
        "observation",
        "observation_digest",
        "actions",
        "estimated_writes",
    ),
    "project-access": (
        "access_mode",
        "source_project",
        "source_project_id",
        "target_projects",
        "observation",
        "observation_digest",
        "actions",
        "estimated_writes",
    ),
}


def nonnegative_integer(value: Any, field: str) -> int:
    if type(value) is not int or value < 0:
        raise SetupExecutionError(f"{field} must be a nonnegative integer")
    return value


def approval_payload(
    *,
    configuration_digest: str,
    template_plan_digest: str,
    bundle_digest: str,
    image: str,
    phases: list[dict[str, Any]],
) -> dict[str, Any]:
    identities = []
    names = set()

    for phase in phases:
        name = phase["name"]
        if name not in PLAN_FIELDS or name in names:
            raise SetupExecutionError("Setup phase identity is invalid")
        names.add(name)

        plan = phase["loaded"].plan
        if not isinstance(plan, dict):
            raise SetupExecutionError("Setup phase plan is invalid")
        if plan.get("mutation_allowed") is not False:
            raise SetupExecutionError("Setup phase plan is not safely staged")

        actions = plan.get("actions")
        if (
            not isinstance(actions, list)
            or not all(isinstance(action, dict) for action in actions)
        ):
            raise SetupExecutionError("Setup phase actions are invalid")

        estimated = nonnegative_integer(
            plan.get("estimated_writes"),
            "estimated_writes",
        )
        expected = (
            int(bool(actions))
            if name == "central-upgrade"
            else len(actions)
        )
        if estimated != expected:
            raise SetupExecutionError("Setup phase write counts do not reconcile")

        identities.append({
            "phase": name,
            "plan": {
                field: copy.deepcopy(plan.get(field))
                for field in PLAN_FIELDS[name]
            },
        })

    if not identities:
        raise SetupExecutionError("Setup has no planned phases")

    return {
        "schema_version": 1,
        "configuration_digest": configuration_digest,
        "template_plan_digest": template_plan_digest,
        "bundle_digest": bundle_digest,
        "image": image,
        "phases": identities,
        "estimated_writes": sum(
            value["plan"]["estimated_writes"]
            for value in identities
        ),
    }


def approval_digest(payload: dict[str, Any]) -> str:
    return stable_digest(payload)


def execute_phases(
    phases: list[dict[str, Any]],
    *,
    maximum_writes: int,
    records: list[dict[str, Any]],
    accounting: dict[str, Any],
) -> None:
    budget = nonnegative_integer(maximum_writes, "maximum_writes")
    accounting.update({
        "mutation_attempts": 0,
        "reported_successful_writes": 0,
        "verified_phase_writes": 0,
        "remote_write_outcome": "no-attempts",
    })

    estimated_total = sum(
        nonnegative_integer(
            phase["loaded"].plan.get("estimated_writes"),
            "estimated_writes",
        )
        for phase in phases
    )
    if estimated_total > budget:
        raise SetupExecutionError("Combined setup write budget exceeded")

    # Validate all local execution bindings before any mutation.
    for phase in phases:
        if not callable(phase.get("execute")):
            raise SetupExecutionError("Setup executor is missing")
        if not getattr(phase["loaded"], "digest", ""):
            raise SetupExecutionError("Setup phase digest is missing")
        nonnegative_integer(phase["client"].writes, "client mutation counter")

    for phase in phases:
        remaining = budget - accounting["mutation_attempts"]
        estimate = phase["loaded"].plan["estimated_writes"]
        if estimate > remaining:
            raise SetupExecutionError("Remaining setup write budget exceeded")

        record = {
            "phase": phase["name"] + "-apply",
            "plan_id": phase["loaded"].plan.get("plan_id", ""),
            "plan_digest": phase["loaded"].digest,
            "status": "started",
            "estimated_writes": estimate,
            "mutation_attempts": 0,
            "reported_successful_writes": 0,
            "result_directory": "",
        }
        records.append(record)
        before = phase["client"].writes
        caught: BaseException | None = None
        verified = False

        try:
            code, result, directory = phase["execute"](
                phase["client"],
                mode="apply",
                maximum_writes=remaining,
                confirm_apply=True,
                expected_plan_digest=phase["loaded"].digest,
            )
            if not isinstance(result, dict):
                raise SetupExecutionError("Setup executor returned an invalid result")

            reported = nonnegative_integer(
                result.get("writes"),
                "reported writes",
            )
            record.update({
                "status": result.get("status", "failed"),
                "outcome": result.get("outcome", ""),
                "reported_successful_writes": reported,
                "result_directory": str(directory),
            })
            accounting["reported_successful_writes"] += reported

            verified = code == 0 and result.get("status") == "ok"
            if not verified:
                raise SetupExecutionError(
                    f"{phase['name']} did not verify successfully"
                )
        except BaseException as error:
            caught = error
            record["status"] = "failed"
            record["error"] = redact_text(str(error))
        finally:
            after = phase["client"].writes
            if type(after) is not int or after < before:
                record["status"] = "failed"
                record["error"] = "Invalid transport mutation counter"
                accounting["remote_write_outcome"] = "unknown"
                raise SetupExecutionError(record["error"]) from caught

            attempts = after - before
            record["mutation_attempts"] = attempts
            accounting["mutation_attempts"] += attempts

            if attempts:
                accounting["remote_write_outcome"] = "partially-applied-or-unknown"

            if verified and caught is None:
                accounting["verified_phase_writes"] += (
                    record["reported_successful_writes"]
                )

            if accounting["mutation_attempts"] > budget:
                record["status"] = "failed"
                record["error"] = "Executor exceeded the transport write budget"
                raise SetupExecutionError(record["error"]) from caught

        if caught is not None:
            raise caught

    accounting["remote_write_outcome"] = (
        "verified-complete"
        if accounting["mutation_attempts"]
        else "no-attempts"
    )
