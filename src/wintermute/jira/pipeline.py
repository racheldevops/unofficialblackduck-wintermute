from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

from wintermute.jira import pipeline_workflow as _workflow
from wintermute.jira.pipeline_lock import PipelineLock as _DurablePipelineLock


class PipelineLock(_DurablePipelineLock):
    def lock_held_exception(self, message):
        return _workflow.PipelineFailure(message, _workflow.EXIT_LOCKED)

    def __enter__(self):
        super().__enter__()
        stale = self.stale_archive_path
        if stale is not None:
            destination = self.path.with_name(f"{self.path.name}.stale-{self.run_id}")
            if stale != destination:
                try:
                    os.replace(stale, destination)
                except BaseException:
                    self.release()
                    raise
                self.stale_archive_path = destination
        return self


_workflow.PipelineLock = PipelineLock

if not hasattr(_workflow, "_wintermute_legacy_run_pipeline"):
    _workflow._wintermute_legacy_run_pipeline = _workflow.run_pipeline

if not hasattr(_workflow, "_wintermute_legacy_parse_args"):
    _workflow._wintermute_legacy_parse_args = _workflow.parse_args


def validated_years(values):
    if not isinstance(values, list) or any(
        type(value) is not int or not 1000 <= value <= 9999
        for value in values
    ):
        raise _workflow.PipelineFailure(
            "--vulnerability-year requires a four-digit year",
            _workflow.EXIT_ARGUMENT_ERROR,
        )
    return sorted(set(values))


def parse_args():
    """Accept per-run product options without changing persistent config."""
    recovery_flag = "--reconcile-missing-jira-issues"
    year_flag = "--vulnerability-year"
    arguments = sys.argv[1:]

    if arguments.count(recovery_flag) > 1:
        raise _workflow.PipelineFailure(
            f"{recovery_flag} may be specified only once",
            _workflow.EXIT_ARGUMENT_ERROR,
        )

    remaining = []
    years = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == recovery_flag:
            index += 1
            continue
        if argument == year_flag:
            if index + 1 >= len(arguments):
                raise _workflow.PipelineFailure(
                    f"{year_flag} requires a four-digit year",
                    _workflow.EXIT_ARGUMENT_ERROR,
                )
            value = arguments[index + 1]
            index += 2
        elif argument.startswith(year_flag + "="):
            value = argument[len(year_flag) + 1:]
            index += 1
        else:
            remaining.append(argument)
            index += 1
            continue

        if len(value) != 4 or not value.isascii() or not value.isdecimal():
            raise _workflow.PipelineFailure(
                f"{year_flag} requires a four-digit year",
                _workflow.EXIT_ARGUMENT_ERROR,
            )
        years.append(int(value))

    previous_argv = sys.argv
    try:
        sys.argv = [previous_argv[0], *remaining]
        args = _workflow._wintermute_legacy_parse_args()
    finally:
        sys.argv = previous_argv

    args.reconcile_missing_jira_issues = recovery_flag in arguments
    args.vulnerability_year = validated_years(years)
    return args


def run_pipeline(args):
    config = _workflow.load_config(Path(args.config))
    raw = config.get("product_reporting", {})
    if not isinstance(raw, dict) or type(raw.get("enabled", False)) is not bool:
        raise _workflow.PipelineFailure(
            "product_reporting.enabled must be boolean",
            _workflow.EXIT_ARGUMENT_ERROR,
        )

    years = validated_years(getattr(args, "vulnerability_year", []))
    args.vulnerability_year = years
    reconcile = bool(getattr(args, "reconcile_missing_jira_issues", False))
    if reconcile and (
        not raw.get("enabled", False)
        or not getattr(args, "apply", False)
        or getattr(args, "dry_run", False)
        or getattr(args, "preflight_only", False)
    ):
        raise _workflow.PipelineFailure(
            "--reconcile-missing-jira-issues requires an applying "
            "product-reporting run (not dry-run or preflight-only)",
            _workflow.EXIT_ARGUMENT_ERROR,
        )

    if raw.get("enabled", False):
        from wintermute.jira import product_reporting

        # Recovery is controlled by this run's flag, not by persistent
        # configuration left enabled for future scheduled runs.
        selected_config = copy.deepcopy(config)
        selected_config["product_reporting"][
            "reconcile_missing_jira_issues"
        ] = reconcile
        return product_reporting.run(args, selected_config)

    if years:
        raise _workflow.PipelineFailure(
            "--vulnerability-year requires product reporting",
            _workflow.EXIT_ARGUMENT_ERROR,
        )
    return _workflow._wintermute_legacy_run_pipeline(args)


def main():
    try:
        return _workflow.run_pipeline(_workflow.parse_args())
    except KeyboardInterrupt:
        return 130
    except _workflow.PipelineFailure as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return error.exit_code
    except (RuntimeError, ValueError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


_workflow.parse_args = parse_args
_workflow.run_pipeline = run_pipeline
_workflow.main = main

if __name__ == "__main__":
    raise SystemExit(main())

sys.modules[__name__] = _workflow
