from __future__ import annotations

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


def run_pipeline(args):
    config = _workflow.load_config(Path(args.config))
    raw = config.get("product_reporting", {})
    if not isinstance(raw, dict) or type(raw.get("enabled", False)) is not bool:
        raise _workflow.PipelineFailure(
            "product_reporting.enabled must be boolean",
            _workflow.EXIT_ARGUMENT_ERROR,
        )
    if raw.get("enabled", False):
        from wintermute.jira import product_reporting
        return product_reporting.run(args, config)
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


_workflow.run_pipeline = run_pipeline
_workflow.main = main

if __name__ == "__main__":
    raise SystemExit(main())

sys.modules[__name__] = _workflow
