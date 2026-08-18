from __future__ import annotations

import os
import sys

from wintermute.jira import pipeline_workflow as _workflow
from wintermute.jira.pipeline_lock import (
    PipelineLock as _DurablePipelineLock,
)


class PipelineLock(_DurablePipelineLock):
    def lock_held_exception(
        self,
        message: str,
    ) -> BaseException:
        return _workflow.PipelineFailure(
            message,
            _workflow.EXIT_LOCKED,
        )

    def __enter__(self) -> PipelineLock:
        super().__enter__()
        stale_archive = self.stale_archive_path

        if stale_archive is None:
            return self

        compatibility_path = self.path.with_name(
            f"{self.path.name}.stale-{self.run_id}"
        )

        if stale_archive == compatibility_path:
            return self

        try:
            os.replace(
                stale_archive,
                compatibility_path,
            )
        except BaseException:
            self.release()
            raise

        self.stale_archive_path = compatibility_path
        return self


_workflow.PipelineLock = PipelineLock


if __name__ == "__main__":
    raise SystemExit(_workflow.main())


sys.modules[__name__] = _workflow
