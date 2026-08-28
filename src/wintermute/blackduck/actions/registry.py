from __future__ import annotations

from typing import Any, Protocol

from wintermute.blackduck.actions.models import (
    BlackDuckAction,
)


class ActionHandler(Protocol):
    kind: str

    def read_state(
        self,
        action: BlackDuckAction,
    ) -> dict[str, Any]:
        ...

    def is_satisfied(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> bool:
        ...

    def conflict_reason(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> str:
        ...

    def apply(
        self,
        action: BlackDuckAction,
        state: dict[str, Any],
    ) -> None:
        ...


class ActionRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, ActionHandler] = {}

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))

    def register(
        self,
        handler: ActionHandler,
    ) -> None:
        kind = str(handler.kind).strip()

        if not kind:
            raise ValueError(
                "Handler kind is required"
            )

        if kind in self._handlers:
            raise ValueError(
                f"Handler already registered: {kind}"
            )

        self._handlers[kind] = handler

    def get(
        self,
        kind: str,
    ) -> ActionHandler:
        try:
            return self._handlers[kind]
        except KeyError as error:
            raise ValueError(
                f"No handler registered for action kind: "
                f"{kind}"
            ) from error

    def validate_kinds(
        self,
        kinds: set[str],
    ) -> None:
        missing = kinds - set(self._handlers)

        if missing:
            raise ValueError(
                "No handlers registered for: "
                + ", ".join(sorted(missing))
            )
