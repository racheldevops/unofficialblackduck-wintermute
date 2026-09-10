from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from wintermute.ai.storage import (
    atomic_write_json,
)
from wintermute.paths import output_root
from wintermute.scan.contracts import (
    ScanRegistryError,
    load_registry,
    resolve_scan,
)
from wintermute.scan.engine import (
    run_scan,
)


def receipt_id() -> str:
    return (
        datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        + "-security-scan-"
        + uuid.uuid4().hex[:12]
    )


def default_receipt_root() -> str:
    return str(
        output_root()
        / "scan"
        / "receipts"
    )


def environment_value(
    name: str,
) -> str:
    return os.getenv(name, "").strip()


def run(
    args: argparse.Namespace,
) -> int:
    import hashlib

    from wintermute.scan.security import (
        redact_payload,
        redact_text,
        resolve_bridge_checksum,
    )

    identifier = receipt_id()
    receipt_root = Path(args.receipt_root).expanduser().resolve()
    receipt_root.mkdir(parents=True, exist_ok=True)
    receipt_path = receipt_root / f"{identifier}.json"
    checksum_path = receipt_root / f"{identifier}.checksums.json"

    if receipt_path.exists() or checksum_path.exists():
        raise RuntimeError("Scan receipt identity already exists")

    result: dict = {}
    error_message = ""
    code = 2
    invocation_started = False
    resolved = None
    bridge_digest = ""
    requested_mode = str(args.mode)

    try:
        if requested_mode not in {"dry-run", "execute"}:
            raise ValueError("Scan mode is invalid")
        if requested_mode == "execute" and not args.confirm_execute:
            raise ValueError("Scan execution requires confirmation")

        registry = load_registry(
            args.registry,
            expected_sha256=args.expected_registry_sha256,
        )
        resolved = resolve_scan(
            registry,
            provider=args.scm_provider,
            provider_instance=args.scm_provider_instance,
            repository_id=args.scm_repository_id,
        )
        bridge_digest = resolve_bridge_checksum(args.expected_bridge_sha256)
        if requested_mode == "execute":
            from wintermute.scan.execution_policy import require_supported_execution

            require_supported_execution(resolved.contract)

        invocation_started = True
        result = run_scan(
            resolved,
            source_root=Path(args.source_root),
            commit_sha=args.commit_sha,
            bridge_executable=args.bridge_executable,
            bridge_sha256=bridge_digest,
            execute=requested_mode == "execute",
            confirm_execute=args.confirm_execute,
        )

        if not isinstance(result, dict):
            raise RuntimeError("Scan engine returned an invalid result")

        if result.get("status") in {None, "planned", "succeeded"}:
            code = 0
        else:
            code = 1

    except KeyboardInterrupt:
        code = 130
        error_message = "Scan interrupted"
        result = {
            "mode": requested_mode,
            "status": "interrupted",
            "outcome": "interrupted",
            "writes": (
                None if invocation_started and requested_mode == "execute" else 0
            ),
            "remote_writes": (
                None if invocation_started and requested_mode == "execute" else 0
            ),
        }
    except Exception as error:
        code = 2
        error_message = redact_text(str(error))
        uncertain = invocation_started and requested_mode == "execute"
        result = {
            "mode": requested_mode,
            "status": "failed",
            "outcome": "execution-error" if uncertain else "validation-failed",
            "writes": None if uncertain else 0,
            "remote_writes": None if uncertain else 0,
        }

    receipt = redact_payload({
        "schema_version": 1,
        "receipt_id": identifier,
        "created_at": (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        ),
        "provider": args.scm_provider,
        "provider_instance": args.scm_provider_instance,
        "repository_id": args.scm_repository_id,
        "commit_sha": args.commit_sha,
        "registry_sha256": args.expected_registry_sha256,
        "bridge_sha256": bridge_digest,
        "exit_code": code,
        "error": error_message,
        "result": result,
    })
    atomic_write_json(receipt_path, receipt)
    atomic_write_json(
        checksum_path,
        {
            "schema_version": 1,
            "sha256": {
                receipt_path.name: hashlib.sha256(
                    receipt_path.read_bytes()
                ).hexdigest(),
            },
        },
    )

    summary = redact_payload({
        "receipt_id": identifier,
        "receipt_path": str(receipt_path),
        "checksum_path": str(checksum_path),
        "mode": requested_mode,
        "contract_id": (
            resolved.contract_id if resolved is not None else ""
        ),
        "engine": result.get(
            "engine",
            resolved.contract.get("engine", "") if resolved is not None else "",
        ),
        "products": result.get(
            "products",
            resolved.contract.get("products", []) if resolved is not None else [],
        ),
        "status": result.get(
            "status",
            "planned" if requested_mode == "dry-run" else "succeeded",
        ),
        "writes": result.get("writes"),
        "remote_writes": result.get("remote_writes"),
        "exit_code": code,
        "error": error_message,
    })
    print(json.dumps(summary, indent=2, sort_keys=True))
    return code



def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run an approved Wintermute "
            "security scan contract."
        )
    )
    parser.add_argument(
        "--registry",
        default=environment_value(
            "WINTERMUTE_SCAN_REGISTRY"
        ),
        required=not bool(
            environment_value(
                "WINTERMUTE_SCAN_REGISTRY"
            )
        ),
    )
    parser.add_argument(
        "--expected-registry-sha256",
        default=environment_value(
            "WINTERMUTE_SCAN_REGISTRY_SHA256"
        ),
        required=not bool(
            environment_value(
                "WINTERMUTE_SCAN_REGISTRY_SHA256"
            )
        ),
    )
    parser.add_argument(
        "--scm-provider",
        choices=[
            "github",
            "gitlab",
        ],
        default=environment_value(
            "SCM_PROVIDER"
        ),
        required=not bool(
            environment_value(
                "SCM_PROVIDER"
            )
        ),
    )
    parser.add_argument(
        "--scm-provider-instance",
        default=environment_value(
            "SCM_PROVIDER_INSTANCE"
        ),
        required=not bool(
            environment_value(
                "SCM_PROVIDER_INSTANCE"
            )
        ),
    )
    parser.add_argument(
        "--scm-repository-id",
        default=environment_value(
            "SCM_REPOSITORY_ID"
        ),
        required=not bool(
            environment_value(
                "SCM_REPOSITORY_ID"
            )
        ),
    )
    parser.add_argument(
        "--commit-sha",
        default=environment_value(
            "SCM_COMMIT_SHA"
        ),
    )
    parser.add_argument(
        "--source-root",
        default=".",
    )
    parser.add_argument(
        "--bridge-executable",
        default=environment_value(
            "BLACKDUCK_BRIDGE_PATH"
        )
        or "bridge",
    )
    parser.add_argument(
        "--expected-bridge-sha256",
        default=environment_value(
            "BLACKDUCK_BRIDGE_SHA256"
        ),
        required=not bool(
            environment_value(
                "BLACKDUCK_BRIDGE_SHA256"
            )
        ),
    )
    parser.add_argument(
        "--mode",
        choices=[
            "dry-run",
            "execute",
        ],
        default=environment_value(
            "WINTERMUTE_SCAN_MODE"
        )
        or "dry-run",
    )
    parser.add_argument(
        "--confirm-execute",
        action="store_true",
    )
    parser.add_argument(
        "--receipt-root",
        default=default_receipt_root(),
    )

    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
) -> int:
    try:
        return run(parse_args(argv))
    except KeyboardInterrupt:
        return 130
    except (
        OSError,
        RuntimeError,
        ScanRegistryError,
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
