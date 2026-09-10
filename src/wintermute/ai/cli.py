from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from wintermute.ai.config import (
    load_ai_settings,
)
from wintermute.ai.gateway import (
    AIGateway,
)
from wintermute.ai.provider import (
    AIProviderError,
    OpenAICompatibleProvider,
)
from wintermute.ai.retrieval import (
    EvidenceCatalog,
)
from wintermute.ai.safety import (
    Anonymizer,
    Sanitizer,
)
from wintermute.ai.storage import (
    AIResponseCache,
    AIUsageLedger,
    write_analysis,
)
from wintermute.paths import output_root


def default_ai_root() -> Path:
    return output_root() / "ai"


def run_scan_profile(
    args: argparse.Namespace,
) -> int:
    settings = load_ai_settings(
        provider=args.provider,
        model=args.model,
        insecure=args.insecure,
        ca_bundle=args.ca_bundle,
    )
    anonymizer = Anonymizer(
        settings.anonymization_key
        or "local-vllm-only"
    )
    sanitizer = Sanitizer(anonymizer)
    source_root = Path(
        args.source_root
    )
    catalog = EvidenceCatalog.build(
        source_root,
        sanitizer,
        max_catalog_files=(
            settings.max_catalog_files
        ),
        max_file_bytes=(
            settings.max_file_bytes
        ),
    )
    ai_root = Path(
        args.output_root
    ).expanduser()
    cache = AIResponseCache(
        ai_root
        / "state"
        / "responses.sqlite3"
    )
    ledger = AIUsageLedger(
        ai_root
        / "state"
        / "usage.sqlite3"
    )
    provider = OpenAICompatibleProvider(
        settings
    )
    gateway = AIGateway(
        settings,
        provider,
        cache,
        ledger,
    )
    repository_alias = anonymizer.alias(
        "repository",
        (
            args.repository
            or source_root.resolve().name
        ),
    )
    tenant_alias = anonymizer.alias(
        "tenant",
        args.tenant or "local",
    )
    result = gateway.scan_profile(
        catalog,
        repository_alias=(
            repository_alias
        ),
        tenant_alias=tenant_alias,
    )
    directory = write_analysis(
        ai_root / "analyses",
        result,
        evidence_catalog=(
            catalog
            .private_descriptor_payload()
        ),
    )

    print(
        json.dumps(
            {
                "analysis_id": (
                    result.analysis_id
                ),
                "task": result.task,
                "provider": (
                    result.provider
                ),
                "model": result.model,
                "round_count": len(
                    result.rounds
                ),
                "evidence_count": len(
                    result.evidence_ids
                ),
                "usage": (
                    result.usage.as_dict()
                ),
                "estimated_cost_usd": (
                    round(
                        result
                        .estimated_cost_usd,
                        8,
                    )
                ),
                "analysis_directory": (
                    str(directory)
                ),
                "status": "succeeded",
            },
            indent=2,
            sort_keys=True,
        )
    )

    return 0


def run_usage(
    args: argparse.Namespace,
) -> int:
    ledger = AIUsageLedger(
        Path(args.output_root)
        / "state"
        / "usage.sqlite3"
    )
    print(
        json.dumps(
            ledger.summary(),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Wintermute AI Gateway"
        )
    )
    parser.add_argument(
        "--output-root",
        default=str(default_ai_root()),
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )
    scan = commands.add_parser(
        "scan-profile",
        help=(
            "Generate a scan profile from "
            "a local source tree"
        ),
    )
    scan.add_argument(
        "--source-root",
        required=True,
    )
    scan.add_argument(
        "--repository",
        default="",
    )
    scan.add_argument(
        "--tenant",
        default="",
    )
    scan.add_argument(
        "--provider",
        choices=["azure", "vllm"],
        default="",
    )
    scan.add_argument(
        "--model",
        default="",
    )
    scan_tls = (
        scan.add_mutually_exclusive_group()
    )
    scan_tls.add_argument(
        "--insecure",
        action="store_true",
    )
    scan_tls.add_argument(
        "--ca-bundle",
    )

    scm_scan = commands.add_parser(
        "scm-scan-profile",
        help=(
            "Generate one scan profile from "
            "an immutable SCM snapshot"
        ),
    )
    from wintermute.ai.scm_profile import (
        add_arguments as add_scm_arguments,
    )

    add_scm_arguments(scm_scan)

    batch = commands.add_parser(
        "scm-batch-scan-profile",
        help=(
            "Generate resumable scan profiles "
            "for SCM snapshot repositories"
        ),
    )
    from wintermute.ai.batch import (
        add_arguments as add_batch_arguments,
    )

    add_batch_arguments(batch)

    commands.add_parser(
        "usage",
        help="Show accumulated AI usage",
    )

    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
) -> int:
    tokens = [
        os.getenv(
            "AZURE_OPENAI_API_KEY",
            "",
        ),
        os.getenv(
            "AZURE_OPENAI_BEARER_TOKEN",
            "",
        ),
        os.getenv(
            "VLLM_API_KEY",
            "",
        ),
        os.getenv(
            "GITHUB_TOKEN",
            "",
        ),
        os.getenv(
            "GITLAB_TOKEN",
            "",
        ),
    ]

    try:
        args = parse_args(argv)

        if args.command == "scan-profile":
            return run_scan_profile(args)

        if args.command == (
            "scm-scan-profile"
        ):
            from wintermute.ai.scm_profile import (
                run,
                validate_args,
            )

            validate_args(args)
            return run(args)

        if args.command == (
            "scm-batch-scan-profile"
        ):
            from wintermute.ai.batch import (
                run,
            )

            return run(args)

        return run_usage(args)

    except KeyboardInterrupt:
        return 130
    except (
        AIProviderError,
        OSError,
        RuntimeError,
        ValueError,
    ) as error:
        message = str(error)

        for token in tokens:
            if token:
                message = message.replace(
                    token,
                    "[REDACTED]",
                )

        print(
            f"ERROR: {message}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
