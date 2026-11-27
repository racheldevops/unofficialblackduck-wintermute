from __future__ import annotations

import argparse
import hashlib
import os
import ssl
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


MAX_REGISTRY_BYTES = 16 * 1024 * 1024


def run(
    args: argparse.Namespace,
) -> int:
    parsed = urlsplit(args.url)
    expected_host = os.getenv(
        "CI_SERVER_HOST",
        "",
    ).strip().casefold()

    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or (
            expected_host
            and parsed.hostname.casefold()
            != expected_host
        )
    ):
        raise ValueError(
            "Registry URL is not an allowed "
            "GitLab endpoint"
        )

    token = os.getenv(
        "CI_JOB_TOKEN",
        "",
    ).strip()

    if not token:
        raise ValueError(
            "CI_JOB_TOKEN must be set"
        )

    context = (
        ssl._create_unverified_context()
        if args.insecure
        else ssl.create_default_context(
            cafile=args.ca_bundle
        )
        if args.ca_bundle
        else None
    )
    request = Request(
        args.url,
        headers={
            "JOB-TOKEN": token,
            "Accept": (
                "application/octet-stream"
            ),
            "User-Agent": (
                "blackduck-wintermute-scan"
            ),
        },
        method="GET",
    )

    with urlopen(
        request,
        timeout=args.timeout,
        context=context,
    ) as response:
        content = response.read(
            MAX_REGISTRY_BYTES + 1
        )

    if len(content) > MAX_REGISTRY_BYTES:
        raise RuntimeError(
            "Scan registry exceeded the "
            "maximum supported size"
        )

    expected = args.expected_sha256
    actual = hashlib.sha256(
        content
    ).hexdigest()

    if actual != expected:
        raise RuntimeError(
            "Downloaded registry checksum "
            "does not match"
        )

    destination = Path(
        args.output
    )
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    temporary = destination.with_name(
        f"{destination.name}."
        f"{uuid.uuid4().hex}.tmp"
    )

    try:
        temporary.write_bytes(content)
        os.replace(
            temporary,
            destination,
        )
    finally:
        temporary.unlink(
            missing_ok=True
        )

    return 0


def parse_args(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url",
        required=True,
    )
    parser.add_argument(
        "--output",
        required=True,
    )
    parser.add_argument(
        "--expected-sha256",
        required=True,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
    )
    tls.add_argument(
        "--ca-bundle",
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
        ValueError,
    ) as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
