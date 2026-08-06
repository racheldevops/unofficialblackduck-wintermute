#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import json
import os
import shutil
import socket
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any
from wintermute.concurrency import MAX_IO_WORKERS, bounded_worker_count
from wintermute.jira import find_parent_projects, findings_hierarchy_plan, findings_to_jira, subp_vuln_rollup
from wintermute.paths import ensure_parent_dir, output_root, package_path
EXIT_SUCCESS = 0
EXIT_PARTIAL = 1
EXIT_ARGUMENT_ERROR = 2
EXIT_REQUIRED_OUTPUT_MISSING = 3
EXIT_LOCKED = 4
EXIT_STRICT_REJECTION = 5
EXIT_INTERRUPTED = 130

class PipelineFailure(RuntimeError):

    def __init__(self, message: str, exit_code: int=EXIT_PARTIAL):
        super().__init__(message)
        self.exit_code = exit_code

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def atomic_write_json(path: str | Path, payload: dict[str, Any]) -> None:
    path = Path(path)
    ensure_parent_dir(path)
    tmp_path = path.with_name(f'{path.name}.tmp')
    with tmp_path.open('w', encoding='utf-8') as output_file:
        json.dump(payload, output_file, indent=2, sort_keys=True)
    os.replace(tmp_path, path)

def atomic_copy(source: Path, destination: Path) -> None:
    ensure_parent_dir(destination)
    tmp_path = destination.with_name(f'{destination.name}.tmp')
    shutil.copy2(source, tmp_path)
    os.replace(tmp_path, destination)

class PipelineLock:

    def __init__(self, path: Path, run_id: str, stale_seconds: int):
        self.path = path
        self.run_id = run_id
        self.stale_seconds = stale_seconds
        self.token = uuid.uuid4().hex
        self.acquired = False

    def __enter__(self) -> PipelineLock:
        ensure_parent_dir(self.path)
        if self.path.exists():
            age_seconds = max(0.0, time.time() - self.path.stat().st_mtime)
            if age_seconds <= self.stale_seconds:
                try:
                    details = json.loads(self.path.read_text(encoding='utf-8'))
                except (OSError, json.JSONDecodeError):
                    details = {'path': str(self.path), 'age_seconds': round(age_seconds, 1)}
                raise PipelineFailure(f'Another Jira pipeline run appears active. Lock details: {json.dumps(details, sort_keys=True)}', EXIT_LOCKED)
            stale_path = self.path.with_name(f'{self.path.name}.stale-{self.run_id}')
            os.replace(self.path, stale_path)
        payload = {'run_id': self.run_id, 'token': self.token, 'hostname': socket.gethostname(), 'pod_name': os.getenv('POD_NAME', ''), 'pid': os.getpid(), 'created_at': now_iso(), 'created_at_epoch': time.time()}
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        except FileExistsError as error:
            raise PipelineFailure(f'Pipeline lock was acquired concurrently: {self.path}', EXIT_LOCKED) from error
        try:
            os.write(descriptor, json.dumps(payload, indent=2, sort_keys=True).encode('utf-8'))
        finally:
            os.close(descriptor)
        self.acquired = True
        return self

    def __exit__(self, exc_type: object, exc_value: object, exc_traceback: object) -> None:
        if not self.acquired or not self.path.exists():
            return
        try:
            current = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return
        if current.get('token') == self.token:
            self.path.unlink(missing_ok=True)

def invoke_module_main(module: ModuleType, arguments: list[str]) -> int:
    previous_argv = sys.argv
    try:
        sys.argv = [module.__name__, *arguments]
        result = module.main()
    except SystemExit as error:
        result = error.code
    finally:
        sys.argv = previous_argv
    if result is None:
        return 0
    if isinstance(result, int):
        return result
    raise RuntimeError(f'{module.__name__}.main() returned unsupported value: {result!r}')

def run_stage(summary: dict[str, Any], name: str, module: ModuleType, arguments: list[str], expected_outputs: list[Path]) -> None:
    started_at = now_iso()
    start_seconds = time.monotonic()
    print()
    print(f'Pipeline stage started: {name}')
    print('=' * (24 + len(name)))
    stage_result: dict[str, Any] = {'name': name, 'module': module.__name__, 'started_at': started_at, 'arguments': list(arguments), 'status': 'running', 'exit_code': None, 'elapsed_seconds': None, 'expected_outputs': [str(path) for path in expected_outputs]}
    summary.setdefault('stages', []).append(stage_result)
    try:
        exit_code = invoke_module_main(module, arguments)
    except KeyboardInterrupt:
        stage_result['status'] = 'interrupted'
        stage_result['exit_code'] = EXIT_INTERRUPTED
        stage_result['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
        raise
    except Exception as error:
        stage_result['status'] = 'failed'
        stage_result['exit_code'] = EXIT_PARTIAL
        stage_result['error'] = str(error)
        stage_result['traceback'] = traceback.format_exc(limit=20)
        stage_result['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
        raise PipelineFailure(f'Stage {name!r} raised an exception: {error}', EXIT_PARTIAL) from error
    stage_result['exit_code'] = exit_code
    stage_result['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
    if exit_code != 0:
        stage_result['status'] = 'failed'
        raise PipelineFailure(f'Stage {name!r} exited with code {exit_code}', exit_code)
    missing_outputs = [str(path) for path in expected_outputs if not path.is_file()]
    if missing_outputs:
        stage_result['status'] = 'failed'
        stage_result['missing_outputs'] = missing_outputs
        raise PipelineFailure(f'Stage {name!r} did not create required output(s): ' + ', '.join(missing_outputs), EXIT_REQUIRED_OUTPUT_MISSING)
    stage_result['status'] = 'succeeded'
    print(f"Pipeline stage completed: {name} in {stage_result['elapsed_seconds']}s")

def count_csv_rows(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open(newline='', encoding='utf-8') as input_file:
        return sum((1 for _ in csv.DictReader(input_file)))

def count_parent_cache_failures(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return 1
    entries = payload.get('entries', {})
    if not isinstance(entries, dict):
        return 1
    return sum((1 for entry in entries.values() if isinstance(entry, dict) and entry.get('status') == 'failed'))

def ensure_empty_rollup_failure_report(path: Path) -> None:
    if path.exists():
        return
    ensure_parent_dir(path)
    fieldnames = ['parent_project', 'parent_version', 'child_project', 'child_version', 'child_version_href', 'source', 'stage', 'elapsed_seconds', 'elapsed_human', 'timeout_seconds', 'retries', 'attempts_per_request', 'error']
    with path.open('w', newline='', encoding='utf-8') as output_file:
        csv.DictWriter(output_file, fieldnames=fieldnames).writeheader()

def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise PipelineFailure(f'Jira configuration does not exist: {path}', EXIT_ARGUMENT_ERROR)
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineFailure(f'Jira configuration is invalid: {error}', EXIT_ARGUMENT_ERROR) from error
    if not isinstance(payload, dict):
        raise PipelineFailure('Jira configuration must contain a JSON object', EXIT_ARGUMENT_ERROR)
    return payload

def validate_environment(args: argparse.Namespace, data_root: Path) -> dict[str, Any]:
    data_root.mkdir(parents=True, exist_ok=True)
    write_test = data_root / f'.write-test-{uuid.uuid4().hex}'
    try:
        write_test.write_text('write-test', encoding='utf-8')
    except OSError as error:
        raise PipelineFailure(f'Output directory is not writable: {data_root}: {error}', EXIT_ARGUMENT_ERROR) from error
    finally:
        write_test.unlink(missing_ok=True)
    missing_blackduck = [name for name in ('BLACKDUCK_URL', 'BLACKDUCK_API_TOKEN') if not os.getenv(name)]
    if missing_blackduck:
        raise PipelineFailure('Missing required Black Duck environment variable(s): ' + ', '.join(missing_blackduck), EXIT_ARGUMENT_ERROR)
    config = load_config(Path(args.config))
    jira_config = config.get('jira', {})
    if not isinstance(jira_config, dict):
        raise PipelineFailure('jira configuration must be an object', EXIT_ARGUMENT_ERROR)
    project_key = str(jira_config.get('project_key') or '').strip()
    if not project_key:
        raise PipelineFailure('jira.project_key must be configured', EXIT_ARGUMENT_ERROR)
    if args.ca_bundle:
        ca_path = Path(args.ca_bundle)
        if not ca_path.is_file():
            raise PipelineFailure(f'Configured CA bundle does not exist: {ca_path}', EXIT_ARGUMENT_ERROR)
        os.environ['SSL_CERT_FILE'] = str(ca_path)
    if args.apply:
        jira_url = str(os.getenv('JIRA_URL') or jira_config.get('url') or '').strip()
        if not jira_url:
            raise PipelineFailure('JIRA_URL or jira.url is required for apply mode', EXIT_ARGUMENT_ERROR)
        auth_mode = str(jira_config.get('auth_mode') or 'basic').strip().lower()
        if auth_mode == 'bearer':
            if not os.getenv('JIRA_PAT'):
                raise PipelineFailure('JIRA_PAT is required for Jira bearer auth', EXIT_ARGUMENT_ERROR)
        elif not (os.getenv('JIRA_USER') and os.getenv('JIRA_API_TOKEN')):
            raise PipelineFailure('JIRA_USER and JIRA_API_TOKEN are required for Jira basic auth', EXIT_ARGUMENT_ERROR)
    return {'output_root': str(data_root), 'config': str(args.config), 'jira_project_key': project_key, 'tls_mode': 'insecure' if args.insecure else f'custom-ca:{args.ca_bundle}' if args.ca_bundle else 'verified-system-ca'}

def promote_outputs(run_dir: Path, active_dir: Path) -> list[str]:
    names = ['parent_projects.csv', 'parent_project_changes.csv', 'subp_vuln_rollup_failures.csv', 'findings.csv', 'jira-hierarchy-plan.json', 'jira-hierarchy-summary.csv', 'jira-hierarchy-nodes.csv', 'jira-rollup-plan.json', 'jira-rollup-results.csv']
    promoted: list[str] = []
    for name in names:
        source = run_dir / name
        if not source.is_file():
            continue
        destination = active_dir / name
        atomic_copy(source, destination)
        promoted.append(str(destination))
    return promoted

def prune_run_directories(runs_dir: Path, current_run_id: str, retain_count: int) -> None:
    if retain_count < 1 or not runs_dir.is_dir():
        return
    directories = sorted((path for path in runs_dir.iterdir() if path.is_dir() and path.name != current_run_id), key=lambda path: path.name, reverse=True)
    for old_directory in directories[retain_count - 1:]:
        shutil.rmtree(old_directory, ignore_errors=True)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run the complete Black Duck to Jira hierarchy pipeline once and exit.')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--dry-run', action='store_true', help='Build the Jira plan without applying Jira changes.')
    mode.add_argument('--apply', action='store_true', help='Apply the generated hierarchy to Jira.')
    failure_mode = parser.add_mutually_exclusive_group()
    failure_mode.add_argument('--strict', dest='strict', action='store_true', help='Reject Jira publishing when Black Duck failures exist.')
    failure_mode.add_argument('--allow-partial', dest='strict', action='store_false', help='Publish successful findings despite Black Duck failures and return a partial exit status.')
    parser.set_defaults(strict=True)
    tls_mode = parser.add_mutually_exclusive_group()
    tls_mode.add_argument('--ca-bundle', help='Customer root/intermediate CA bundle path.')
    tls_mode.add_argument('--insecure', action='store_true', help='Disable TLS verification for non-production testing.')
    parser.add_argument('--config', default=package_path('jira', 'config', 'jira-rollup-config.json'), help='Jira publisher configuration JSON.')
    parser.add_argument('--preflight-only', action='store_true', help='Validate configuration, storage, and secrets only.')
    parser.add_argument('--refresh-parents', action='store_true', help='Force a full parent relationship rescan.')
    parser.add_argument('--refresh-blackduck-cache', action='store_true', help='Refresh the vulnerability API cache.')
    parser.add_argument('--refresh-existing-jira', action='store_true', help='Reconcile local Jira state against Jira.')
    parser.add_argument('--sync-existing-fields', action='store_true', help='Update configured managed fields on existing issues.')
    parser.add_argument('--max-create', type=int, help='Maximum Jira issues to create during apply.')
    parser.add_argument('--only-parent-project')
    parser.add_argument('--only-parent-version')
    parser.add_argument('--only-subproject')
    parser.add_argument('--only-vulnerability')
    parser.add_argument('--project-name-contains', help='Optional parent discovery project-name filter.')
    parser.add_argument('--threshold', type=float, default=7.0)
    parser.add_argument('--score-field', default='overallScore')
    parser.add_argument('--entity-custom-field', default='foo Entity')
    parser.add_argument('--require-entity', action='store_true')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--retries', type=int, default=2)
    parser.add_argument('--retry-delay', type=float, default=2.0)
    parser.add_argument('--page-limit', type=int, default=500)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--description-format', choices=['wiki', 'adf'], default='wiki')
    parser.add_argument('--retain-runs', type=int, default=10)
    parser.add_argument('--lock-stale-seconds', type=int, default=28800)
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--resolve-bom-names', action='store_true', help='Enable exact BOM component name/version fallback during parent relationship discovery.')
    parser.add_argument('--parent-timeout', type=int, default=90, help='Parent-discovery HTTP timeout. Default: 90.')
    parser.add_argument('--parent-retries', type=int, default=2, help='Parent-discovery retry count. Default: 2.')
    parser.add_argument('--parent-workers', type=int, help='Parent-discovery worker count. When omitted, --workers is used.')
    parser.add_argument('--rollup-workers', type=int, help='Vulnerability-rollup worker count. When omitted, --workers is used.')
    parser.add_argument('--rollup-timeout', type=int, default=30, help='Vulnerability-rollup HTTP timeout. Default: 30.')
    parser.add_argument('--rollup-retries', type=int, default=1, help='Vulnerability-rollup retry count. Default: 1.')
    parser.add_argument('--hierarchy-limit', type=int, help='Optional findings limit passed to hierarchy planning. This may produce incomplete component aggregation.')
    parser.add_argument('--allow-empty', action='store_true', help='Allow zero relationships, findings, or hierarchy nodes. Empty results fail safely by default.')
    return parser.parse_args()

def validate_args(args: argparse.Namespace) -> None:
    args.resolve_bom_names = bool(
        getattr(args, "resolve_bom_names", False)
    )
    args.allow_empty = bool(
        getattr(args, "allow_empty", False)
    )
    args.workers = int(getattr(args, "workers", 2))
    args.parent_timeout = int(
        getattr(args, "parent_timeout", getattr(args, "timeout", 90))
    )
    args.parent_retries = int(
        getattr(args, "parent_retries", getattr(args, "retries", 2))
    )

    parent_workers = getattr(args, "parent_workers", None)
    rollup_workers = getattr(args, "rollup_workers", None)

    args.parent_workers = int(
        parent_workers
        if parent_workers is not None
        else args.workers
    )
    args.rollup_workers = int(
        rollup_workers
        if rollup_workers is not None
        else args.workers
    )
    args.rollup_timeout = int(
        getattr(args, "rollup_timeout", getattr(args, "timeout", 30))
    )
    args.rollup_retries = int(
        getattr(args, "rollup_retries", getattr(args, "retries", 1))
    )
    args.hierarchy_limit = getattr(args, "hierarchy_limit", None)

    if args.max_create is not None and args.max_create < 1:
        raise PipelineFailure(
            "--max-create must be greater than zero",
            EXIT_ARGUMENT_ERROR,
        )

    if args.timeout <= 0:
        raise PipelineFailure(
            "--timeout must be greater than zero",
            EXIT_ARGUMENT_ERROR,
        )

    if args.retries < 0:
        raise PipelineFailure(
            "--retries cannot be negative",
            EXIT_ARGUMENT_ERROR,
        )

    if args.parent_timeout <= 0:
        raise PipelineFailure(
            "--parent-timeout must be greater than zero",
            EXIT_ARGUMENT_ERROR,
        )

    if args.parent_retries < 0:
        raise PipelineFailure(
            "--parent-retries cannot be negative",
            EXIT_ARGUMENT_ERROR,
        )

    if args.rollup_timeout <= 0:
        raise PipelineFailure(
            "--rollup-timeout must be greater than zero",
            EXIT_ARGUMENT_ERROR,
        )

    if args.rollup_retries < 0:
        raise PipelineFailure(
            "--rollup-retries cannot be negative",
            EXIT_ARGUMENT_ERROR,
        )

    for flag, value in (
        ("--workers", args.workers),
        ("--parent-workers", args.parent_workers),
        ("--rollup-workers", args.rollup_workers),
    ):
        if value <= 0:
            raise PipelineFailure(
                f"{flag} must be greater than zero",
                EXIT_ARGUMENT_ERROR,
            )

        if value > MAX_IO_WORKERS:
            print(
                f"Warning: {flag} {value} exceeds maximum "
                f"{MAX_IO_WORKERS}; clamping.",
                file=sys.stderr,
            )

    args.workers = bounded_worker_count(
        args.workers,
        maximum=MAX_IO_WORKERS,
    )
    args.parent_workers = bounded_worker_count(
        args.parent_workers,
        maximum=MAX_IO_WORKERS,
    )
    args.rollup_workers = bounded_worker_count(
        args.rollup_workers,
        maximum=MAX_IO_WORKERS,
    )

    if args.hierarchy_limit is not None and args.hierarchy_limit < 1:
        raise PipelineFailure(
            "--hierarchy-limit must be greater than zero",
            EXIT_ARGUMENT_ERROR,
        )

    if args.page_limit <= 0:
        raise PipelineFailure(
            "--page-limit must be greater than zero",
            EXIT_ARGUMENT_ERROR,
        )

    if args.retain_runs < 1:
        raise PipelineFailure(
            "--retain-runs must be greater than zero",
            EXIT_ARGUMENT_ERROR,
        )

    if args.lock_stale_seconds < 60:
        raise PipelineFailure(
            "--lock-stale-seconds must be at least 60",
            EXIT_ARGUMENT_ERROR,
        )

    if not args.apply:
        args.dry_run = True

def run_pipeline(args: argparse.Namespace) -> int:
    validate_args(args)
    data_root = output_root()
    active_dir = data_root / 'jira'
    cache_dir = active_dir / 'cache'
    state_dir = active_dir / 'state'
    runs_dir = active_dir / 'runs'
    for directory in (active_dir, cache_dir, state_dir, runs_dir):
        directory.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + f'-{uuid.uuid4().hex[:8]}'
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    summary: dict[str, Any] = {'run_id': run_id, 'status': 'starting', 'mode': 'apply' if args.apply else 'dry-run', 'strict': bool(args.strict), 'started_at': now_iso(), 'finished_at': '', 'elapsed_seconds': None, 'run_directory': str(run_dir), 'active_directory': str(active_dir), 'stages': [], 'failure_counts': {'parent_scan_failures': 0, 'rollup_failures': 0}, 'promoted_outputs': [], 'error': '', 'exit_code': None}
    summary['concurrency'] = {
        'workers': args.workers,
        'parent_workers': args.parent_workers,
        'rollup_workers': args.rollup_workers,
    }
    active_summary = active_dir / 'pipeline-run-summary.json'
    run_summary = run_dir / 'pipeline-run-summary.json'
    start_seconds = time.monotonic()

    def save_summary() -> None:
        atomic_write_json(run_summary, summary)
        atomic_write_json(active_summary, summary)
    lock_path = active_dir / 'pipeline.lock'
    try:
        with PipelineLock(lock_path, run_id, args.lock_stale_seconds):
            summary['preflight'] = validate_environment(args, data_root)
            summary['status'] = 'running'
            save_summary()
            if args.preflight_only:
                summary['status'] = 'succeeded'
                summary['finished_at'] = now_iso()
                summary['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
                summary['exit_code'] = EXIT_SUCCESS
                save_summary()
                return EXIT_SUCCESS
            parent_cache = cache_dir / 'parent_projects_cache.json'
            rollup_cache = cache_dir / 'subp_vuln_rollup_cache.json'
            jira_state = state_dir / 'jira-rollup-state.json'
            parent_output = run_dir / 'parent_projects.csv'
            parent_changes = run_dir / 'parent_project_changes.csv'
            parent_arguments = ['--out', str(parent_output), '--changes-out', str(parent_changes), '--cache', str(parent_cache), '--refresh-older-than-days', '7', '--timeout', str(args.parent_timeout), '--retries', str(args.parent_retries), '--retry-delay', str(args.retry_delay), '--workers', str(args.parent_workers)]
            parent_arguments.extend(
                ['--page-limit', str(args.page_limit)]
            )
            if args.refresh_parents:
                parent_arguments.append('--refresh-all')
            if args.resolve_bom_names:
                parent_arguments.append('--resolve-bom-names')
            if args.project_name_contains:
                parent_arguments.extend(['--project-name-contains', args.project_name_contains])
            if args.ca_bundle:
                parent_arguments.extend(['--ca-bundle', args.ca_bundle])
            elif args.insecure:
                parent_arguments.append('--insecure')
            if args.debug:
                parent_arguments.append('--debug')
            run_stage(summary, 'find-parent-projects', find_parent_projects, parent_arguments, [parent_output, parent_changes, parent_cache])
            parent_relationship_count = count_csv_rows(parent_output)
            summary.setdefault('source_counts', {})['parent_relationships'] = parent_relationship_count
            save_summary()
            if parent_relationship_count == 0 and (not args.allow_empty):
                raise PipelineFailure('Parent discovery produced zero relationships. Use --resolve-bom-names when required, --refresh-parents to replace an old empty cache, or --allow-empty when zero relationships are valid.', EXIT_STRICT_REJECTION)
            save_summary()
            parent_failure_count = count_parent_cache_failures(parent_cache)
            summary['failure_counts']['parent_scan_failures'] = parent_failure_count
            findings_output = run_dir / 'findings.csv'
            rollup_failures = run_dir / 'subp_vuln_rollup_failures.csv'
            rollup_arguments = ['--parents-csv', str(parent_output), '--out', str(findings_output), '--failures-out', str(rollup_failures), '--api-cache', str(rollup_cache), '--threshold', str(args.threshold), '--score-field', args.score_field, '--entity-custom-field', args.entity_custom_field, '--timeout', str(args.rollup_timeout), '--retries', str(args.rollup_retries), '--retry-delay', str(args.retry_delay), '--page-limit', str(args.page_limit)]
            rollup_arguments.extend(
                ['--workers', str(args.rollup_workers)]
            )
            if args.only_parent_project:
                rollup_arguments.extend(['--parent-project', args.only_parent_project])
            if args.only_parent_version:
                rollup_arguments.extend(['--parent-version', args.only_parent_version])
            if args.only_subproject:
                rollup_arguments.extend(['--only-child-project', args.only_subproject])
            if args.require_entity:
                rollup_arguments.append('--require-entity')
            if args.refresh_blackduck_cache:
                rollup_arguments.append('--refresh-api-cache')
            if args.insecure:
                rollup_arguments.append('--insecure')
            if args.debug:
                rollup_arguments.append('--debug')
            run_stage(summary, 'collect-vulnerability-rollup', subp_vuln_rollup, rollup_arguments, [findings_output, rollup_cache])
            finding_count = count_csv_rows(findings_output)
            summary.setdefault('source_counts', {})['findings'] = finding_count
            save_summary()
            if finding_count == 0 and (not args.allow_empty):
                raise PipelineFailure('Vulnerability rollup produced zero findings. Jira publishing was blocked. Use --allow-empty only when an empty result is known to be valid.', EXIT_STRICT_REJECTION)
            ensure_empty_rollup_failure_report(rollup_failures)
            rollup_failure_count = count_csv_rows(rollup_failures)
            summary['failure_counts']['rollup_failures'] = rollup_failure_count
            save_summary()
            partial_detected = bool(parent_failure_count or rollup_failure_count)
            if partial_detected and args.strict:
                raise PipelineFailure(f'Strict mode rejected Jira publishing because parent failures={parent_failure_count}, rollup failures={rollup_failure_count}', EXIT_STRICT_REJECTION)
            hierarchy_plan = run_dir / 'jira-hierarchy-plan.json'
            hierarchy_summary = run_dir / 'jira-hierarchy-summary.csv'
            hierarchy_nodes = run_dir / 'jira-hierarchy-nodes.csv'
            planner_arguments = ['--findings', str(findings_output), '--hierarchy-mode', 'vulnerability-remediation', '--plan-out', str(hierarchy_plan), '--summary-out', str(hierarchy_summary), '--nodes-out', str(hierarchy_nodes)]
            if args.hierarchy_limit is not None:
                planner_arguments.extend(['--limit', str(args.hierarchy_limit)])
            filter_arguments = [('--only-parent-project', args.only_parent_project), ('--only-parent-version', args.only_parent_version), ('--only-subproject', args.only_subproject), ('--only-vulnerability', args.only_vulnerability)]
            for flag, value in filter_arguments:
                if value:
                    planner_arguments.extend([flag, value])
            if args.debug:
                planner_arguments.append('--debug')
            run_stage(summary, 'build-jira-hierarchy', findings_hierarchy_plan, planner_arguments, [hierarchy_plan, hierarchy_summary, hierarchy_nodes])
            hierarchy_validation_payload = json.loads(hierarchy_plan.read_text(encoding='utf-8'))
            hierarchy_validation_nodes = hierarchy_validation_payload.get('nodes')
            if not isinstance(hierarchy_validation_nodes, list):
                raise PipelineFailure('Generated hierarchy plan has no nodes array', EXIT_REQUIRED_OUTPUT_MISSING)
            hierarchy_node_count = len(hierarchy_validation_nodes)
            summary.setdefault('source_counts', {})['hierarchy_nodes'] = hierarchy_node_count
            save_summary()
            if hierarchy_node_count == 0 and (not args.allow_empty):
                raise PipelineFailure('Hierarchy planning produced zero nodes. Jira publishing was blocked. Use --allow-empty only when an empty plan is known to be valid.', EXIT_STRICT_REJECTION)
            save_summary()
            plan_payload = json.loads(hierarchy_plan.read_text(encoding='utf-8'))
            plan_nodes = plan_payload.get('nodes')
            if not isinstance(plan_nodes, list):
                raise PipelineFailure('Generated hierarchy plan has no nodes array', EXIT_REQUIRED_OUTPUT_MISSING)
            summary['hierarchy_counts'] = plan_payload.get('node_counts', {})
            jira_results = run_dir / 'jira-rollup-results.csv'
            jira_publish_plan = run_dir / 'jira-rollup-plan.json'
            publisher_arguments = ['--hierarchy-plan', str(hierarchy_plan), '--config', str(args.config), '--state', str(jira_state), '--results-out', str(jira_results), '--plan-out', str(jira_publish_plan), '--description-format', args.description_format, '--timeout', str(args.timeout), '--retries', str(args.retries), '--retry-delay', str(args.retry_delay)]
            if args.apply:
                publisher_arguments.append('--apply')
            else:
                publisher_arguments.append('--dry-run')
            if args.refresh_existing_jira:
                publisher_arguments.append('--refresh-existing')
            if args.sync_existing_fields:
                publisher_arguments.append('--sync-existing-fields')
            if args.max_create is not None:
                publisher_arguments.extend(['--max-create', str(args.max_create)])
            if args.debug:
                publisher_arguments.append('--debug')
            run_stage(summary, 'publish-jira-hierarchy', findings_to_jira, publisher_arguments, [jira_results, jira_publish_plan])
            summary['promoted_outputs'] = promote_outputs(run_dir, active_dir)
            if partial_detected:
                summary['status'] = 'partial'
                exit_code = EXIT_PARTIAL
            else:
                summary['status'] = 'succeeded'
                exit_code = EXIT_SUCCESS
            summary['finished_at'] = now_iso()
            summary['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
            summary['exit_code'] = exit_code
            save_summary()
            prune_run_directories(runs_dir, run_id, args.retain_runs)
            return exit_code
    except KeyboardInterrupt:
        summary['status'] = 'interrupted'
        summary['error'] = 'Pipeline interrupted'
        summary['finished_at'] = now_iso()
        summary['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
        summary['exit_code'] = EXIT_INTERRUPTED
        save_summary()
        return EXIT_INTERRUPTED
    except PipelineFailure as error:
        summary['status'] = 'skipped_publish' if error.exit_code == EXIT_STRICT_REJECTION else 'failed'
        summary['error'] = str(error)
        summary['finished_at'] = now_iso()
        summary['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
        summary['exit_code'] = error.exit_code
        save_summary()
        print(f'ERROR: {error}', file=sys.stderr)
        return error.exit_code
    except Exception as error:
        summary['status'] = 'failed'
        summary['error'] = str(error)
        summary['traceback'] = traceback.format_exc(limit=30)
        summary['finished_at'] = now_iso()
        summary['elapsed_seconds'] = round(time.monotonic() - start_seconds, 3)
        summary['exit_code'] = EXIT_PARTIAL
        save_summary()
        print(f'ERROR: unexpected pipeline failure: {error}', file=sys.stderr)
        return EXIT_PARTIAL

def main() -> int:
    try:
        return run_pipeline(parse_args())
    except PipelineFailure as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print('Interrupted.', file=sys.stderr)
        return EXIT_INTERRUPTED
if __name__ == '__main__':
    raise SystemExit(main())
