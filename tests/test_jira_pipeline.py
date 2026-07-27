from __future__ import annotations
import argparse
import json
from pathlib import Path
import pytest
from harness.jira import pipeline

def test_pipeline_lock_blocks_concurrent_run(tmp_path: Path) -> None:
    lock_path = tmp_path / 'pipeline.lock'
    with pipeline.PipelineLock(lock_path, 'run-one', 3600):
        with pytest.raises(pipeline.PipelineFailure) as captured:
            with pipeline.PipelineLock(lock_path, 'run-two', 3600):
                pass
        assert captured.value.exit_code == pipeline.EXIT_LOCKED

def test_default_mode_is_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('sys.argv', ['blackduck-jira-pipeline'])
    args = pipeline.parse_args()
    pipeline.validate_args(args)
    assert args.dry_run is True
    assert args.apply is False
    assert args.strict is True

def test_pipeline_promotes_successful_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('HARNESS_OUTPUT_DIR', str(tmp_path))
    monkeypatch.setenv('BLACKDUCK_URL', 'https://example.invalid')
    monkeypatch.setenv('BLACKDUCK_API_TOKEN', 'not-used')
    config_path = tmp_path / 'jira-config.json'
    config_path.write_text(json.dumps({'jira': {'project_key': 'TEST', 'auth_mode': 'basic'}}), encoding='utf-8')

    def fake_run_stage(summary, name, module, arguments, expected_outputs):
        del module
        for output in expected_outputs:
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.name == 'jira-hierarchy-plan.json':
                output.write_text(json.dumps({'schema_version': 3, 'hierarchy_mode': 'vulnerability-project', 'node_counts': {'epic_count': 0, 'story_count': 0, 'vulnerability_count': 0, 'total_node_count': 0}, 'nodes': []}), encoding='utf-8')
            elif output.suffix == '.json':
                output.write_text('{}', encoding='utf-8')
            else:
                output.write_text('header\n', encoding='utf-8')
        if name == 'find-parent-projects':
            cache_index = arguments.index('--cache') + 1
            cache_path = Path(arguments[cache_index])
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps({'entries': {}}), encoding='utf-8')
        if name == 'collect-vulnerability-rollup':
            cache_index = arguments.index('--api-cache') + 1
            cache_path = Path(arguments[cache_index])
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps({'entries': {}}), encoding='utf-8')
        summary.setdefault('stages', []).append({'name': name, 'status': 'succeeded', 'exit_code': 0})
    monkeypatch.setattr(pipeline, 'run_stage', fake_run_stage)
    args = argparse.Namespace(dry_run=True, apply=False, strict=True, ca_bundle=None, insecure=False, config=str(config_path), preflight_only=False, refresh_parents=False, refresh_blackduck_cache=False, refresh_existing_jira=False, sync_existing_fields=False, max_create=None, only_parent_project=None, only_parent_version=None, only_subproject=None, only_vulnerability=None, project_name_contains=None, threshold=7.0, score_field='overallScore', entity_custom_field='foo Entity', require_entity=False, timeout=60, retries=2, retry_delay=2.0, page_limit=500, workers=1, description_format='wiki', retain_runs=3, lock_stale_seconds=3600, debug=False, allow_empty=True)
    result = pipeline.run_pipeline(args)
    assert result == pipeline.EXIT_SUCCESS
    assert (tmp_path / 'jira' / 'jira-hierarchy-plan.json').is_file()
    assert (tmp_path / 'jira' / 'pipeline-run-summary.json').is_file()
