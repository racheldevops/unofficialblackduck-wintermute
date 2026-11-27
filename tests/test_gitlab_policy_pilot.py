from wintermute.scm.onboarding.policy_pilot import (
    PolicyConfiguration,
    desired_files,
    link_endpoint,
    policy_text,
)


def configuration(
    state: str,
    *,
    link_scope: str = "project",
) -> PolicyConfiguration:
    return PolicyConfiguration(
        link_scope=link_scope,
        target_project=(
            "rhorner/"
            "coverity-python-scan-test"
        ),
        target_group="bd-releng",
        policy_project=(
            "rhorner/"
            "wintermute-security-policies"
        ),
        policy_namespace_type="user",
        central_project=(
            "rhorner/"
            "wintermute-security-scans"
        ),
        pilot_project=(
            "rhorner/"
            "coverity-python-scan-test"
        ),
        state=state,
    )


def test_disabled_policy_is_project_scoped() -> None:
    selected = configuration(
        "disabled"
    )
    text = policy_text(
        selected,
        pilot_project_id=20,
    )

    selected.validate()
    assert "enabled: false" in text
    assert "          - id: 20" in text
    assert (
        'project: "rhorner/'
        'wintermute-security-scans"'
        in text
    )
    assert link_endpoint(
        selected,
        20,
    ) == (
        "/projects/20/"
        "security_policy_project"
    )


def test_group_link_remains_available() -> None:
    selected = configuration(
        "disabled",
        link_scope="group",
    )

    selected.validate()
    assert link_endpoint(
        selected,
        10,
    ) == (
        "/groups/10/"
        "security_policy_project"
    )


def test_pilot_policy_changes_only_state() -> None:
    disabled = policy_text(
        configuration("disabled"),
        pilot_project_id=20,
    )
    pilot = policy_text(
        configuration("pilot"),
        pilot_project_id=20,
    )

    assert (
        disabled.replace(
            "enabled: false",
            "enabled: true",
        )
        == pilot
    )


def test_managed_files_record_project_link() -> None:
    files = desired_files(
        configuration("pilot"),
        link_target_id=20,
        pilot_project_id=20,
    )
    manifest = files[
        "wintermute-managed.json"
    ]

    assert set(files) == {
        (
            ".gitlab/security-policies/"
            "policy.yml"
        ),
        "wintermute-managed.json",
    }
    assert b'"policy_state": "pilot"' in (
        manifest
    )
    assert b'"scope": "project"' in (
        manifest
    )
    assert (
        b'"path": "rhorner/'
        b'coverity-python-scan-test"'
        in manifest
    )
