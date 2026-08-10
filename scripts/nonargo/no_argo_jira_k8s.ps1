[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet(
        "preflight",
        "build-push",
        "configure",
        "render",
        "deploy",
        "run",
        "wait",
        "status",
        "logs",
        "all",
        "help"
    )]
    [string] $Command = "help",

    [string] $JobName = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-EnvironmentValue {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [string] $Default = ""
    )

    $value = [Environment]::GetEnvironmentVariable($Name)

    if ([string]::IsNullOrWhiteSpace($value)) {
        return $Default
    }

    return $value
}

function Test-Truthy {
    param([string] $Value)

    return @(
        "1",
        "true",
        "yes",
        "on"
    ) -contains $Value.Trim().ToLowerInvariant()
}

function Require-Command {
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Invoke-External {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [string[]] $Arguments = @(),

        [int[]] $AllowedExitCodes = @(0)
    )

    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE

    if ($AllowedExitCodes -notcontains $exitCode) {
        throw (
            "$FilePath failed with exit code " +
            "$exitCode"
        )
    }
}

function Get-ExternalOutput {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [string[]] $Arguments = @(),

        [int[]] $AllowedExitCodes = @(0)
    )

    $output = & $FilePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($AllowedExitCodes -notcontains $exitCode) {
        throw (
            "$FilePath failed with exit code " +
            "$exitCode`: " +
            (($output | Out-String).Trim())
        )
    }

    return (($output | Out-String).Trim())
}

function Invoke-Kubectl {
    param(
        [string[]] $Arguments = @(),

        [int[]] $AllowedExitCodes = @(0)
    )

    $allArguments = @(
        "--context",
        $script:KubeContext
    ) + $Arguments

    Invoke-External `
        -FilePath "kubectl" `
        -Arguments $allArguments `
        -AllowedExitCodes $AllowedExitCodes
}

function Get-KubectlOutput {
    param(
        [string[]] $Arguments = @(),

        [int[]] $AllowedExitCodes = @(0)
    )

    $allArguments = @(
        "--context",
        $script:KubeContext
    ) + $Arguments

    return Get-ExternalOutput `
        -FilePath "kubectl" `
        -Arguments $allArguments `
        -AllowedExitCodes $AllowedExitCodes
}

function Apply-KubernetesObject {
    param(
        [Parameter(Mandatory)]
        [hashtable] $Object
    )

    $payload = $Object |
        ConvertTo-Json -Depth 30 -Compress

    $payload |
        & kubectl `
            --context $script:KubeContext `
            apply `
            --filename -

    if ($LASTEXITCODE -ne 0) {
        throw (
            "kubectl apply failed with exit code " +
            "$LASTEXITCODE"
        )
    }
}

function Read-PlainTextSecret {
    param(
        [Parameter(Mandatory)]
        [string] $EnvironmentName,

        [Parameter(Mandatory)]
        [string] $Prompt
    )

    $existing = Get-EnvironmentValue $EnvironmentName

    if (-not [string]::IsNullOrWhiteSpace($existing)) {
        return $existing
    }

    $secureValue = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
        $secureValue
    )

    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            $pointer
        )
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR(
            $pointer
        )
    }
}

$Root = (
    Resolve-Path (
        Join-Path $PSScriptRoot "..\.."
    )
).Path

$stateBase = Get-EnvironmentValue "LOCALAPPDATA"

if ([string]::IsNullOrWhiteSpace($stateBase)) {
    $stateBase = Join-Path $HOME ".local\state"
}

$StateDirectory = Get-EnvironmentValue `
    "WINTERMUTE_K8S_STATE_DIR" `
    (Join-Path $stateBase "blackduck-wintermute")

$Manifest = Join-Path `
    $StateDirectory `
    "rendered-jira-pipeline.yaml"

$LatestJobFile = Join-Path `
    $StateDirectory `
    "latest-jira-job.txt"

$KubeContext = Get-EnvironmentValue "KUBE_CONTEXT"

$Namespace = Get-EnvironmentValue `
    "KUBE_NAMESPACE" `
    "blackduck-wintermute"

$RegistryHost = Get-EnvironmentValue "REGISTRY_HOST"
$RegistryRepository = Get-EnvironmentValue "REGISTRY_REPOSITORY"
$ImageTag = Get-EnvironmentValue "IMAGE_TAG"
$JiraUrl = Get-EnvironmentValue "JIRA_URL"
$JiraProjectKey = Get-EnvironmentValue "JIRA_PROJECT_KEY"

$PipelineMode = Get-EnvironmentValue `
    "PIPELINE_MODE" `
    "dry-run"

$ConfirmApply = Get-EnvironmentValue "CONFIRM_APPLY"

$MaxCreate = [int] (
    Get-EnvironmentValue "MAX_CREATE" "10"
)

$PvcSize = Get-EnvironmentValue "PVC_SIZE" "10Gi"

$Workers = [int] (
    Get-EnvironmentValue "WORKERS" "2"
)

$ParentWorkers = [int] (
    Get-EnvironmentValue `
        "PARENT_WORKERS" `
        ([string] $Workers)
)

$RollupWorkers = [int] (
    Get-EnvironmentValue `
        "ROLLUP_WORKERS" `
        ([string] $Workers)
)

$Schedule = Get-EnvironmentValue `
    "CRON_SCHEDULE" `
    "0 2 * * *"

$Timezone = Get-EnvironmentValue `
    "CRON_TIMEZONE" `
    "Etc/UTC"

$JiraInsecure = Test-Truthy (
    Get-EnvironmentValue "JIRA_INSECURE" "false"
)

$EnableSchedule = Test-Truthy (
    Get-EnvironmentValue "ENABLE_SCHEDULE" "false"
)

$WaitTimeout = [int] (
    Get-EnvironmentValue "JOB_TIMEOUT_SECONDS" "3600"
)

New-Item `
    -ItemType Directory `
    -Force `
    -Path $StateDirectory |
    Out-Null

function Resolve-ImageTag {
    if (-not [string]::IsNullOrWhiteSpace($script:ImageTag)) {
        return
    }

    Require-Command "git"

    $script:ImageTag = Get-ExternalOutput `
        -FilePath "git" `
        -Arguments @(
            "-C",
            $Root,
            "rev-parse",
            "HEAD"
        )
}

function Require-Context {
    Require-Command "kubectl"

    if ([string]::IsNullOrWhiteSpace($script:KubeContext)) {
        throw "Set KUBE_CONTEXT explicitly"
    }

    Invoke-Kubectl -Arguments @(
        "cluster-info"
    )
}

function Require-ImageSettings {
    if ([string]::IsNullOrWhiteSpace($script:RegistryHost)) {
        throw "Set REGISTRY_HOST"
    }

    if ([string]::IsNullOrWhiteSpace($script:RegistryRepository)) {
        throw "Set REGISTRY_REPOSITORY"
    }

    Resolve-ImageTag
}

function Require-RenderSettings {
    Require-ImageSettings

    if ([string]::IsNullOrWhiteSpace($script:JiraUrl)) {
        throw "Set JIRA_URL"
    }

    if ([string]::IsNullOrWhiteSpace($script:JiraProjectKey)) {
        throw "Set JIRA_PROJECT_KEY"
    }

    if (
        $script:PipelineMode -eq "apply" -and
        $script:ConfirmApply -ne "APPLY"
    ) {
        throw "Apply mode requires CONFIRM_APPLY=APPLY"
    }
}

function Get-ImageName {
    Require-ImageSettings

    return (
        $script:RegistryHost.TrimEnd("/") +
        "/" +
        $script:RegistryRepository.TrimStart("/") +
        ":" +
        $script:ImageTag
    )
}

function Invoke-Preflight {
    Require-Context

    Write-Host "Context: $KubeContext"
    Write-Host "Namespace: $Namespace"
    Write-Host ""

    Invoke-Kubectl -Arguments @(
        "get",
        "nodes",
        "-o",
        "wide"
    )

    Write-Host ""

    Invoke-Kubectl -Arguments @(
        "get",
        "storageclass"
    )

    Write-Host ""

    foreach ($resource in @(
        "cronjobs.batch",
        "jobs.batch",
        "persistentvolumeclaims",
        "secrets"
    )) {
        $answer = Get-KubectlOutput -Arguments @(
            "auth",
            "can-i",
            "create",
            $resource,
            "--namespace",
            $Namespace
        )

        Write-Host "create ${resource}: $answer"

        if ($answer.Trim().ToLowerInvariant() -ne "yes") {
            throw (
                "Current Kubernetes identity cannot create " +
                "$resource in namespace $Namespace"
            )
        }
    }
}

function Invoke-BuildPush {
    Require-Command "docker"
    Require-ImageSettings

    $image = Get-ImageName

    Write-Host "Building $image"

    Invoke-External `
        -FilePath "docker" `
        -Arguments @(
            "build",
            "--pull",
            "--target",
            "runtime",
            "--tag",
            $image,
            $Root
        )

    Invoke-External `
        -FilePath "docker" `
        -Arguments @(
            "run",
            "--rm",
            $image,
            "--help"
        )

    Write-Host "Pushing $image"

    Invoke-External `
        -FilePath "docker" `
        -Arguments @(
            "push",
            $image
        )
}

function Invoke-Configure {
    Require-Context
    Require-ImageSettings

    Apply-KubernetesObject -Object @{
        apiVersion = "v1"
        kind = "Namespace"
        metadata = @{
            name = $Namespace
        }
    }

    $blackDuckUrl = Get-EnvironmentValue "BLACKDUCK_URL"

    if ([string]::IsNullOrWhiteSpace($blackDuckUrl)) {
        $blackDuckUrl = Read-Host "Black Duck URL"
    }

    if ([string]::IsNullOrWhiteSpace($script:JiraUrl)) {
        $script:JiraUrl = Read-Host "Jira URL"
    }

    if ([string]::IsNullOrWhiteSpace($script:JiraProjectKey)) {
        $script:JiraProjectKey = Read-Host "Jira project key"
    }

    $jiraUser = Get-EnvironmentValue "JIRA_USER"

    if ([string]::IsNullOrWhiteSpace($jiraUser)) {
        $jiraUser = Read-Host "Jira user"
    }

    $blackDuckToken = Read-PlainTextSecret `
        -EnvironmentName "BLACKDUCK_API_TOKEN" `
        -Prompt "Black Duck API token"

    $jiraToken = Read-PlainTextSecret `
        -EnvironmentName "JIRA_API_TOKEN" `
        -Prompt "Jira API token"

    try {
        foreach ($entry in @{
            BLACKDUCK_URL = $blackDuckUrl
            BLACKDUCK_API_TOKEN = $blackDuckToken
            JIRA_URL = $script:JiraUrl
            JIRA_USER = $jiraUser
            JIRA_API_TOKEN = $jiraToken
        }.GetEnumerator()) {
            if (
                [string]::IsNullOrWhiteSpace(
                    [string] $entry.Value
                )
            ) {
                throw "$($entry.Key) must not be empty"
            }
        }

        Apply-KubernetesObject -Object @{
            apiVersion = "v1"
            kind = "Secret"
            metadata = @{
                name = "blackduck-wintermute-credentials"
                namespace = $Namespace
            }
            type = "Opaque"
            stringData = @{
                BLACKDUCK_URL = $blackDuckUrl.TrimEnd("/")
                BLACKDUCK_API_TOKEN = $blackDuckToken
                JIRA_URL = $script:JiraUrl.TrimEnd("/")
                JIRA_USER = $jiraUser
                JIRA_API_TOKEN = $jiraToken
            }
        }

        $registryUser = Get-EnvironmentValue "REGISTRY_USERNAME"

        if ([string]::IsNullOrWhiteSpace($registryUser)) {
            $registryUser = Read-Host (
                "Registry username " +
                "(blank for cluster-integrated registry)"
            )
        }

        $registryPassword = ""

        if (-not [string]::IsNullOrWhiteSpace($registryUser)) {
            $registryPassword = Read-PlainTextSecret `
                -EnvironmentName "REGISTRY_PASSWORD" `
                -Prompt "Registry password"
        }

        try {
            $auths = @{}

            if (-not [string]::IsNullOrWhiteSpace($registryUser)) {
                $pair = "${registryUser}:${registryPassword}"
                $auth = [Convert]::ToBase64String(
                    [Text.Encoding]::UTF8.GetBytes($pair)
                )

                $auths[$RegistryHost] = @{
                    username = $registryUser
                    password = $registryPassword
                    auth = $auth
                }
            }

            $dockerConfiguration = @{
                auths = $auths
            } |
                ConvertTo-Json -Depth 10 -Compress

            Apply-KubernetesObject -Object @{
                apiVersion = "v1"
                kind = "Secret"
                metadata = @{
                    name = "blackduck-wintermute-registry"
                    namespace = $Namespace
                }
                type = "kubernetes.io/dockerconfigjson"
                stringData = @{
                    ".dockerconfigjson" = $dockerConfiguration
                }
            }
        }
        finally {
            $registryPassword = $null
        }
    }
    finally {
        $blackDuckToken = $null
        $jiraToken = $null
    }

    Write-Host "Credentials configured."
}

function Invoke-Render {
    Require-Command "python"
    Require-Command "kubectl"
    Require-RenderSettings

    $arguments = @(
        (Join-Path $PSScriptRoot "render_jira_cronjob.py"),
        "--project-root",
        $Root,
        "--output",
        $Manifest,
        "--registry-host",
        $RegistryHost,
        "--registry-repository",
        $RegistryRepository,
        "--image-tag",
        $ImageTag,
        "--namespace",
        $Namespace,
        "--jira-url",
        $JiraUrl,
        "--jira-project-key",
        $JiraProjectKey,
        "--pipeline-mode",
        $PipelineMode,
        "--max-create",
        ([string] $MaxCreate),
        "--pvc-size",
        $PvcSize,
        "--workers",
        ([string] $Workers),
        "--parent-workers",
        ([string] $ParentWorkers),
        "--rollup-workers",
        ([string] $RollupWorkers),
        "--schedule",
        $Schedule,
        "--timezone",
        $Timezone,
        "--kubectl",
        "kubectl"
    )

    if ($ConfirmApply -eq "APPLY") {
        $arguments += "--confirm-apply"
    }

    if ($JiraInsecure) {
        $arguments += "--jira-insecure"
    }

    if ($EnableSchedule) {
        $arguments += "--enable-schedule"
    }

    Invoke-External `
        -FilePath "python" `
        -Arguments $arguments
}

function Invoke-Deploy {
    Require-Context
    Require-RenderSettings
    Invoke-Render

    Apply-KubernetesObject -Object @{
        apiVersion = "v1"
        kind = "Namespace"
        metadata = @{
            name = $Namespace
        }
    }

    foreach ($secret in @(
        "blackduck-wintermute-credentials",
        "blackduck-wintermute-registry"
    )) {
        Invoke-Kubectl -Arguments @(
            "get",
            "secret",
            $secret,
            "--namespace",
            $Namespace
        )
    }

    Write-Host "Reviewing Kubernetes diff"

    Invoke-Kubectl `
        -Arguments @(
            "diff",
            "--namespace",
            $Namespace,
            "--filename",
            $Manifest
        ) `
        -AllowedExitCodes @(0, 1)

    Invoke-Kubectl -Arguments @(
        "apply",
        "--server-side",
        "--field-manager",
        "blackduck-wintermute",
        "--filename",
        $Manifest
    )

    Invoke-Kubectl -Arguments @(
        "get",
        "cronjob,pvc,configmap",
        "--namespace",
        $Namespace
    )
}

function Start-ManualJob {
    Require-Context

    Invoke-Kubectl -Arguments @(
        "get",
        "cronjob",
        "blackduck-jira-pipeline",
        "--namespace",
        $Namespace
    )

    $job = (
        "blackduck-jira-manual-" +
        ([DateTimeOffset]::UtcNow).ToUnixTimeSeconds()
    )

    Invoke-Kubectl -Arguments @(
        "create",
        "job",
        "--namespace",
        $Namespace,
        "--from=cronjob/blackduck-jira-pipeline",
        $job
    )

    [IO.File]::WriteAllText(
        $LatestJobFile,
        "$job`n",
        (
            New-Object Text.UTF8Encoding($false)
        )
    )

    Write-Host "Submitted job: $job"

    return $job
}

function Get-LatestJob {
    if (-not [string]::IsNullOrWhiteSpace($JobName)) {
        return $JobName
    }

    if (-not (Test-Path $LatestJobFile)) {
        throw "No saved manual Job"
    }

    $selected = (
        Get-Content $LatestJobFile -Raw
    ).Trim()

    if ([string]::IsNullOrWhiteSpace($selected)) {
        throw "Saved manual Job name is empty"
    }

    return $selected
}

function Show-JobLogs {
    param([string] $SelectedJob = "")

    Require-Context

    if ([string]::IsNullOrWhiteSpace($SelectedJob)) {
        $SelectedJob = Get-LatestJob
    }

    Invoke-Kubectl -Arguments @(
        "logs",
        "--namespace",
        $Namespace,
        "job/$SelectedJob",
        "--all-containers=true",
        "--tail=500"
    )
}

function Show-JobStatus {
    Require-Context
    $selected = Get-LatestJob

    Invoke-Kubectl -Arguments @(
        "get",
        "jobs,pods",
        "--namespace",
        $Namespace,
        "--selector",
        "job-name=$selected",
        "-o",
        "wide"
    )
}

function Wait-ManualJob {
    Require-Context
    $selected = Get-LatestJob
    $started = ([DateTimeOffset]::UtcNow).ToUnixTimeSeconds()

    while ($true) {
        $complete = Get-KubectlOutput -Arguments @(
            "get",
            "job",
            $selected,
            "--namespace",
            $Namespace,
            "-o",
            'jsonpath={.status.conditions[?(@.type=="Complete")].status}'
        )

        $failed = Get-KubectlOutput -Arguments @(
            "get",
            "job",
            $selected,
            "--namespace",
            $Namespace,
            "-o",
            'jsonpath={.status.conditions[?(@.type=="Failed")].status}'
        )

        if ($complete -eq "True") {
            Show-JobLogs -SelectedJob $selected
            return
        }

        if ($failed -eq "True") {
            try {
                Show-JobLogs -SelectedJob $selected
            }
            catch {
                Write-Warning $_
            }

            Invoke-Kubectl -Arguments @(
                "describe",
                "job",
                $selected,
                "--namespace",
                $Namespace
            )

            throw "Job failed: $selected"
        }

        $current = ([DateTimeOffset]::UtcNow).ToUnixTimeSeconds()

        if (($current - $started) -ge $WaitTimeout) {
            throw "Job timed out after $WaitTimeout seconds"
        }

        Start-Sleep -Seconds 10
    }
}

function Show-Help {
    $lines = @(
        "Usage:",
        "  .\scripts\nonargo\no_argo_jira_k8s.ps1 COMMAND",
        "",
        "Commands:",
        "  preflight   Check cluster access and permissions",
        "  build-push  Build and push the all-in-one Jira image",
        "  configure   Prompt for credentials and create Secrets",
        "  render      Render a suspended non-Argo CronJob",
        "  deploy      Render, diff, and apply the CronJob",
        "  run         Start one manual Job",
        "  wait        Wait for the latest manual Job",
        "  status      Show the latest Job and Pods",
        "  logs        Show logs for the latest Job",
        "  all         Build, configure, deploy, run, and wait",
        "",
        "Required environment:",
        "  KUBE_CONTEXT",
        "  REGISTRY_HOST",
        "  REGISTRY_REPOSITORY",
        "  JIRA_URL",
        "  JIRA_PROJECT_KEY",
        "",
        "Defaults:",
        "  KUBE_NAMESPACE=blackduck-wintermute",
        "  PVC_SIZE=10Gi",
        "  PIPELINE_MODE=dry-run",
        "  ENABLE_SCHEDULE=false",
        "  WORKERS=2",
        "  MAX_CREATE=10"
    )

    Write-Output (
        $lines -join [Environment]::NewLine
    )
}

switch ($Command) {
    "preflight" {
        Invoke-Preflight
    }
    "build-push" {
        Invoke-BuildPush
    }
    "configure" {
        Invoke-Configure
    }
    "render" {
        Invoke-Render
    }
    "deploy" {
        Invoke-Deploy
    }
    "run" {
        Start-ManualJob | Out-Null
    }
    "wait" {
        Wait-ManualJob
    }
    "status" {
        Show-JobStatus
    }
    "logs" {
        Show-JobLogs
    }
    "all" {
        Invoke-Preflight
        Invoke-BuildPush
        Invoke-Configure
        Invoke-Deploy
        Start-ManualJob | Out-Null
        Wait-ManualJob
    }
    default {
        Show-Help
    }
}
