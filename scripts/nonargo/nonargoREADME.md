## Non-Argo Jira k8s install

### 1. From the repository root, verify prerequisites

```textmate
docker --version && kubectl version --client && python --version && kubectl config current-context
```


### 2. Log in to the container registry

```textmate
docker login YOUR_REGISTRY.example.com
```


### 3. Configure the deployment

Replace the example values: (this is dry-run only and disabled on cluster initially)
(kube context is your current cluster context e.g. 'default')

```textmate
export KUBE_CONTEXT="$(kubectl config current-context)" KUBE_NAMESPACE='blackduck-wintermute' REGISTRY_HOST='YOUR_REGISTRY.example.com' REGISTRY_REPOSITORY='security/blackduck-wintermute' IMAGE_TAG="$(git rev-parse HEAD)" JIRA_URL='https://YOUR_JIRA.example.com' JIRA_PROJECT_KEY='YOUR_PROJECT_KEY' PVC_SIZE='10Gi' PIPELINE_MODE='dry-run' ENABLE_SCHEDULE='false'
```


### 4. Macos Run the guided installation

```textmate
zsh scripts/nonargo/no_argo_jira_k8s.zsh all
```


The script will:

1. Check the selected cluster and permissions.
2. Build the all-in-one Jira pipeline image.
3. Test the image entry point.
4. Push the image to the configured registry.
5. Prompt securely for Black Duck and Jira credentials.
6. Create the namespace and Secrets.
7. Render the non-Argo deployment.
8. Create the `5Gi` PVC.
9. Apply a suspended, dry-run CronJob.
10. Start one manual dry-run Job.
11. Wait and print its logs.

## If image has been built/published to reg already and you're rerunning it, you can skip all and just run below

```textmate
zsh scripts/nonargo/no_argo_jira_k8s.zsh preflight
```


```textmate
zsh scripts/nonargo/no_argo_jira_k8s.zsh configure
```


```textmate
zsh scripts/nonargo/no_argo_jira_k8s.zsh deploy
```


```textmate
zsh scripts/nonargo/no_argo_jira_k8s.zsh run
```


```textmate
zsh scripts/nonargo/no_argo_jira_k8s.zsh wait
```


## Check the result

```textmate
kubectl --context "${KUBE_CONTEXT}" -n "${KUBE_NAMESPACE}" get cronjob,pvc,job,pods
```


```textmate
kubectl --context "${KUBE_CONTEXT}" -n "${KUBE_NAMESPACE}" logs "job/$(cat "${HOME}/.local/state/blackduck-wintermute/latest-jira-job.txt")" --all-containers=true --tail=500
```


## Important

Keep these settings for initial testing:

```textmate
export PIPELINE_MODE='dry-run' ENABLE_SCHEDULE='false'
```


Do not enable the schedule or apply Jira changes until the manual dry-run counts have been reviewed.


## Windows PowerShell

Windows requires PowerShell, Python 3.12, Docker, kubectl, Git, registry access, and a configured Kubernetes context.

From PowerShell at the repository root:

```powershell
$env:KUBE_CONTEXT = kubectl config current-context
$env:KUBE_NAMESPACE = "blackduck-wintermute"
$env:REGISTRY_HOST = "YOUR_REGISTRY.example.com"
$env:REGISTRY_REPOSITORY = "security/blackduck-wintermute"
$env:IMAGE_TAG = git rev-parse HEAD
$env:JIRA_URL = "https://YOUR_JIRA.example.com"
$env:JIRA_PROJECT_KEY = "YOUR_PROJECT_KEY"
$env:PVC_SIZE = "10Gi"
$env:PIPELINE_MODE = "dry-run"
$env:ENABLE_SCHEDULE = "false"
```

Log in to the registry:
``` powershell
docker login $env:REGISTRY_HOST
```

If local script execution is blocked, permit it only for the current PowerShell process:
``` powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Run the complete guided dry-run installation:
``` powershell
.\scripts\nonargo\no_argo_jira_k8s.ps1 all
```

Or run each phase separately:
``` powershell
.\scripts\nonargo\no_argo_jira_k8s.ps1 preflight
.\scripts\nonargo\no_argo_jira_k8s.ps1 build-push
.\scripts\nonargo\no_argo_jira_k8s.ps1 configure
.\scripts\nonargo\no_argo_jira_k8s.ps1 deploy
.\scripts\nonargo\no_argo_jira_k8s.ps1 run
.\scripts\nonargo\no_argo_jira_k8s.ps1 wait
```

Credentials are entered through secure prompts and stored in Kubernetes Secrets. They are not written to the rendered manifest. '''
