{{- define "blackduck-wintermute-jira.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "blackduck-wintermute-jira.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "blackduck-wintermute-jira.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "blackduck-wintermute-jira.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/name: {{ include "blackduck-wintermute-jira.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: jira-pipeline
{{- end -}}

{{- define "blackduck-wintermute-jira.selectorLabels" -}}
app.kubernetes.io/name: {{ include "blackduck-wintermute-jira.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: jira-pipeline
{{- end -}}

{{- define "blackduck-wintermute-jira.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "blackduck-wintermute-jira.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "blackduck-wintermute-jira.image" -}}
{{- $repository := required "image.repository is required" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repository (required "image.tag is required when image.digest is empty" .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "blackduck-wintermute-jira.claimName" -}}
{{- default (printf "%s-data" (include "blackduck-wintermute-jira.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}
