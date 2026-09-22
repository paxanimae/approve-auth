{{/*
Standard Helm naming helpers (chart-scaffold boilerplate, not project-
specific) -- fullname truncated to 63 chars for the DNS-1123 label
limit Kubernetes Service/Pod names share.
*/}}

{{- define "approve-auth-demo.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "approve-auth-demo.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "approve-auth-demo.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "approve-auth-demo.labels" -}}
helm.sh/chart: {{ include "approve-auth-demo.chart" . }}
{{ include "approve-auth-demo.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "approve-auth-demo.selectorLabels" -}}
app.kubernetes.io/name: {{ include "approve-auth-demo.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Per-component name/label helpers: db, keycloak, landing, seed, certgen,
and one per sample app (parameterized by `name`, passed via `dict
"root" . "name" "kiosk"` from range loops). Each gets its own
app.kubernetes.io/name suffix so `kubectl get pods` reads clearly.
*/}}

{{- define "approve-auth-demo.component.fullname" -}}
{{- printf "%s-%s" (include "approve-auth-demo.fullname" .root) .name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "approve-auth-demo.component.selectorLabels" -}}
app.kubernetes.io/name: {{ include "approve-auth-demo.name" .root }}-{{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}

{{- define "approve-auth-demo.component.labels" -}}
helm.sh/chart: {{ include "approve-auth-demo.chart" .root }}
{{ include "approve-auth-demo.component.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{- end -}}
