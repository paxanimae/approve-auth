{{/*
Standard Helm naming helpers (chart-scaffold boilerplate, not project-
specific) -- fullname truncated to 63 chars for the DNS-1123 label
limit Kubernetes Service/Pod names share.
*/}}

{{- define "approve-auth.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "approve-auth.fullname" -}}
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

{{- define "approve-auth.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "approve-auth.labels" -}}
helm.sh/chart: {{ include "approve-auth.chart" . }}
{{ include "approve-auth.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "approve-auth.selectorLabels" -}}
app.kubernetes.io/name: {{ include "approve-auth.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "approve-auth.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "approve-auth.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
db.<x> helpers -- the bundled Postgres StatefulSet's own name/labels,
kept distinct from the main app's so `kubectl get pods` output reads
the same as `docker service ls` does against deploy/stack.yml (a
separate `db` service, not folded into the main one).
*/}}

{{- define "approve-auth.db.fullname" -}}
{{- printf "%s-db" (include "approve-auth.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "approve-auth.db.selectorLabels" -}}
app.kubernetes.io/name: {{ include "approve-auth.name" . }}-db
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "approve-auth.db.labels" -}}
helm.sh/chart: {{ include "approve-auth.chart" . }}
{{ include "approve-auth.db.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
