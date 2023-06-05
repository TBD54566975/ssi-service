{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ssi-service.fullname" -}}
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

{{- define "ssi-service.shortname" -}}
{{- include "ssi-service.fullname" . | trunc 55 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "ssi-service.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "ssi-service.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Values.customLabels -}}
{{ toYaml .Values.customLabels }}
{{- end -}}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "ssi-service.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ssi-service.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}




{{- define "uni-resolver.fullname" -}}
{{- printf "%s-uni" (include "ssi-service.shortname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "uni-resolver.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "uni-resolver.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Values.customLabels -}}
{{ toYaml .Values.customLabels }}
{{- end -}}
{{- end -}}

{{- define "uni-resolver.selectorLabels" -}}
app.kubernetes.io/name: {{ include "uni-resolver.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}




{{- define "dion.fullname" -}}
{{- printf "%s-dion" (include "ssi-service.shortname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "dion.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "dion.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Values.customLabels -}}
{{ toYaml .Values.customLabels }}
{{- end -}}
{{- end -}}

{{- define "dion.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dion.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}




{{- define "jaeger.fullname" -}}
{{- printf "%s-jaeger" (include "ssi-service.shortname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "jaeger.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "jaeger.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Values.customLabels -}}
{{ toYaml .Values.customLabels }}
{{- end -}}
{{- end -}}

{{- define "jaeger.selectorLabels" -}}
app.kubernetes.io/name: {{ include "jaeger.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
