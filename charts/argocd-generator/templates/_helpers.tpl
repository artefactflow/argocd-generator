{{- define "argocd-generator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "argocd-generator.fullname" -}}
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

{{- define "argocd-generator.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "argocd-generator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "argocd-generator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "argocd-generator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "argocd-generator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "argocd-generator.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Secret name and key for the upstream ArtefactFlow client secret.
*/}}
{{- define "argocd-generator.upstreamSecretName" -}}
{{- default (printf "%s-upstream" (include "argocd-generator.fullname" .)) .Values.artefactflow.existingSecret -}}
{{- end -}}

{{- define "argocd-generator.upstreamSecretKey" -}}
{{- if .Values.artefactflow.existingSecret -}}
{{- .Values.artefactflow.existingSecretKey -}}
{{- else -}}
client-secret
{{- end -}}
{{- end -}}

{{/*
Secret name and key for the plugin token shared with the ApplicationSet
controller.
*/}}
{{- define "argocd-generator.pluginSecretName" -}}
{{- default (printf "%s-plugin-token" (include "argocd-generator.fullname" .)) .Values.plugin.existingSecret -}}
{{- end -}}

{{- define "argocd-generator.pluginSecretKey" -}}
{{- if .Values.plugin.existingSecret -}}
{{- .Values.plugin.existingSecretKey -}}
{{- else -}}
token
{{- end -}}
{{- end -}}

{{/*
The reference Argo CD resolves to read the plugin token. A bare "$name" is
looked up in argocd-secret; "$secret:key" in the named secret.
*/}}
{{- define "argocd-generator.pluginTokenRef" -}}
{{- if .Values.plugin.tokenRef -}}
{{- .Values.plugin.tokenRef -}}
{{- else -}}
{{- printf "$%s:%s" (include "argocd-generator.pluginSecretName" .) (include "argocd-generator.pluginSecretKey" .) -}}
{{- end -}}
{{- end -}}

{{/*
Fail early on the combinations that would otherwise deploy a plugin that
cannot start or cannot be reached.
*/}}
{{- define "argocd-generator.validate" -}}
{{- if and (not .Values.artefactflow.clientSecret) (not .Values.artefactflow.existingSecret) -}}
{{- fail "argocd-generator: set artefactflow.clientSecret or artefactflow.existingSecret; the plugin cannot reach ArtefactFlow without service-account credentials" -}}
{{- end -}}
{{- if and (not .Values.artefactflow.clientId) (not .Values.artefactflow.existingSecretClientIdKey) -}}
{{- fail "argocd-generator: set artefactflow.clientId (the service account's id, a UUID), or point artefactflow.existingSecretClientIdKey at the key holding it" -}}
{{- end -}}
{{- if and (not .Values.plugin.token) (not .Values.plugin.existingSecret) -}}
{{- fail "argocd-generator: set plugin.token or plugin.existingSecret; the ApplicationSet controller authenticates to the plugin with it" -}}
{{- end -}}
{{- if not .Values.artefactflow.apiUrl -}}
{{- fail "argocd-generator: artefactflow.apiUrl is required" -}}
{{- end -}}
{{- end -}}
