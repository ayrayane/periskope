{{- define "periskope.image" -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end }}
{{- define "periskope.tokenSecret" -}}{{ if $.root.Values.crossplane.enabled }}gitlab-token-{{ .i.slug }}{{ else }}{{ .i.tokenSecret | default (printf "gitlab-token-%s" .i.slug) }}{{ end }}{{- end }}
{{- define "periskope.webhookSecret" -}}{{ if $.root.Values.crossplane.enabled }}gitlab-webhook-{{ .i.slug }}{{ else }}{{ .i.webhookSecret | default (printf "gitlab-webhook-%s" .i.slug) }}{{ end }}{{- end }}

{{- define "periskope.pod" -}}
securityContext: { runAsNonRoot: true, runAsUser: 10001, seccompProfile: { type: RuntimeDefault } }
automountServiceAccountToken: false
{{- with .Values.image.pullSecret }}
imagePullSecrets: [{ name: {{ . }} }]
{{- end }}
{{- end }}

{{- define "periskope.container" -}}
image: {{ include "periskope.image" . }}
securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: [ALL] } }
env:
  - name: PERISKOPE_DATABASE_URL
    valueFrom: { secretKeyRef: { name: periskope-db-app, key: uri } }
  - { name: PERISKOPE_VALKEY_URL, value: "redis://periskope-valkey:6379" }
  - { name: PERISKOPE_INSTANCES_FILE, value: /etc/periskope/instances.json }
  - { name: PERISKOPE_SECRETS_DIR, value: /var/run/secrets/periskope }
  - { name: PERISKOPE_TIMEZONE, value: {{ .Values.timezone | quote }} }
  - { name: PERISKOPE_PUBLIC_URL, value: {{ printf "https://%s" .Values.host | quote }} }
  - { name: PERISKOPE_OIDC_ISSUER, value: {{ .Values.oidc.issuer | quote }} }
  - { name: PERISKOPE_OIDC_CLIENT_ID, value: {{ .Values.oidc.clientId | quote }} }
  - { name: PERISKOPE_ROLE_MAP, value: {{ .Values.oidc.roleMap | toJson | quote }} }
  - { name: PERISKOPE_ADMINS, value: {{ .Values.admins | toJson | quote }} }
  - { name: PERISKOPE_IDENTITY_MATCH, value: {{ .Values.identity.match | quote }} }
  - { name: PERISKOPE_GITLAB_LDAP_ONLY, value: {{ .Values.identity.gitlabLdapOnly | quote }} }
  - { name: PERISKOPE_KEV_URL, value: {{ .Values.vulnFeeds.kevUrl | quote }} }
  - { name: PERISKOPE_EPSS_URL, value: {{ .Values.vulnFeeds.epssUrl | quote }} }
  - { name: PERISKOPE_FEEDS_PROXY, value: {{ .Values.vulnFeeds.proxy | quote }} }
  - { name: PERISKOPE_DT_URL, value: {{ .Values.dependencyTrack.url | quote }} }
  - { name: PERISKOPE_DT_INSTANCE, value: {{ .Values.dependencyTrack.instance | default (first .Values.instances).slug | quote }} }
  - { name: PERISKOPE_DT_SOURCES, value: {{ .Values.dependencyTrack.sources | quote }} }
  {{- if .Values.oidc.caConfigMap }}
  - { name: PERISKOPE_OIDC_CA_FILE, value: /etc/periskope/ca/ca.crt }
  - { name: SSL_CERT_FILE, value: /etc/periskope/ca/ca.crt }
  {{- end }}
{{- end }}

{{- define "periskope.mounts" -}}
- { name: config, mountPath: /etc/periskope/instances.json, subPath: instances.json, readOnly: true }
- { name: tmp, mountPath: /tmp }
{{- if .Values.oidc.caConfigMap }}
- { name: ca, mountPath: /etc/periskope/ca, readOnly: true }
{{- end }}
{{- end }}

{{- define "periskope.volumes" -}}
- { name: config, configMap: { name: periskope-instances } }
- { name: tmp, emptyDir: {} }
{{- with .Values.oidc.caConfigMap }}
- { name: ca, configMap: { name: {{ . }} } }
{{- end }}
{{- end }}

{{- /* True when at least one instance offers « Corriger dans GitLab ». */ -}}
{{- define "periskope.anyFixes" -}}
{{- range .Values.instances }}{{ if .fixes }}true{{ end }}{{ end -}}
{{- end }}
