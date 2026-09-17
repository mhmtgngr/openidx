{{/*
Expand the name of the chart.
*/}}
{{- define "openidx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "openidx.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "openidx.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "openidx.labels" -}}
helm.sh/chart: {{ include "openidx.chart" . }}
{{ include "openidx.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "openidx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "openidx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "openidx.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "openidx.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Zero-downtime pod termination.

Kubernetes removes a Pod from Service endpoints and sends SIGTERM at the same
time, and those two things race across the cluster. The application already
drains correctly (internal/server/graceful.go), but if it exits the instant it
receives SIGTERM, kube-proxy on some nodes may still be forwarding to it — the
caller sees a connection reset. That is the usual cause of 502s during an
otherwise healthy rolling update.

preStop simply waits, doing nothing, so endpoint removal wins the race before
the container starts shutting down. terminationGracePeriodSeconds must exceed
the preStop delay plus the application's own drain window, otherwise Kubernetes
sends SIGKILL mid-drain and cuts live requests.

Usage: {{- include "openidx.gracefulTermination" . | nindent 6 }}  (pod spec level)
*/}}
{{- define "openidx.gracefulTermination" -}}
{{- $g := .Values.gracefulTermination | default dict -}}
{{- if ne (dig "enabled" true $g) false }}
terminationGracePeriodSeconds: {{ dig "gracePeriodSeconds" 45 $g }}
{{- end }}
{{- end }}

{{/*
preStop lifecycle hook, applied at container level.

Kept separate from the pod-level setting above because Kubernetes puts them in
different places in the spec.
*/}}
{{- define "openidx.preStopHook" -}}
{{- $g := .Values.gracefulTermination | default dict -}}
{{- if ne (dig "enabled" true $g) false }}
lifecycle:
  preStop:
    exec:
      # Sleep only. The application's own graceful shutdown does the draining;
      # this delay exists purely so endpoint removal propagates first.
      command: ["/bin/sh", "-c", "sleep {{ dig "preStopSeconds" 5 $g }}"]
{{- end }}
{{- end }}

{{/*
Spread replicas across failure domains.

podAntiAffinity (already used here) keeps replicas off the same node, which
survives a node failure. It does not, on its own, stop every replica landing in
one availability zone — so an AZ outage would still take the whole service down.
This constraint spreads across zones as well.

whenUnsatisfiable is ScheduleAnyway on purpose: DoNotSchedule would leave pods
Pending on a single-zone cluster, which trades an availability improvement for
an outage. A best-effort spread is the right default; operators who run
multi-zone and want the hard guarantee can set it to DoNotSchedule.

Usage: {{- include "openidx.topologySpread" (dict "ctx" . "component" "identity-service") | nindent 6 }}
*/}}
{{- define "openidx.topologySpread" -}}
{{- $ctx := .ctx -}}
{{- $t := $ctx.Values.topologySpread | default dict -}}
{{- if ne (dig "enabled" true $t) false }}
topologySpreadConstraints:
  - maxSkew: {{ dig "maxSkew" 1 $t }}
    topologyKey: {{ dig "topologyKey" "topology.kubernetes.io/zone" $t }}
    whenUnsatisfiable: {{ dig "whenUnsatisfiable" "ScheduleAnyway" $t }}
    labelSelector:
      matchLabels:
        {{- include "openidx.selectorLabels" $ctx | nindent 8 }}
        app.kubernetes.io/component: {{ .component }}
{{- end }}
{{- end }}

{{/*
Rolling update strategy.

Kubernetes defaults to maxUnavailable=25%, which means a rollout may take a
quarter of the fleet out of service before any replacement is Ready. Under load
that shows up as elevated latency or shed traffic during an ordinary deploy.

maxUnavailable: 0 with maxSurge: 1 inverts that: a new pod must become Ready
before an old one is removed, so capacity never dips below the declared replica
count. The cost is one extra pod's worth of resources for the duration of the
rollout, which is the right trade for an always-on service.

Usage: {{- include "openidx.rollingStrategy" . | nindent 2 }}  (deployment spec level)
*/}}
{{- define "openidx.rollingStrategy" -}}
{{- $s := .Values.rollingUpdate | default dict -}}
{{- if ne (dig "enabled" true $s) false }}
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: {{ dig "maxUnavailable" 0 $s }}
    maxSurge: {{ dig "maxSurge" 1 $s }}
{{- end }}
{{- end }}

{{/*
The registry OpenIDX's own images come from.

Why this is not `global.imageRegistry`: that key belongs to the Bitnami
subchart contract. `common.images.image` reads it as
`default .image.registry .global.imageRegistry`, so the GLOBAL wins — setting
it to `ghcr.io/mhmtgngr/openidx`, as values.yaml did, rewrote the bundled
PostgreSQL, Redis and Elasticsearch images to
`ghcr.io/mhmtgngr/openidx/bitnami/postgresql:...`, which has never existed.
A default `helm install` therefore could not start its own data plane.
`helm lint` and `helm template` both pass on it — the image name is only
wrong once something tries to pull it — and values-prod.yaml disables all
three subcharts, which is why the reference deployment never hit it.

So OpenIDX images read `global.openidxRegistry`, and `global.imageRegistry`
is shipped empty so each subchart falls back to its own `image.registry`
(docker.io). The fallback below keeps an operator who set only the old key
on their images rather than silently moving them to the default.
*/}}
{{- define "openidx.imageRegistry" -}}
{{- $g := .Values.global | default dict -}}
{{- $r := dig "openidxRegistry" "" $g -}}
{{- if not $r -}}{{- $r = dig "imageRegistry" "" $g -}}{{- end -}}
{{- $r | default "ghcr.io/mhmtgngr/openidx" -}}
{{- end }}

{{/*
The DSN a REQUEST-SERVING service uses, when the transaction pooler is in front
of Postgres (global-scale plan task 2.2).

It is an `env` entry rather than another `envFrom` source on purpose. `env`
beats `envFrom` by documented Kubernetes precedence, so this cleanly replaces
the direct DATABASE_URL that the -db-url secret carries; the alternative --
mounting a second secret after -db-url and relying on later-source-wins for a
duplicate key -- works today but is not a promise the API makes.

The migration Job, the bootstrap hook and the backup CronJob deliberately do
NOT include this and keep the direct DSN. None of the three survives
transaction pooling: migrations take session-scoped advisory locks, and
pg_dump needs one session to hold its snapshot for the whole dump. A pooler
would hand each of them a different backend mid-flight.
*/}}
{{- define "openidx.pooledDatabaseUrl" -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "openidx.fullname" . }}-pgcat-dsn
      key: DATABASE_URL
{{- end }}

{{/*
The bundled PostgreSQL's PRIMARY, by Service name.

The Bitnami subchart names its Service `<release>-postgresql` in standalone
mode and `<release>-postgresql-primary` once `postgresql.architecture` is
"replication" -- the same chart, a different name, and every DSN this chart
builds used to spell the standalone one. Turning replication on therefore
broke every connection string at once: the migration Job waited on a Service
that did not exist and `helm --wait` burned its timeout. One helper, every
template that names the host uses it, and the read replica has its own below.
*/}}
{{- define "openidx.postgresHost" -}}
{{- if eq (.Values.postgresql.architecture | default "standalone") "replication" -}}
{{- include "openidx.fullname" . }}-postgresql-primary
{{- else -}}
{{- include "openidx.fullname" . }}-postgresql
{{- end -}}
{{- end }}

{{/*
The bundled PostgreSQL's READ replicas, by Service name. Only meaningful when
postgresql.architecture is "replication"; the subchart renders nothing under
this name otherwise.
*/}}
{{- define "openidx.postgresReadHost" -}}
{{- include "openidx.fullname" . }}-postgresql-read
{{- end }}

{{/*
The availability plane a service connects as, validated.

A misspelled plane must not render: the value picks a Postgres role, and a name
nothing created would fail at connect time, on one service, after the rollout
looked healthy.
*/}}
{{- define "openidx.planeFor" -}}
{{- $ctx := .ctx -}}
{{- $svc := .service -}}
{{- $plane := index $ctx.Values.database.planeRoles.assignments $svc | default "" -}}
{{- if not (has $plane (list "issue" "admin" "event")) -}}
{{- fail (printf "database.planeRoles.assignments.%s = %q, which is not a plane. Set one of \"issue\" (statement_timeout 2s), \"admin\" (10s) or \"event\" (30s); each names a Postgres role migration v189 creates." $svc $plane) -}}
{{- end -}}
{{- $plane -}}
{{- end -}}

{{/*
DATABASE_URL for a service's plane role (task 2.4).

Placed in `env:` rather than `envFrom:` on purpose: an `env` entry beats a
`secretRef` key of the same name, so this overrides the fleet-wide DSN in
-db-url for this one service without the two disagreeing anywhere else.
*/}}
{{- define "openidx.planeDatabaseUrl" -}}
{{- $plane := include "openidx.planeFor" . -}}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ include "openidx.fullname" .ctx }}-plane-dsn
      key: DATABASE_URL_{{ upper $plane }}
{{- end }}
