# Periskope

Periskope measures DSOMM evidence on GitLab projects without asking the teams anything: which of the 54 retained checks pass, which are missing and how to get them. Specification: the "Spécifications — Periskope" document.

## Layout

| Path | What |
| --- | --- |
| `packages/core` | Check catalogue, DSOMM 5.0.2 activities, scoring and scope rules (the only place they live) |
| `packages/clients` | Async GitLab client: read-only, token file re-read on 401, per-instance quota |
| `packages/checks` | The check registry and the 54 checks: GitLab, repository, SonarQube, Dependency-Track trees and the vulnerability ledger |
| `packages/db` | PostgreSQL schema (Alembic), run lifecycle, `Viewer.where()` scope filter |
| `services/collector` | ARQ worker for one GitLab instance: analyses, project sync, memberships |
| `services/scheduler` | Webhook receiver and nightly tasks (sync 00:30, catch-up 01:00, rollup 05:00) |
| `services/api` | FastAPI on `/api/v1`, Keycloak bearer tokens |
| `frontend` | React + Vite: portfolio and project page |
| `chart/periskope` | Helm chart; deployment values live in the `periskope-deploy` project |

`import-linter` keeps the boundaries: core imports nothing else, checks only core and clients, the API never the collectors, clients or checks.

## Develop

```sh
podman run -d --name periskope-pg -e POSTGRES_USER=periskope -e POSTGRES_PASSWORD=dev -p 55432:5432 postgres:16-alpine
podman run -d --name periskope-valkey -p 56379:6379 valkey/valkey:8-alpine
uv sync
uv run pytest            # unit tests, plus integration tests against the containers above
uv run lint-imports
cd frontend && npm ci && npm test && npm run dev
```

Add a check: one decorated function in `packages/checks`, with a pass, fail and unknown case in `tests/test_checks.py`. No migration, screen or route.

## Release

A `vX.Y.Z` tag builds the image (api, scheduler and collector share it), the frontend image and the chart, all at the same version. Deploying is a merge request on `periskope-deploy`.

## Keycloak prerequisites

The chart declares its client with the operator's `KeycloakOIDCClient` (Keycloak 26.8+), which needs:

- the server feature `client-admin-api:v2` (`spec.features.enabled` on the Keycloak CR);
- a Secret `<keycloak>-admin` in the Keycloak namespace with `client-id` and `client-secret` of a master-realm service account holding the `admin` role;
- users get the client role `viewer`, `maintainer` or `admin` (or a realm role mapped by `oidc.roleMap`). No audience mapper is needed: the API accepts the tokens issued to the `periskope` client (`azp`), whatever their `aud`.
- a way to tie each Keycloak user to their GitLab account, chosen with `identity.match`:
  - `verified_email` (default): the realm's `email` scope sends `email_verified` (built-in "email verified" mapper), and GitLab has the same e-mail. A user without a verified e-mail sees no project.
  - `username`: for a realm whose accounts all come from a trusted directory (LDAP federation, no local accounts, no self-registration). The login is the person; set `identity.gitlabLdapOnly: true` when GitLab uses the same LDAP, so a local GitLab account of the same name is never taken.

## Rights

| Keycloak role (mapped by `oidc.roleMap`) | Sees | Launches analyses and scopes a project | Administers |
|---|---|---|---|
| `viewer` | the projects of their GitLab groups and projects | where GitLab makes them Maintainer or Owner | no |
| `auditor` | every project of every instance | where GitLab makes them Maintainer or Owner | no |
| `admin` | everything | everything | settings, organisation scoping, audit log |

Admins can also be listed by Keycloak login, whatever their roles: chart value `admins: [prenom.nom, ...]`, kept in the deployment repository (`admins.yaml`).

Example for an LDAP-backed workspace whose realm roles are `manager` and `user`:

```yaml
oidc:
  roleMap: { manager: auditor, user: viewer }
identity:
  match: username
  gitlabLdapOnly: true   # if GitLab uses the same LDAP
```

## Environments (GitLab topics)

A project's environment is the GitLab topic it carries: `prod`, `test` or `dev` (any case; Settings › General › Topics). The dashboard, the Vulnerabilities tab, the report and the CSV exports filter on it (`?env=prod|test|dev|none`); a project with several of these topics counts in each, one with none is « Non classé ». Topics are read at each synchronisation.

## Vulnerability priority (KEV and EPSS)

Each open CVE gets a priority (shown) and an SSVC response, which sets its correction deadline (Immédiat 7 days, Hors cycle 30,
Planifié 90, Différé none; admin settings, counted from the first detection). The priority:
listed in CISA's KEV catalogue → critical; EPSS at or above the threshold (10 % by default) → severity raised one level;
EPSS below it → a critical comes down to high; no EPSS → the severity. The SSVC response (CISA's deployer tree, reduced to what
Periskope knows): exploitation from KEV and EPSS, exposure from the environment (a `prod` tree in Dependency-Track, else the `prod`
topic; a project without environment counts as prod), automatable from the CVSS vector (network, no privilege, no user) or a
critical severity. Exploited in prod → Immédiat; exploited elsewhere, likely exploited in prod, or automatable/critical in prod →
Hors cycle; likely exploited elsewhere or any other finding in prod → Planifié; the rest → Différé. The network has no Internet: the scheduler reads
both feeds each night (admin setting `feeds_at`, 00:15), from the official sites or an internal copy.

```yaml
vulnFeeds:   # with Internet access (direct, or through proxy)
  kevUrl: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  epssUrl: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  proxy: http://proxy.internal:3128     # optional, used for these two files only
```

Without Internet, the same two files copied daily to an internal web server, and their URLs there (gzipped or plain CSV).
A URL may hold `{date}` (YYYY-MM-DD, UTC) for a daily archive, e.g. a pipeline that drops one file a day in a Nexus raw
repository: Periskope reads the most recent of the last 7 days, so a missed day is not a gap.

```yaml
vulnFeeds:
  kevUrl: https://nexus.internal/repository/vuln-feeds/kev/known_exploited_vulnerabilities-{date}.json
  epssUrl: https://nexus.internal/repository/vuln-feeds/epss/epss_scores-{date}.csv.gz
```

A feed that fails keeps the previous day's data; the Vulnerabilities tab shows each feed's date and last error. Empty URLs:
priority is the severity.

## Dependency-Track

Dependency-Track is required on every instance: without it the level-1 activity « Inventory of production components »
stays unknown, so no project reaches the « socle N1 ».

With `dependencyTrack.url`, the scheduler reads DT every hour, read only (an API key whose team has VIEW_PORTFOLIO,
VIEW_VULNERABILITY and SYSTEM_CONFIGURATION_READ, the last one to read when the CVE sources were last mirrored; Secret
`periskope-dtrack`, key `apiKey`):

- **Projects**: DT mirrors GitLab, each project named by its full GitLab path (`cms/back/brique-a`) and versioned; groups and
  projects of no GitLab path of `dependencyTrack.instance` are ignored.
- **Delivered versions**: a DT project tagged `version-livree`, named after the CMS, its version the delivery's. The GitOps
  template builds it: it exports the SBOM of each brick version chosen (neither the latest nor the same number), merges them so
  that each brick is a component named and versioned as its own DT project, uploads the result with the tag, then uploads each
  brick's VEX. Before that, for each brick chosen, the job merges the code SBOM exported from DT with the SBOM of the brick's OCI
  image kept by Harbor (at the deployed digest; an SPDX one converted with `cyclonedx convert` first), under the brick's name and
  version (`cyclonedx merge --name <GitLab path> --version <tag>`), and uploads the result back into the brick's own DT project:
  its findings then cover code and image, read once by Periskope, and its VEX decisions stay. Checked on DT 5.2.1 with a CycloneDX
  image SBOM; reading it from Harbor was not (no Harbor on the lab). Calls, checked on DT 5.2.1: `GET /api/v1/bom/cyclonedx/project/{uuid}?format=json&variant=inventory` (its
  `metadata.component` is the DT project's name and version), `cyclonedx merge --hierarchical --name <CMS> --version <version>`
  (cyclonedx-cli 0.27.2: each brick stays a top-level component with its dependencies under it), `PUT /api/v1/bom` with
  `projectName`, `projectVersion`, `autoCreate: true` and `projectTags: [{"name": "version-livree"}]`, then `PUT /api/v1/vex` per
  brick. A VEX must list the components it concerns in its own `components[]` (purl, name, version) and point `affects[].ref` at
  their `bom-ref`: DT resolves the reference inside the VEX, then matches the component in the project; a VEX pointing at the
  SBOM's `bom-ref`s only is accepted and silently ignored (DT logs « Unable to locate affected element »). A brick version may be
  in any number of delivered versions, of one CMS or of several. Periskope finds every
  delivered version by itself; its bricks are its components that match a DT project of their own (same name, same version), whose
  findings and analyses are read there, once. A delivered version counts as production. Its bricks feed the production evidence (version, SBOM, deployment by digest)
  and the CVE exposure. A project in no delivered version counts its latest SBOM, without environment (its GitLab topics tell the
  exposure, and stay the fallback of the production evidence). A brick without SBOM, or tagged `deploiement-par-tag` by the GitOps
  job, is listed in « Travail à faire »; so are bricks with components without purl. VEX decisions are taken in the brick's VEX
  file, never by hand in DT: the template copies them into each delivered version, and a decision made by hand there would hold
  for that delivered version alone. DT's own totals count a delivered brick twice (its project and each delivered version);
  Periskope does not.
- **Findings**: DT's replace GitLab's dependency and container findings (GitLab keeps SAST, secrets and DAST), one per CVE (a GHSA
  is keyed by its CVE alias). KEV and EPSS come from Periskope's feeds, else from DT. A finding analysed `NOT_AFFECTED` or
  `FALSE_POSITIVE` is « non concernée » (VEX); a suppressed one, or one answered `WILL_NOT_FIX`/`CAN_NOT_FIX`, is an exception
  that ends on the date written in its analysis detail (`expire 2027-03-01`), else 90 days after it was recorded (`exception_days`).
- **Sources**: the last completed mirror run of each DT vulnerability source (`dependencyTrack.sources`, default `nvd,github,osv`;
  one DT does not run is skipped). A source, or KEV/EPSS, older than 2 days is flagged and alerted.

Every open finding is also kept in a ledger (opened, deadline, closed), refreshed every 5 minutes: it gives the follow-up sheet
of a CVE and the five indicators of the report. A CVE is closed when it is in no running version any more (D15).

Alerts (`alerts.secret`, Mattermost incoming webhook): a score drop, a new vulnerability of critical priority (once per CVE and
project, naming the security referents of CODEOWNERS), a stale CVE source (once a day).

Pages: Vulnérabilités › « Par version livrée » (each tree, two side by side), « Exceptions et VEX », the « Fiche de suivi »
of a CVE (every version, DT's decision, versions already updated, history); the project's deployed versions; the report's indicators.

## Without Internet (air-gap)

Periskope itself calls only GitLab, Keycloak and the two feed URLs: no CDN, no web font, no telemetry. On a closed network:

1. **Images** in the internal registry (Harbor or Nexus): `image.repository` and `image.frontend` (built by the `vX.Y.Z` tag), plus the
   two third-party images, copied once per version:
   ```yaml
   image:
     valkey: harbor.internal/mirror/valkey/valkey:8.0-alpine
     postgres: harbor.internal/mirror/cloudnative-pg/postgresql:16
     pullSecret: harbor-pull       # if the registry needs a login; used by every pod and by the database
   ```
2. **Chart** from the same registry (`helm install periskope oci://<registry>/periskope/periskope/charts/periskope --version X.Y.Z`),
   values in `periskope-deploy`.
3. **Cluster prerequisites**, already installed from their own mirrored images: CloudNativePG, the Keycloak operator (see above),
   and only if enabled KEDA (`keda`), Crossplane (`crossplane`) and the Prometheus operator (`monitoring`).
4. **Private CA** of Keycloak, GitLab and Nexus: a ConfigMap with `ca.crt`, named in `oidc.caConfigMap`.
5. **Dependency-Track**: its own mirrors of NVD, GitHub and OSV (daily copy in Nexus); Periskope only needs DT's URL.
6. **KEV and EPSS**: the daily Nexus copy above (`{date}` URLs, filled by a scheduled job on a runner that has Internet). Without it, Periskope works and priority is GitLab's severity alone.

The only link out is « Fiche NVD » on a CVE (nvd.nist.gov, opened in the user's browser): dead without Internet, nothing else depends on it.
