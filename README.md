# Periskope

Periskope measures DSOMM evidence on GitLab projects without asking the teams anything: which of the 47 retained checks pass, which are missing and how to get them. Specification: the "Spécifications — Periskope" document.

## Layout

| Path | What |
| --- | --- |
| `packages/core` | Check catalogue, DSOMM 5.0.2 activities, scoring and scope rules (the only place they live) |
| `packages/clients` | Async GitLab client: read-only, token file re-read on 401, per-instance quota |
| `packages/checks` | The check registry and the 40 GitLab and repository checks (SonarQube in lot 2) |
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

## Vulnerability priority (KEV and EPSS)

Each open CVE gets a priority, and its correction deadline (24 h, 7, 30, 90 days by default, admin settings) follows it:
listed in CISA's KEV catalogue → critical; EPSS at or above the threshold (10 % by default) → severity raised one level;
EPSS below it → a critical comes down to high; no EPSS → the severity. The network has no Internet: the scheduler reads
both feeds each night (admin setting `feeds_at`, 00:15), from the official sites or an internal copy.

```yaml
vulnFeeds:   # with Internet access (direct, or through proxy)
  kevUrl: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  epssUrl: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  proxy: http://proxy.internal:3128     # optional, used for these two files only
```

Without Internet, the same two files copied daily to an internal web server, and their URLs there (gzipped or plain CSV).
A URL may hold `{date}` (YYYY-MM-DD, UTC) for a daily archive, e.g. a pipeline that drops one file a day in a Nexus raw
repository: Periskope reads the most recent of the last 7 days, so a missed day is not a gap. Such a pipeline: [`docs/vuln-feeds.gitlab-ci.yml`](docs/vuln-feeds.gitlab-ci.yml).

```yaml
vulnFeeds:
  kevUrl: https://nexus.internal/repository/vuln-feeds/kev/known_exploited_vulnerabilities-{date}.json
  epssUrl: https://nexus.internal/repository/vuln-feeds/epss/epss_scores-{date}.csv.gz
```

A feed that fails keeps the previous day's data; the Vulnerabilities tab shows each feed's date and last error. Empty URLs:
priority is the severity.
