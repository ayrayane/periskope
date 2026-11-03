# Changelog

## 1.1.0 — 2026-11-03

**Corriger dans GitLab**
- A Maintainer fixes a failing check from its project page: a preview first, then one click applies it with their own GitLab account (OAuth, PKCE). Periskope's service token stays read-only; nothing is ever changed without that click.
- GitLab settings are changed in place (protected branch, force push, pipeline must succeed, visibility, approvals, secret push protection, nightly schedule, masked variables); files arrive as a merge request on a `periskope/…` branch, never pushed to the default branch, and an existing file is never overwritten.
- Each fix is audited (`fix.apply`, `fix.refused`); a setting fix re-analyses the project. Premium and Ultimate fixes are not offered on CE.
- Off by default: `instances[].fixes: true` plus a GitLab OAuth application (`gitlab-oauth-<slug>` Secret, scope `api`); the chart generates the key that encrypts the borrowed GitLab tokens.

**Rights and identity**
- Keycloak roles are mapped to Periskope rights by configuration (`oidc.roleMap`); new `auditor` right reads every project without administering (e.g. a workspace `manager`).
- Account matching by login for LDAP-only realms (`identity.match: username`, optionally GitLab LDAP accounts only), as an alternative to the verified e-mail.
- Launching analyses and scoping a project follow GitLab: Maintainer or Owner of the group or project. The Keycloak `maintainer` role no longer grants it (v1 security audit).

## 1.0.0 — 2026-11-01

First release announced to teams. Periskope reads several GitLab instances, measures 53 OWASP DSOMM 5.0.2 checks per project without asking teams anything, shows each user only the projects they belong to in GitLab, and says what to fix and how.

**Measure**
- 47 collected checks (GitLab API, repository, SonarQube); the 6 Scorecard checks are scoped out by default (no Internet access).
- Score, coverage and per-dimension score up to each project's target level; an unknown result never counts as a failure.
- Sample, vendored and generated code (`examples/`, `vendor/`, `fixtures/`…) is never judged as the product.
- Results are reused only for the same commit, settings, SonarQube analysis and check-engine version.

**Use**
- Dashboard by GitLab instance, group and subgroup; "my projects" first when the scope is small.
- Project page: where to start, practices and checks with filters and sorting, a fix guide for each of the 53 checks (steps, snippet, official docs), to-do, history, branch analysis compared with the default branch.
- Trend, declining projects, heat map, CSV exports (with justifications), printable committee report.
- French names for practices and dimensions; plain-language definitions next to each term.
- Score-drop alerts to Mattermost or any JSON webhook (URL in a Secret).

**Operate**
- Helm chart: one collector, queue and KEDA rule per instance; CloudNativePG primary and replica with continuous WAL archiving and a nightly base backup; Prometheus ServiceMonitor, PodMonitor and alert rules.
- CI: tests with a 70 % coverage gate on the check engine (95 % measured), secret detection, SAST, SBOM, dependency and image scans.

**Security**
- A Keycloak user is tied to a GitLab account only through a verified e-mail; every route hides other teams' projects behind a 404 (tested per route); read-only toward GitLab; no code from analysed repositories is ever run.

**Known limits**
- SonarQube checks untested against a real server (they stay "undetermined" until one is configured).
- Deployment is still run by hand (`helm upgrade`), not by the CI.
- Guests see raw evidence; Keycloak "maintainer" acts on every project the user belongs to; alerts go to one channel for all teams. Planned for 1.1.
