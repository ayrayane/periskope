# Changelog

## 1.3.1 — 2026-11-09

- KEV and EPSS feeds: with a private CA (`oidc.caConfigMap`), the feeds trusted that CA alone and refused every public certificate (seen on the lab: `ConnectError`). They now trust the public authorities and the private CA together. A failed read says its cause (certificate, DNS, timeout), still never the address.

## 1.3.0 — 2026-11-09

**Retours UX**
- Open vulnerabilities leave the dashboard (no tile, card or list badge): they live in the « Vulnérabilités » tab, and in a « Vulnérabilités » tab of the project page.
- The « Vulnérabilités » tab opens on the scope's coverage: share of projects whose count can be trusted, split into « remontent des vulnérabilités », « SBOM publié, aucune vulnérabilité », « sans SBOM CycloneDX » (a zero that proves nothing) and « non mesurés »; one click lists the projects of a group. API: `vuln_coverage` on `/projects` (row and filter) and on `/projects/summary`.
- Practices behind the score: the project page reads « 21 pratiques absentes sur 36 attendues » with partial, done and unverified counts; the project list gains a « Pratiques » column; the dashboard shows absent practices per project on average. API: `practices` on `/projects` rows and `/projects/summary`.

- Dashboard tiles fit a low maturity: « Socle niveau 1 en place » (every level-1 practice implemented), « En progrès sur 30 jours » (with those in decline), « Pratiques absentes par projet », « Non mesurés » (never analysed or failing). « Niveau cible non atteint » left the tiles and filters (still in the report). API: `foundation_ok`, `improving`, `declining`, `compared`, `unmeasured` on `/projects/summary`; filters `foundation_missing`, `trend=up|down`, `unmeasured` on `/projects`.
- Project page « Branches » tab: every GitLab branch with its latest analysis, score, gap to the reference branch and an « Analyser » button for maintainers; analysed branches since deleted stay listed. API: `GET /projects/{instance}/{path}/branch-scores`.

**Vulnérabilités (gestion des CVE)**
- Severity colours are GitLab's own (vulnerability report tokens red-800, red-600, orange-400, orange-300, blue-400), each severity shown with its CVSS range (critical 9.0–10, high 7.0–8.9, medium 4.0–6.9, low 0.1–3.9).
- Age of each open vulnerability (from GitLab's first detection, `detectedAt`) and correction deadlines by severity: 24 h, 7, 30 and 90 days by default, admin settings `sla_*`. Counts past the deadline per severity, per CVE and per project. Dates arrive with each project's next analysis.
- Priority of each CVE from exploitation feeds read nightly from an internal mirror (chart `vulnFeeds.kevUrl`, `vulnFeeds.epssUrl`): in CISA's KEV → critical; EPSS ≥ threshold (admin `epss_high_pct`, 10 %) → one level up; low EPSS brings a critical to high; otherwise the severity. Deadlines and « hors délai » follow the priority; « Exploitée (KEV) » badge and EPSS shown per CVE; feed dates and errors shown on the Vulnerabilities tab. Migration 0008 adds `vuln_kev`, `vuln_epss`, `vuln_feeds`.
- Feed URLs may be the official sites, go through `vulnFeeds.proxy`, or hold `{date}` for a daily archive (most recent of the last 7 days); `docs/vuln-feeds.gitlab-ci.yml` copies both feeds into a Nexus raw repository each day.
- Admin settings: `alert_drop` was shown but not saved; it is now.

**Authentification**
- The API no longer checks the token's audience: Keycloak needs no audience mapper. Tokens must still come from the Periskope client (`azp`), from the realm's issuer, signed and unexpired. Chart value `oidc.audience` and `PERISKOPE_OIDC_AUDIENCE` are gone (an old value is ignored).
- Admins by Keycloak login: chart value `admins` (`PERISKOPE_ADMINS`), kept in the deployment repository's `admins.yaml`. A listed login is admin whatever its Keycloak roles; roleMap, client roles and hand grants still work.

**Catalogue**
- The 6 OpenSSF Scorecard entries are removed (never collected, duplicates of existing checks): 47 retained checks. Migration 0007 drops their scope decisions.

## 1.2.0 — 2026-11-04

**Vulnérabilités**
- New « Vulnérabilités » tab: open vulnerabilities of the default branch grouped by CVE (by title without one), searchable, filtered by instance, group and severity; one click lists every project it touches, with its score.
- Portfolio card « Vulnérabilités ouvertes » links to it; the committee report gains an open-vulnerabilities section.
- Read from GitLab's vulnerability report (Ultimate); on CE it says « non mesuré », never zero. Migration 0006 adds the per-project findings.

**Security and robustness (code audit)**
- Plain realm roles of other applications (`admin`, `auditor`) no longer grant Periskope rights: only `periskope-*` realm roles, `oidc.roleMap` entries and client roles count.
- « Corriger dans GitLab »: the GitLab login is bound to the browser that started it; a login link opened by someone else completes nothing.
- Runs left active by a stopped collector are failed by the nightly catch-up instead of blocking their project.
- Hand-granted rights: a project grant opens that project, an instance grant without namespace the whole instance.
- A project listing cut short by the page limit retires no project; a failed nightly task is retried; a tampered cursor is a 400.
- API docs (`/api/v1/docs`) are off unless `PERISKOPE_API_DOCS=true`.

**Interface**
- Long names no longer overflow cards and tables (tooltips on truncated paths), dashboard layout fixed between 1000 and 1400 px.

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
