// Demo mode (VITE_DEMO): the real interface over a fictitious, reproducible estate of 10 GitLab instances and 100 projects.
// Check results are drawn per project, then practices, scores and coverage follow Periskope's scoring rules, so every
// screen tells the same story. Nothing leaves the browser; writes are refused (read-only demo).
import catalog from "./catalog.json";

type Status = "pass" | "fail" | "unknown" | "not_applicable";
type Check = (typeof catalog.checks)[number];
type ActivityStatus = "implemented" | "partial" | "not_implemented" | "unknown" | "not_applicable" | "out_of_scope";

const CHECKS = catalog.checks as Check[];
const ACTIVITIES = catalog.activities;
const BY_NAME = Object.fromEntries(ACTIVITIES.map((a) => [a.name, a]));
const TARGET = 3;

function rng(seed: number) {
  let s = seed % 2147483647 || 1;
  return () => (s = (s * 16807) % 2147483647) / 2147483647;
}

const SITES = ["Toulon", "Brest", "Lorient", "Cherbourg", "Paris", "Nantes", "Bordeaux", "Lyon", "Toulouse", "Rennes"];
const GROUPS = ["plateforme", "plateforme/ci", "plateforme/infra", "applications/web", "applications/mobile", "applications/web/front", "data", "data/pipelines", "securite", "securite/outils"];
const NAMES = ["portail", "api-gateway", "auth", "facturation", "catalogue", "reporting", "runner-images", "terraform", "helm-charts", "etl", "scanner", "mobile-app", "design-system", "notifications", "archivage"];
const DAY = 86_400_000;
const NOW = Date.parse("2026-11-02T08:00:00Z");
const iso = (t: number) => new Date(t).toISOString();

export const INSTANCES = SITES.map((c, k) => ({
  slug: c.toLowerCase(), name: `GitLab ${c}`, url: `https://gitlab-${c.toLowerCase()}.example.org`, enterprise: k % 3 === 0,
  last_sync_at: iso(NOW - 7 * 3600_000), sonar: k % 2 === 0,
}));

const MESSAGES: Record<Status, (c: Check) => string> = {
  pass: (c) => `constaté : ${c.title.charAt(0).toLowerCase() + c.title.slice(1)}`,
  fail: (c) => `non constaté : ${/^.[a-zà-ÿ]/.test(c.title) ? c.title.charAt(0).toLowerCase() + c.title.slice(1) : c.title}`,
  unknown: (c) => (c.source === "SonarQube" ? "SonarQube non configuré pour cette instance" : "source indisponible lors de l'analyse"),
  not_applicable: () => "sans objet pour ce projet",
};

function drawResults(quality: number, sonar: boolean, r: () => number) {
  const results: Record<string, { status: Status; message: string; action?: string }> = {};
  for (const c of CHECKS) {
    let s: Status;
    if (c.source === "SonarQube" && !sonar) s = "unknown";
    else if (/docker|image|pinning/i.test(c.id) && r() < 0.2) s = "not_applicable";
    else if (r() < 0.06) s = "unknown";
    else s = r() < quality * (1.25 - c.level * 0.12) ? "pass" : "fail";
    results[c.id] = { status: s, message: MESSAGES[s](c), ...(s !== "pass" && c.action ? { action: c.action } : {}) };
  }
  return results;
}

/** Periskope's rule: main checks decide; an unknown never counts as a failure; partial earns half a point. */
function score(results: Record<string, { status: Status }>) {
  const statuses: Record<string, { status: ActivityStatus; to_confirm: boolean }> = {};
  for (const a of ACTIVITIES) {
    const main = CHECKS.filter((c) => c.activity === a.name && results[c.id]?.status !== "not_applicable");
    if (!main.length) { statuses[a.name] = { status: CHECKS.some((c) => c.activity === a.name) ? "not_applicable" : "out_of_scope", to_confirm: false }; continue; }
    const known = main.filter((c) => results[c.id].status !== "unknown");
    const passed = known.filter((c) => results[c.id].status === "pass");
    const status: ActivityStatus = !known.length ? "unknown" : passed.length === known.length ? "implemented" : passed.length ? "partial" : "not_implemented";
    statuses[a.name] = { status, to_confirm: passed.some((c) => c.kind === "hint") };
  }
  const points: Partial<Record<ActivityStatus, number>> = { implemented: 1, partial: 0.5, not_implemented: 0 };
  const total = (names: string[]) => {
    const counted = names.filter((n) => !["not_applicable", "out_of_scope"].includes(statuses[n].status));
    const measured = counted.filter((n) => statuses[n].status !== "unknown");
    return {
      score: measured.length ? Math.round((1000 * measured.reduce((s, n) => s + (points[statuses[n].status] ?? 0), 0)) / measured.length) / 10 : null,
      coverage: counted.length ? Math.round((1000 * measured.length) / counted.length) / 10 : 0,
    };
  };
  const inTarget = ACTIVITIES.filter((a) => a.level <= TARGET).map((a) => a.name);
  const dims = [...new Set(ACTIVITIES.map((a) => a.dimension))].sort();
  return {
    statuses, ...total(inTarget),
    by_dimension: Object.fromEntries(dims.map((d) => [d, total(inTarget.filter((n) => BY_NAME[n].dimension === d)).score])),
  };
}

/** Open vulnerabilities as GitLab Ultimate counts them: the weaker the project, the more and the more severe. */
function drawVulns(weakness: number, r: () => number) {
  const n = (scale: number) => Math.floor(r() * r() * scale * weakness);
  return { critical: n(4), high: n(14), medium: n(30), low: n(25), info: n(8), unknown: n(3) };
}

// Well-known CVEs and scanner findings: each project draws some of those its severity counts allow.
const CATALOGUE: [key: string, sev: "critical" | "high" | "medium" | "low", title: string, type: string, odds: number][] = [
  ["CVE-2021-44228", "critical", "Log4Shell : exécution de code à distance dans log4j-core", "dependency_scanning", 0.45],
  ["CVE-2022-22965", "critical", "Spring4Shell : exécution de code dans spring-beans", "dependency_scanning", 0.25],
  ["CVE-2022-42889", "critical", "Text4Shell : interpolation dangereuse dans commons-text", "dependency_scanning", 0.2],
  ["CVE-2024-3094", "critical", "Porte dérobée dans xz-utils 5.6.0 et 5.6.1", "container_scanning", 0.12],
  ["CVE-2023-44487", "high", "HTTP/2 Rapid Reset : déni de service", "dependency_scanning", 0.5],
  ["CVE-2023-4863", "high", "Dépassement de tas dans libwebp", "container_scanning", 0.35],
  ["CVE-2024-21626", "high", "runc : évasion de conteneur (Leaky Vessels)", "container_scanning", 0.3],
  ["CVE-2021-23337", "high", "Injection de commande dans lodash", "dependency_scanning", 0.3],
  ["CVE-2022-24999", "high", "Pollution de prototype dans qs", "dependency_scanning", 0.25],
  ["Mot de passe codé en dur", "high", "Mot de passe codé en dur", "secret_detection", 0.2],
  ["CVE-2023-26136", "medium", "Pollution de prototype dans tough-cookie", "dependency_scanning", 0.4],
  ["CVE-2024-28849", "medium", "follow-redirects divulgue l'en-tête Proxy-Authorization", "dependency_scanning", 0.35],
  ["Algorithme de hachage faible (MD5)", "medium", "Algorithme de hachage faible (MD5)", "sast", 0.3],
  ["CVE-2020-8908", "low", "Guava : répertoire temporaire lisible par tous", "dependency_scanning", 0.3],
  ["En-tête Content-Security-Policy absent", "low", "En-tête Content-Security-Policy absent", "dast", 0.25],
];

function drawFindings(v: ReturnType<typeof drawVulns> | null, r: () => number) {
  return v && CATALOGUE.filter(([, sev, , , odds]) => v[sev] > 0 && r() < odds)
    .map(([key, severity, title, type]) => ({ key, cve: key.startsWith("CVE-"), severity, title, type, detected_at: iso(NOW - Math.floor(r() * 120 * DAY)) }));
}

type Demo = ReturnType<typeof makeProject>;
function makeProject(id: number, inst: (typeof INSTANCES)[number], n: number, groups: string[], bias: number, r: () => number) {
  const ns = groups[Math.floor(r() * groups.length)];
  const path = `${ns}/${NAMES[(n + id) % NAMES.length]}${n > 6 ? `-${n}` : ""}`;
  const never = r() < 0.08;
  const quality = Math.min(0.97, Math.max(0.08, bias + (r() - 0.5) * 0.45));
  const results = drawResults(quality, inst.sonar, r);
  const s = never ? null : score(results);
  const lastAt = NOW - Math.floor(r() * 10 * DAY) - 3600_000;
  const failed = !never && r() < 0.05;
  const vulns = never || !inst.enterprise ? null : drawVulns(1 - quality, r);
  const history = never ? [] : Array.from({ length: 6 }, (_, k) => {
    const sc = Math.max(0, Math.min(100, (s!.score ?? 0) - (5 - k) * (r() * 4) + (r() - 0.5) * 3));
    return { id: id * 100 + k, branch: "main", commit_sha: Math.floor(r() * 2 ** 48).toString(16).padStart(12, "0") + "abcd1234",
      trigger: k === 5 ? "nightly" : ["webhook", "nightly", "user"][k % 3], requested_by: k % 3 === 2 ? "demo" : null, status: "succeeded" as const,
      created_at: iso(lastAt - (5 - k) * 4 * DAY), finished_at: iso(lastAt - (5 - k) * 4 * DAY + 40_000), error: null,
      score: k === 5 ? s!.score : Math.round(sc * 10) / 10, coverage: s!.coverage };
  });
  return {
    id, instance: inst.slug, path, namespace_path: ns, default_branch: "main", target_level: TARGET,
    score: s?.score ?? null, coverage: s?.coverage ?? null, by_dimension: s?.by_dimension ?? null, statuses: s?.statuses ?? null,
    last_success_at: never ? null : iso(lastAt), last_error: failed ? "GitLab indisponible (503)" : null,
    last_run_id: never ? null : id * 100 + 5, last_status: "succeeded", results: never ? null : results, history,
    vulns, findings: drawFindings(vulns, r),
    // From the id, not the generator: the rest of the estate stays what it was.
    topics: [["prod"], ["prod"], ["prod"], ["test"], ["dev"], ["dev"], []][id % 7],
  };
}

const PROJECTS: Demo[] = (() => {
  const r = rng(7);
  const out: Demo[] = [];
  let id = 1;
  for (const inst of INSTANCES) {
    const groups = GROUPS.filter(() => r() > 0.25);
    const bias = 0.25 + r() * 0.55;
    for (let n = 0; n < 10; n++) out.push(makeProject(id++, inst, n, groups.length ? groups : ["plateforme"], bias, rng(id * 9973)));
  }
  return out;
})();

const practices = (x: Demo) => {
  if (!x.statuses) return null;
  const counted = ACTIVITIES.filter((a) => a.level <= TARGET && !["not_applicable", "out_of_scope"].includes(x.statuses![a.name].status));
  const n = (st: string) => counted.filter((a) => x.statuses![a.name].status === st).length;
  return { done: n("implemented"), partial: n("partial"), missing: n("not_implemented"), unknown: n("unknown"), counted: counted.length };
};
const vulnCoverage = (x: Demo) => {
  const sbom = x.results?.["gitlab.sbom_artifact"]?.status;
  return x.last_run_id == null ? "unmeasured" : x.vulns && SEV.some((k) => x.vulns![k] > 0) ? "reporting"
    : sbom === "fail" ? "blind" : sbom === "pass" && x.vulns ? "clean" : "unmeasured";
};
const foundation = (x: Demo) => !!x.statuses && ACTIVITIES.every((a) => a.level !== 1 || !["not_implemented", "partial", "unknown"].includes(x.statuses![a.name]?.status));
// The demo's score 30 days ago: its oldest kept analysis.
const before = (x: Demo) => x.history[0]?.score ?? null;
const trendOf = (x: Demo) => { const b = before(x); return b == null || x.score == null ? null : x.score > b + 1 ? "up" : x.score < b - 1 ? "down" : "flat"; };
const row = (x: Demo) => {
  const { results, history, statuses, findings, ...p } = x;
  return { ...p, practices: practices(x), vuln_coverage: vulnCoverage(x) };
};
const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
const inScope = (q: URLSearchParams) => PROJECTS.filter((p) => (!q.get("instance") || p.instance === q.get("instance"))
  && (!q.get("env") || (q.get("env") === "none" ? !p.topics.length : p.topics.includes(q.get("env")!)))
  && (!q.get("namespace") || p.namespace_path === q.get("namespace") || p.namespace_path.startsWith(q.get("namespace") + "/")));

function roadmap(p: Demo) {
  return ACTIVITIES.filter((a) => a.level <= TARGET && ["not_implemented", "partial"].includes(p.statuses?.[a.name]?.status ?? ""))
    .sort((a, b) => a.level - b.level || a.name.localeCompare(b.name))
    .map((a) => ({ activity: a.name, dimension: a.dimension, level: a.level, status: p.statuses![a.name].status, blocked_by: [],
      steps: CHECKS.filter((c) => c.activity === a.name && p.results?.[c.id]?.status === "fail").map((c) => ({ check: c.id, action: c.action, message: p.results![c.id].message })) }));
}

const SEV = ["critical", "high", "medium", "low", "info", "unknown"] as const;
// Deadlines by SSVC response (D5); Différé has none.
const SLA: Record<string, number> = { immediate: 7 * 24, out_of_cycle: 30 * 24, scheduled: 90 * 24 };
const RESP = ["immediate", "out_of_cycle", "scheduled", "deferred"];
// Demo exploitation data: Log4Shell, Text4Shell and xz-utils are in KEV; EPSS made up per CVE.
const KEV = new Set(["CVE-2021-44228", "CVE-2022-42889", "CVE-2024-3094", "CVE-2023-44487"]);
const epssOf = (key: string) => (KEV.has(key) ? 0.94 : key.startsWith("CVE-") ? [0.94, 0.002, 0.31, 0.05, 0.0004, 0.12][[...key].reduce((a, c) => a + c.charCodeAt(0), 0) % 6] : null);
const priorityOf = (f: { key: string; severity: string }) => {
  const e = epssOf(f.key);
  if (KEV.has(f.key)) return "critical";
  if (e != null && e >= 0.1) return f.severity === "medium" ? "high" : f.severity === "low" ? "medium" : "critical";
  return e != null && f.severity === "critical" ? "high" : f.severity;
};
type Finding = { key: string; severity: string; detected_at: string; type?: string };
// The SQL's SSVC, on the demo: exploitation (KEV, EPSS), exposure (prod or no environment), automatable (the RCE-like CVEs) or critical.
const AUTOMATABLE = new Set(["CVE-2021-44228", "CVE-2022-22965", "CVE-2022-42889", "CVE-2023-44487"]);
const responseOf = (f: Finding, topics: string[]) => {
  const exposed = topics.includes("prod") || !topics.some((t) => t === "test" || t === "dev");
  const strong = f.severity === "critical" || AUTOMATABLE.has(f.key), e = epssOf(f.key) ?? 0;
  if (KEV.has(f.key)) return exposed ? "immediate" : "out_of_cycle";
  if (f.severity === "info" || f.severity === "unknown") return "deferred";
  if (e >= 0.1) return exposed && strong ? "immediate" : exposed ? "out_of_cycle" : "scheduled";
  return exposed && strong ? "out_of_cycle" : exposed ? "scheduled" : "deferred";
};
const late = (f: Finding, topics: string[]) => {
  const h = SLA[responseOf(f, topics)];
  return !!h && Date.parse(f.detected_at) + h * 3_600_000 < Date.now();
};
const PRIO = ["critical", "high", "medium", "low"];
function vulnSummary(items: Demo[]) {
  const measured = items.filter((x) => x.vulns);
  if (!measured.length) return null;
  const sums = Object.fromEntries(SEV.map((k) => [k, measured.reduce((s, x) => s + x.vulns![k], 0)])) as Record<(typeof SEV)[number], number>;
  const exposed = measured.filter((x) => x.vulns!.critical + x.vulns!.high > 0)
    .sort((a, b) => b.vulns!.critical - a.vulns!.critical || b.vulns!.high - a.vulns!.high || a.path.localeCompare(b.path)).slice(0, 5)
    .map(({ instance, path, vulns }) => ({ instance, path, vulns: vulns! }));
  const found = measured.flatMap((x) => (x.findings ?? []).map((f) => ({ f, t: x.topics })));
  const overdue = Object.fromEntries(Object.keys(SLA).map((k) => [k, found.filter(({ f, t }) => responseOf(f, t) === k && late(f, t)).length]));
  const byResponse = Object.fromEntries(RESP.map((k) => [k, found.filter(({ f, t }) => responseOf(f, t) === k).length]));
  const byPriority = Object.fromEntries(PRIO.map((k) => [k, found.filter(({ f }) => priorityOf(f) === k).length]));
  return { ...sums, total: SEV.reduce((s, k) => s + sums[k], 0), projects: measured.length, exposed, sla_hours: SLA, overdue, dated: found.length,
    by_response: byResponse, by_priority: byPriority, kev: found.filter(({ f }) => KEV.has(f.key)).length };
}

class DemoError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

// « Corriger dans GitLab » in the demo: real previews of a few fixes, an apply that changes nothing.
const DEMO_FIXES: Record<string, { kind: "setting" | "mr"; label: string; preview: object }> = {
  "gitlab.pipeline_must_succeed": { kind: "setting", label: "Exiger un pipeline réussi avant le merge", preview: {
    summary: "Exiger un pipeline réussi avant le merge.", changes: [{ what: "Merge avec un pipeline en échec", before: "possible", after: "bloqué" }] } },
  "gitlab.protected_branch_no_push": { kind: "setting", label: "Fermer le push direct", preview: {
    summary: "Protéger « main » : plus aucun push direct, les changements passent par des merge requests.",
    changes: [{ what: "Push direct sur main", before: "push direct : Maintainers", after: "personne (merge : Maintainers)" }] } },
  "gitlab.secret_detection": { kind: "mr", label: "Ajouter la détection de secrets", preview: {
    summary: "Ajouter le job GitLab Secret Detection au pipeline.",
    files: [{ path: ".gitlab/ci/periskope-security.yml", content: "include:\n  # periskope: gitlab.secret_detection\n  - template: Jobs/Secret-Detection.gitlab-ci.yml\n" },
      { path: ".gitlab-ci.yml", content: "include:\n  - local: .gitlab/ci/periskope-security.yml\nstages: [build, test]\n…" }] } },
  "repo.patch_policy": { kind: "mr", label: "Ajouter SECURITY.md", preview: {
    summary: "Ajouter une politique de correctifs (SECURITY.md).",
    files: [{ path: "SECURITY.md", content: "# Politique de sécurité\n\nSignalez une faille à l'équipe via un ticket confidentiel.\nLes failles critiques sont corrigées sous 7 jours, les hautes sous 30 jours.\n" }] } },
};

function demoFix(instance: string, path: string, check: string | undefined, preview: boolean): unknown {
  const proj = PROJECTS.find((x) => x.instance === instance && x.path === path);
  if (!proj) throw new DemoError(404, "Ce projet n'existe pas dans la démo.");
  if (!check) return { enabled: true, can_fix: true, connected: true, items: Object.entries(DEMO_FIXES)
    .filter(([id]) => proj.results?.[id]?.status === "fail").map(([id, f]) => ({ check: id, kind: f.kind, label: f.label, needs: null })) };
  const f = DEMO_FIXES[check];
  if (!f) throw new DemoError(404, "Pas de correction automatique pour cette preuve.");
  if (preview) return f.preview;
  return f.kind === "mr" ? { done: "Démo : la merge request aurait été ouverte avec votre compte GitLab. Rien n'a été modifié." }
    : { done: "Démo : le réglage aurait été appliqué avec votre compte GitLab. Rien n'a été modifié." };
}

// Dependency-Track in the demo: the projects of the first group with findings are bricks of the CMS, in prod and test and in two JAR deliveries.
const DT_TYPES = new Set(["dependency_scanning", "container_scanning"]);
const BRICKS = PROJECTS.filter((x) => x.findings?.some((f) => DT_TYPES.has(f.type)) && x.instance === PROJECTS[0].instance).slice(0, 9);
const TREES = [
  { uuid: "t-prod", name: "CMS · prod", env: "prod", active: true, minor: 4 }, { uuid: "t-test", name: "CMS · test", env: "test", active: true, minor: 5 },
  { uuid: "t-520", name: "CMS · 5.2.0 (livraison JAR)", env: null, active: true, minor: 4 }, { uuid: "t-510", name: "CMS · 5.1.0 (livraison JAR)", env: null, active: false, minor: 2 },
];
const brickName = (x: Demo) => x.path.split("/").at(-1)!;
const versionOf = (x: Demo, t: (typeof TREES)[number]) => `${1 + (x.id % 3)}.${t.minor}.${x.id % 4}`;
// What DT finds in a brick of a tree: its dependency findings; test has fixed the most severe one; 5.1.0 still carries an older one.
const dtFindings = (x: Demo, t: (typeof TREES)[number]) => {
  const own = (x.findings ?? []).filter((f) => DT_TYPES.has(f.type));
  return t.env === "test" ? own.slice(1) : t.uuid === "t-510" ? [...own, { key: "CVE-2022-22965", cve: true, severity: "critical", title: "Spring4Shell : exécution de code dans spring-beans", type: "dependency_scanning", detected_at: iso(NOW - 300 * DAY) }] : own;
};
const dtTrees = (x: Demo) => (BRICKS.includes(x) ? TREES.filter((t) => t.active).map((t) => t.name) : null);
const sbom = (x: Demo) => x.id % 5 !== 0;
const byTag = (x: Demo) => x.id % 7 === 2;
const noPurl = (x: Demo) => x.id % 4;
function dtBricksOf(x: Demo) {
  return BRICKS.includes(x) ? TREES.filter((t) => t.active).map((t) => ({ tree: t.name, env: t.env, uuid: `${t.uuid}-${x.id}`, version: versionOf(x, t),
    sbom: sbom(x), by_tag: t.env === "prod" && byTag(x), components: sbom(x) ? 120 + x.id % 90 : null, no_purl: sbom(x) ? noPurl(x) : null })) : null;
}
const where = (x: Demo, t: (typeof TREES)[number], f: { key: string }) => `${brickName(x)} ${versionOf(x, t)} · ${f.key === "CVE-2021-44228" ? "org.apache.logging.log4j:log4j-core@2.14.1" : "dépendance"}`;
function dtVersion(t: (typeof TREES)[number]) {
  const found = new Map<string, { key: string; cve: boolean; title: string; severity: string; response: string; kev: boolean; epss: number | null; where: string[] }>();
  for (const x of BRICKS) for (const f of dtFindings(x, t)) {
    const g = found.get(f.key) ?? { key: f.key, cve: f.cve, title: f.title, severity: f.severity, response: responseOf(f, t.env === "test" ? ["test"] : ["prod"]), kev: KEV.has(f.key), epss: epssOf(f.key), where: [] };
    g.where.push(where(x, t, f));
    found.set(f.key, g);
  }
  return [...found.values()].sort((a, b) => RESP.indexOf(a.response) - RESP.indexOf(b.response) || SEV.indexOf(a.severity as (typeof SEV)[number]) - SEV.indexOf(b.severity as (typeof SEV)[number]) || a.key.localeCompare(b.key));
}
const treeOf = (uuid: string | null) => {
  const t = TREES.find((x) => x.uuid === uuid);
  if (!t) throw new DemoError(404, "Version introuvable.");
  return t;
};
const treeRow = (t: (typeof TREES)[number]) => ({ uuid: t.uuid, name: t.name, env: t.env, active: t.active, synced_at: iso(NOW - 1800_000) });
const EXCEPTIONS = () => BRICKS.slice(0, 3).map((x, i) => ({ key: ["CVE-2023-26136", "CVE-2020-8908", "CVE-2024-28849"][i], title: null, severity: (["medium", "low", "medium"] as const)[i],
  kind: "exception", state: "EXPLOITABLE", justification: null, response: "WILL_NOT_FIX", detail: ["Correctif bloqué par le fournisseur, contournement en place (proxy)", "Répertoire temporaire jamais utilisé en prod", "Risque accepté jusqu'à la migration de la brique"][i],
  analysed_at: iso(NOW - [120, 40, 100][i] * DAY), expires_on: iso(NOW + [-30, 50, -10][i] * DAY).slice(0, 10), expired: [true, false, true][i], brick: brickName(x), version: versionOf(x, TREES[0]), tree: "CMS · prod", instance: x.instance, path: x.path }));
const NOT_CONCERNED = () => BRICKS.slice(2, 5).map((x, i) => ({ key: ["CVE-2023-4863", "CVE-2021-23337", "CVE-2022-24999"][i], title: null, severity: "high", kind: "not_concerned", state: "NOT_AFFECTED",
  justification: ["CODE_NOT_REACHABLE", "CODE_NOT_PRESENT", "PROTECTED_AT_PERIMETER"][i], response: null, detail: ["libwebp présente dans l'image de base, jamais chargée", "Fonction template() non utilisée", "Parseur exposé derrière le proxy qui filtre"][i],
  analysed_at: iso(NOW - (10 + 20 * i) * DAY), expires_on: null, expired: null, brick: brickName(x), version: versionOf(x, TREES[0]), tree: "CMS · prod", instance: x.instance, path: x.path }));

function dtRoute(p: string, q: URLSearchParams): unknown {
  if (p === "/dt/work") {
    const mine = BRICKS.filter((x) => inScope(q).includes(x));
    const ref = (x: Demo) => ({ uuid: `t-prod-${x.id}`, name: brickName(x), version: versionOf(x, TREES[0]), components: 120 + x.id % 90, no_purl: noPurl(x), tree: "CMS · prod", instance: x.instance, path: x.path });
    return { configured: true, synced_at: iso(NOW - 1800_000), no_sbom: mine.filter((x) => !sbom(x)).map(ref), by_tag: mine.filter(byTag).map(ref),
      no_purl: mine.filter((x) => sbom(x) && noPurl(x)).map(ref), expired_exceptions: EXCEPTIONS().filter((e) => e.expired && mine.some((x) => x.path === e.path)).length,
      stale_sources: [{ name: "NVD", completed_at: iso(Date.now() - 4 * DAY), via: "dependency-track" }] };
  }
  if (p === "/dt/versions") return TREES.map((t) => {
    const f = dtVersion(t);
    return { ...treeRow(t), bricks: BRICKS.length, no_sbom: BRICKS.filter((x) => !sbom(x)).length, open: f.length, immediate: f.filter((x) => x.response === "immediate").length };
  });
  const one = /^\/dt\/versions\/(.+)$/.exec(p);
  if (one) {
    const t = treeOf(one[1]);
    return { tree: treeRow(t), findings: dtVersion(t), bricks: BRICKS.map((x) => ({ uuid: `${t.uuid}-${x.id}`, name: brickName(x), version: versionOf(x, t), active: t.active, sbom: sbom(x),
      by_tag: t.env === "prod" && byTag(x), components: sbom(x) ? 120 + x.id % 90 : null, no_purl: sbom(x) ? noPurl(x) : null, instance: x.instance, path: x.path })) };
  }
  if (p === "/dt/compare") {
    const a = treeOf(q.get("a")), b = treeOf(q.get("b")), fa = dtVersion(a), fb = dtVersion(b);
    const ka = new Set(fa.map((x) => x.key)), kb = new Set(fb.map((x) => x.key));
    return { a: treeRow(a), b: treeRow(b), bricks: BRICKS.filter((x) => versionOf(x, a) !== versionOf(x, b)).map((x) => ({ name: brickName(x), a: versionOf(x, a), b: versionOf(x, b) })),
      only_a: fa.filter((x) => !kb.has(x.key)), only_b: fb.filter((x) => !ka.has(x.key)), both: fb.filter((x) => ka.has(x.key)) };
  }
  const cve = /^\/dt\/cve\/(.+)$/.exec(p);
  if (cve) {
    const key = cve[1], places: Record<string, unknown>[] = [], fixed: Record<string, unknown>[] = [], ledger: Record<string, unknown>[] = [];
    for (const t of TREES) for (const x of BRICKS) {
      const f = dtFindings(x, t).find((v) => v.key === key);
      const row = { tree: t.name, env: t.env, tree_active: t.active, brick: brickName(x), version: versionOf(x, t), active: true };
      if (f) places.push({ ...row, tree_uuid: t.uuid, instance: x.instance, path: x.path, component_name: key === "CVE-2021-44228" ? "org.apache.logging.log4j:log4j-core" : "dépendance",
        component_version: key === "CVE-2021-44228" ? "2.14.1" : "1.0", title: f.title, severity: f.severity, vector: null, kev: KEV.has(key), epss: epssOf(key),
        state: t.env === "prod" && x === BRICKS[0] ? "IN_TRIAGE" : null, analysis_response: t.env === "prod" && x === BRICKS[0] ? "UPDATE" : null,
        justification: null, detail: t.env === "prod" && x === BRICKS[0] ? "Patch ciblé livré hors cycle (log4j 2.17.1), version corrigée en qualification" : null,
        analysed_at: t.env === "prod" && x === BRICKS[0] ? iso(NOW - 2 * DAY) : null, expires_on: null, attributed_at: f.detected_at, status: "open", response: responseOf(f, t.env === "test" ? ["test"] : ["prod"]) });
      else if (places.some((pl) => pl.brick === brickName(x)) || BRICKS.some((y) => y === x && (y.findings ?? []).some((v) => v.key === key))) fixed.push(row);
    }
    for (const x of PROJECTS) for (const f of x.findings ?? []) if (f.key === key) ledger.push({ instance: x.instance, path: x.path, opened_at: f.detected_at, closed_at: null,
      priority: priorityOf(f), response: responseOf(f, x.topics), deadline_at: SLA[responseOf(f, x.topics)] ? iso(Date.parse(f.detected_at) + SLA[responseOf(f, x.topics)] * 3_600_000) : null });
    if (key === "CVE-2022-22965") ledger.push({ instance: BRICKS[0].instance, path: BRICKS[0].path, opened_at: iso(NOW - 300 * DAY), closed_at: iso(NOW - 250 * DAY), priority: "critical", response: "immediate", deadline_at: iso(NOW - 293 * DAY) });
    if (!places.length && !ledger.length) throw new DemoError(404, "CVE introuvable.");
    return { key, places, fixed_in: fixed, ledger };
  }
  if (p === "/dt/exceptions") return { exceptions: EXCEPTIONS().sort((a, b) => a.expires_on.localeCompare(b.expires_on)), not_concerned: NOT_CONCERNED() };
  if (p === "/indicators") {
    const months = Array.from({ length: 6 }, (_, k) => {
      const d = new Date(NOW); d.setDate(1); d.setMonth(d.getMonth() - 5 + k);
      const fixed = [9, 12, 7, 14, 11, 8][k], on = [5, 8, 6, 12, 10, 8][k];
      return { month: d.toISOString().slice(0, 10), critical_fixed: fixed, critical_on_time: on, days: { critical: [14, 11, 9, 7, 6, 5][k], high: [40, 35, 33, 28, 26, 22][k], medium: [80, 76, 70, 66, 61, 58][k], low: null },
        overdue_stock: [64, 58, 51, 47, 40, 33][k] };
    });
    return { months, sbom: { bricks: BRICKS.length, with_sbom: BRICKS.filter(sbom).length }, exceptions: { active: 1, expired: 2 } };
  }
  return undefined;
}

function route(path: string, method: string): unknown {
  const u = new URL(path, "https://demo.invalid");
  const q = u.searchParams;
  const p = decodeURIComponent(u.pathname);
  const fix = /^\/projects\/([^/]+)\/(.+?)\/fixes(?:\/([^/]+?)(\/preview)?)?$/.exec(p);
  if (fix) return demoFix(fix[1], fix[2], fix[3], !!fix[4]);
  if (method !== "GET") throw new DemoError(403, "Démo en lecture seule : aucune analyse ni modification n'est possible ici.");
  if (p === "/me") return { sub: "demo", username: "demo", admin: false, reads_all: true, namespaces: [], maintains: [] };
  if (p === "/instances") return INSTANCES.map(({ sonar, ...i }) => i);
  if (p === "/checks") return CHECKS.map((c) => ({ ...c, scope: null }));
  if (p === "/activities") return { version: "5.0.2", items: ACTIVITIES };
  if (p === "/groups") {
    const g: Record<string, { instance: string; path: string; projects: number; analysed: number; score_sum: number }> = {};
    for (const x of PROJECTS) {
      const e = (g[`${x.instance} ${x.namespace_path}`] ||= { instance: x.instance, path: x.namespace_path, projects: 0, analysed: 0, score_sum: 0 });
      e.projects++; if (x.score != null) { e.analysed++; e.score_sum += x.score; }
    }
    return Object.values(g);
  }
  if (p === "/projects") {
    let items = inScope(q);
    if (q.get("q")) items = items.filter((x) => x.path.toLowerCase().includes(q.get("q")!.toLowerCase()));
    if (q.get("below_target")) items = items.filter((x) => x.score != null && x.score < 100);
    if (q.get("failed")) items = items.filter((x) => x.last_error);
    if (q.get("never")) items = items.filter((x) => x.score == null);
    if (q.get("foundation_missing")) items = items.filter((x) => x.statuses && !foundation(x));
    if (q.get("trend")) items = items.filter((x) => trendOf(x) === q.get("trend"));
    if (q.get("unmeasured")) items = items.filter((x) => x.score == null || x.last_error);
    if (q.get("vuln_coverage")) items = items.filter((x) => vulnCoverage(x) === q.get("vuln_coverage"));
    const sort = q.get("sort");
    items = [...items].sort(sort === "score" ? (a, b) => (b.score ?? -1) - (a.score ?? -1)
      : sort === "last_run" ? (a, b) => (b.last_success_at ?? "").localeCompare(a.last_success_at ?? "") : (a, b) => a.path.localeCompare(b.path));
    return { items: items.map(row), next_cursor: null };
  }
  if (p === "/projects/summary") {
    const items = inScope(q), sc = items.filter((x) => x.score != null);
    const every = new URLSearchParams(q); every.delete("env");
    const all = inScope(every), count = (e: string) => all.filter((x) => x.topics.includes(e)).length;
    const dims = [...new Set(ACTIVITIES.map((a) => a.dimension))].sort();
    const gaps = ACTIVITIES.filter((a) => a.level <= TARGET).map((a) => {
      const measured = sc.filter((x) => ["implemented", "partial", "not_implemented"].includes(x.statuses![a.name].status));
      return { activity: a.name, level: a.level, missing: measured.filter((x) => x.statuses![a.name].status !== "implemented").length, measured: measured.length };
    }).filter((g) => g.missing).sort((a, b) => b.missing - a.missing || a.level - b.level);
    return {
      envs: { prod: count("prod"), test: count("test"), dev: count("dev"), none: all.filter((x) => !x.topics.length).length, total: all.length },
      total: items.length, analysed: sc.length, score: avg(sc.map((x) => x.score!)), coverage: avg(sc.map((x) => x.coverage!)),
      below_target: sc.filter((x) => x.score! < 100).length, failed: items.filter((x) => x.last_error).length, never: items.length - sc.length,
      high: sc.filter((x) => x.score! >= 75).length, mid: sc.filter((x) => x.score! >= 50 && x.score! < 75).length, low: sc.filter((x) => x.score! < 50).length,
      dimensions: Object.fromEntries(dims.map((d) => [d, avg(sc.map((x) => x.by_dimension![d]).filter((v): v is number => v != null)) ?? 0])),
      gaps, lowest: [...sc].sort((a, b) => a.score! - b.score!).slice(0, 3).map(({ instance, path, score, coverage, last_success_at }) => ({ instance, path, score, coverage, last_success_at })),
      vulns: vulnSummary(items),
      feeds: { kev: { configured: true, fetched_at: iso(NOW), rows: 1484, published: null, error: null },
        epss: { configured: true, fetched_at: iso(NOW), rows: 299112, published: iso(NOW - DAY), error: null } },
      // Dated from the real clock: the 2-day freshness rule is read against today.
      sources: [{ name: "EPSS", completed_at: iso(Date.now()), error: null, via: "periskope" }, { name: "KEV", completed_at: iso(Date.now()), error: null, via: "periskope" },
        { name: "GITHUB", completed_at: iso(Date.now() - 3600_000), error: null, via: "dependency-track" }, { name: "NVD", completed_at: iso(Date.now() - 4 * DAY), error: null, via: "dependency-track" },
        { name: "OSV", completed_at: iso(Date.now() - 5 * 3600_000), error: null, via: "dependency-track" }],
      foundation_ok: items.filter(foundation).length, unmeasured: items.filter((x) => x.score == null || x.last_error).length,
      improving: items.filter((x) => trendOf(x) === "up").length, declining: items.filter((x) => trendOf(x) === "down").length,
      compared: items.filter((x) => trendOf(x) != null).length,
      practices: sc.length ? { projects: sc.length, ...Object.fromEntries((["done", "partial", "missing", "unknown", "counted"] as const).map((k) => [k, avg(sc.map((x) => practices(x)![k]))])) } : null,
      vuln_coverage: Object.fromEntries(["reporting", "clean", "blind", "unmeasured"].map((b) => [b, items.filter((x) => vulnCoverage(x) === b).length])),
    };
  }
  if (p === "/vulnerabilities") {
    const measured = inScope(q).filter((x) => x.findings), needle = q.get("q")?.toLowerCase();
    const groups = new Map<string, { key: string; cve: boolean; title: string; severity: string; projects: number; detected_at: string; overdue: number; response: string }>();
    for (const [f, t] of measured.flatMap((x) => x.findings!.map((f) => [f, x.topics] as const))) {
      if (needle && !f.key.toLowerCase().includes(needle) && !f.title.toLowerCase().includes(needle)) continue;
      const g = groups.get(f.key) ?? { key: f.key, cve: f.cve, title: f.title, severity: f.severity, projects: 0, detected_at: f.detected_at, overdue: 0, response: "deferred" };
      g.projects++;
      if (late(f, t)) g.overdue++;
      if (RESP.indexOf(responseOf(f, t)) < RESP.indexOf(g.response)) g.response = responseOf(f, t);
      Object.assign(g, { priority: priorityOf(f), kev: KEV.has(f.key), epss: epssOf(f.key), percentile: null });
      if (f.detected_at < g.detected_at) g.detected_at = f.detected_at;
      groups.set(f.key, g);
    }
    const rank = (s: string) => SEV.indexOf(s as (typeof SEV)[number]);
    return { measured: measured.length, sla_hours: SLA, items: [...groups.values()].sort((a, b) => RESP.indexOf(a.response) - RESP.indexOf(b.response) || rank(priorityOf(a)) - rank(priorityOf(b)) || rank(a.severity) - rank(b.severity) || b.projects - a.projects || a.key.localeCompare(b.key)) };
  }
  if (p === "/vulnerabilities/projects") {
    return inScope(q).flatMap((x) => (x.findings ?? []).filter((f) => f.key === q.get("key")).map((f) => ({ instance: x.instance, path: x.path, score: x.score, coverage: x.coverage, severity: f.severity, type: DT_TYPES.has(f.type) && dtTrees(x) ? "dependency_track" : f.type, detected_at: f.detected_at, overdue: late(f, x.topics), priority: priorityOf(f),
      response: responseOf(f, x.topics), kev: KEV.has(f.key), epss: epssOf(f.key), ...(DT_TYPES.has(f.type) && dtTrees(x) ? { trees: dtTrees(x), components: [] } : {}) })))
      .sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || a.instance.localeCompare(b.instance) || a.path.localeCompare(b.path));
  }
  if (p === "/vulnerabilities/by-project") {
    const needle = q.get("q")?.toLowerCase(), offset = Number(q.get("offset") ?? 0), limit = Number(q.get("limit") ?? 50);
    const rows = inScope(q).filter((x) => x.findings?.length && (!needle || x.path.toLowerCase().includes(needle))).map((x) => {
      const f = x.findings!, by = Object.fromEntries(PRIO.map((k) => [k, f.filter((v) => priorityOf(v) === k).length]));
      const resp = Object.fromEntries(["immediate", "out_of_cycle"].map((k) => [k, f.filter((v) => responseOf(v, x.topics) === k).length]));
      return { instance: x.instance, path: x.path, score: x.score, coverage: x.coverage, total: f.length, overdue: f.filter((v) => late(v, x.topics)).length,
        kev: f.filter((v) => KEV.has(v.key)).length, by_priority: by, by_response: resp };
    }).sort((a, b) => b.by_priority.critical - a.by_priority.critical || b.by_priority.high - a.by_priority.high || b.by_priority.medium - a.by_priority.medium
      || b.by_priority.low - a.by_priority.low || b.overdue - a.overdue || b.total - a.total || a.path.localeCompare(b.path));
    return { items: rows.slice(offset, offset + limit), next_offset: offset + limit < rows.length ? offset + limit : null };
  }
  if (p === "/projects/trend") {
    const sc = inScope(q).filter((x) => x.score != null), now = avg(sc.map((x) => x.score!)) ?? 0;
    return {
      months: Array.from({ length: 11 }, (_, k) => ({ month: `2026-${String(k + 1).padStart(2, "0")}-01`, score: Math.max(3, now - (10 - k) * 2.1 + Math.sin(k * 1.7) * 2.5), projects: sc.length })),
      declining: sc.filter((x) => x.id % 11 === 3).slice(0, 4).map((x) => ({ instance: x.instance, path: x.path, score: x.score, before: Math.min(100, x.score! + 7 + (x.id % 9)), since: iso(NOW - 30 * DAY) })),
    };
  }
  if (p === "/groups/heatmap") {
    const inst = q.get("instance"), ns = q.get("namespace");
    const key = (x: Demo) => (!inst ? x.instance : !ns ? x.namespace_path.split("/")[0] : x.namespace_path === ns ? "" : x.namespace_path.slice(ns.length + 1).split("/")[0]);
    const dims = [...new Set(ACTIVITIES.map((a) => a.dimension))].sort();
    const rows: Record<string, Demo[]> = {};
    for (const x of inScope(q).filter((x) => x.score != null)) (rows[key(x)] ||= []).push(x);
    return { dimensions: dims, rows: Object.entries(rows).map(([k, xs]) => ({ key: k, projects: xs.length,
      cells: Object.fromEntries(dims.map((d) => [d, avg(xs.map((x) => x.by_dimension![d]).filter((v): v is number => v != null))])) })) };
  }
  if (p === "/projects/export.csv") throw new DemoError(403, "Les exports sont désactivés dans la démo.");
  const runMatch = /^\/runs\/(\d+)(\/diff|\/evidence)?$/.exec(p);
  if (runMatch) {
    const id = Number(runMatch[1]);
    const proj = PROJECTS.find((x) => x.history.some((h) => h.id === id));
    const run = proj?.history.find((h) => h.id === id);
    if (!proj || !run) throw new DemoError(404, "Analyse introuvable.");
    if (runMatch[2] === "/evidence") return {};
    if (runMatch[2] === "/diff") {
      const prev = proj.history[proj.history.indexOf(run) - 1] ?? run;
      const pick = (h: typeof run) => ({ id: h.id, branch: h.branch, commit_sha: h.commit_sha, finished_at: h.finished_at, score: h.score, coverage: h.coverage });
      return { before: pick(prev), after: pick(run), gained: [], lost: [], changed: [] };
    }
    return { ...run, instance: proj.instance, path: proj.path, default_branch: "main", results: proj.results };
  }
  const dt = dtRoute(p, q);
  if (dt !== undefined) return dt;
  const projMatch = /^\/projects\/([^/]+)\/(.+?)(\/branches|\/branch-scores|\/runs|\/roadmap)?$/.exec(p);
  if (projMatch) {
    const proj = PROJECTS.find((x) => x.instance === projMatch[1] && x.path === projMatch[2]);
    if (!proj) throw new DemoError(404, "Ce projet n'existe pas dans la démo.");
    if (projMatch[3] === "/branches") return ["main", "develop", "feat/securite", "fix/dependances"].map((name, i) => ({ name, default: i === 0, protected: i < 2, committed_at: iso(NOW - i * 2 * DAY) }));
    if (projMatch[3] === "/branch-scores") {
      const last = proj.history.at(-1);
      if (!last) return [];
      return [["main", 0], ["develop", 6], ["feat/securite", 14], ["release/2.3", -9]].map(([branch, delta], i) => {
        const score = Math.max(0, Math.min(100, (last.score ?? 0) + (delta as number)));
        return { branch, last_id: last.id + i, last_status: "succeeded", last_at: iso(NOW - i * DAY), run_id: last.id, score, coverage: last.coverage, finished_at: iso(NOW - i * DAY), commit_sha: last.commit_sha };
      });
    }
    if (projMatch[3] === "/runs") return { items: [...proj.history].reverse(), next_cursor: null };
    if (projMatch[3] === "/roadmap") return roadmap(proj);
    const last = proj.history.at(-1);
    return { ...row(proj), statuses: proj.statuses, can_launch: false, active_run: null, dt: dtBricksOf(proj),
      last_run: last && { id: last.id, commit_sha: last.commit_sha, finished_at: last.finished_at, results: proj.results, reused_from: null } };
  }
  if (p === "/scope") return CHECKS.map((c) => ({ target: "check", target_id: c.id, decision: "retained",
    reason: null, level: "défaut", inherited: false, author: null, updated_at: null }));
  throw new DemoError(404, "Indisponible dans la démo.");
}

export async function demoApi<T>(path: string, init: RequestInit = {}): Promise<T> {
  await new Promise((r) => setTimeout(r, 120)); // the feel of a network round trip
  try {
    return route(path, (init.method ?? "GET").toUpperCase()) as T;
  } catch (e) {
    if (e instanceof DemoError) {
      const { ApiError } = await import("../api");
      throw new ApiError(e.status, e.message);
    }
    throw e;
  }
}
