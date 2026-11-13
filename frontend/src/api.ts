// Client of the Periskope API: same origin, Bearer token from Keycloak, RFC 7807 errors turned into messages.
import { userManager } from "./auth";

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message);
  }
}

export const DEMO = import.meta.env.VITE_DEMO === "1";

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  // Demo build: a fictitious estate answered in the browser, no server and no sign-in.
  if (DEMO) return (await import("./demo/api")).demoApi<T>(path, init);
  // init.signal lets TanStack Query abort a request whose answer nobody waits for any more.
  const user = await (await userManager()).getUser();
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(user ? { Authorization: `Bearer ${user.access_token}` } : {}), ...init.headers },
  });
  if (res.status === 401) {
    await (await userManager()).signinRedirect({ state: location.pathname + location.search });
  }
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new ApiError(res.status, body?.detail ?? `Erreur ${res.status}`, body);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

/** Saves an API file (CSV) through the authenticated fetch: a plain link would not carry the token. */
export async function download(path: string): Promise<void> {
  if (DEMO) throw new ApiError(403, "Les exports sont désactivés dans la démo.");
  const user = await (await userManager()).getUser();
  const res = await fetch(`/api/v1${path}`, { headers: user ? { Authorization: `Bearer ${user.access_token}` } : {} });
  if (!res.ok) throw new ApiError(res.status, `Erreur ${res.status}`);
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") ?? "")?.[1] ?? "periskope.csv";
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export interface Trend {
  months: { month: string; score: number; projects: number }[];
  declining: { instance: string; path: string; score: number; before: number; since: string }[];
}
export interface Heatmap { dimensions: string[]; rows: { key: string; projects: number; cells: Record<string, number> }[] }

// GitLab paths keep their slashes: each segment is encoded on its own.
export const projectUrl = (instance: string, path: string) => `/projects/${encodeURIComponent(instance)}/${path.split("/").map(encodeURIComponent).join("/")}`;

export type CheckStatus = "pass" | "fail" | "unknown" | "not_applicable";
export type ActivityStatus = "implemented" | "partial" | "not_implemented" | "unknown" | "not_applicable" | "out_of_scope";

export interface Instance { slug: string; name: string; url: string; enterprise: boolean; last_sync_at: string | null }
export interface Group { instance: string; path: string; projects: number; analysed: number; score_sum: number }

export interface Vulns { critical: number; high: number; medium: number; low: number; info: number; unknown: number }

/** SSVC response (D14): it sets the correction deadline (Immédiat, Hors cycle, Planifié; Différé has none). */
export type Response = "immediate" | "out_of_cycle" | "scheduled" | "deferred";
export interface VulnItem { key: string; cve: boolean; title: string; severity: keyof Vulns; projects: number; detected_at: string | null; overdue: number; priority: keyof Vulns; response: Response; kev: boolean; epss: number | null; percentile: number | null }
// envs, trees, components: where Dependency-Track finds it (type dependency_track).
export interface VulnProject { instance: string; path: string; score: number | null; coverage: number | null; severity: keyof Vulns; type: string; detected_at: string | null; overdue: boolean; priority: keyof Vulns; response: Response; kev: boolean; epss: number | null; envs?: string[] | null; trees?: string[] | null; components?: string[] | null }
/** A project's open vulnerabilities, counted by priority, past their deadline and exploited (KEV). */
export interface VulnByProject { instance: string; path: string; score: number | null; coverage: number | null; total: number; overdue: number; kev: number; by_priority: Partial<Record<keyof Vulns, number>>; by_response: Partial<Record<Response, number>> }
/** Correction deadlines in hours by SSVC response (Différé has none). */
export type Sla = Partial<Record<Response, number>>;
/** One analysed branch of a project: its latest run and its latest successful score. */
export interface BranchScore { branch: string; last_id: number; last_status: Run["status"]; last_at: string; run_id: number | null; score: number | null; coverage: number | null; finished_at: string | null; commit_sha: string | null }

/** The practices behind a score, up to the target level: done, partial, missing (absent), not verified, and how many are expected. */
export interface Practices { done: number; partial: number; missing: number; unknown: number; counted: number }
/** Whether a project's vulnerability count can be trusted: it reports some, it publishes an SBOM and has none, it has no SBOM (zero means nothing), or it is not measured. */
export type VulnCoverage = "reporting" | "clean" | "blind" | "unmeasured";

export interface Summary { total: number; analysed: number; score: number | null; coverage: number | null; below_target: number; failed: number; never: number; high: number; mid: number; low: number; dimensions: Record<string, number>;
  gaps: { activity: string; level: number; missing: number; measured: number }[];
  lowest: { instance: string; path: string; score: number; coverage: number; last_success_at: string | null }[];
  // Projects with every level-1 practice in place; compared with their score 30 days ago (compared: those with such a history); never analysed or last analysis failed.
  foundation_ok: number; improving: number; declining: number; compared: number; unmeasured: number;
  // Averages per analysed project; null before any analysis.
  practices: (Practices & { projects: number }) | null;
  vuln_coverage: Record<VulnCoverage, number>;
  // null: no project of the scope measured (GitLab without Ultimate).
  vulns: (Vulns & { total: number; projects: number; exposed: { instance: string; path: string; vulns: Vulns }[]; sla_hours: Sla; overdue: Sla;
    by_response: Record<Response, number>; by_priority: Partial<Record<keyof Vulns, number>>; dated: number; kev: number }) | null;
  feeds: Record<"kev" | "epss", Feed>;
  // Every CVE source and its last completed update: KEV and EPSS (Periskope), NVD, GitHub, OSV (Dependency-Track).
  sources: Source[];
  // Projects of the scope per environment, whatever ?env= asks: a project is counted under each topic it carries.
  envs: Record<Env | "total", number> }
export interface Source { name: string; completed_at: string | null; error: string | null; via: "periskope" | "dependency-track" }
/** A Dependency-Track brick of a project: the version running in a tree (environment or delivered version). */
export interface DtBrick { tree: string; env: string | null; uuid: string; version: string | null; sbom: boolean; by_tag: boolean; components: number | null; no_purl: number | null }
export interface DtTree { uuid: string; name: string; env: string | null; active: boolean; synced_at: string; bricks: number; no_sbom: number; open: number; immediate: number }
export interface DtTreeBrick { uuid: string; name: string; version: string | null; active: boolean; sbom: boolean; by_tag: boolean; components: number | null; no_purl: number | null; instance: string | null; path: string | null }
export interface DtFinding { key: string; cve: boolean; title: string | null; severity: keyof Vulns; response: Response; kev: boolean; epss: number | null; where: string[] }
export interface DtVersion { tree: Omit<DtTree, "bricks" | "no_sbom" | "open" | "immediate">; bricks: DtTreeBrick[]; findings: DtFinding[] }
export interface DtCompare { a: DtVersion["tree"]; b: DtVersion["tree"]; bricks: { name: string; a: string | null; b: string | null }[]; only_a: DtFinding[]; only_b: DtFinding[]; both: DtFinding[] }
/** Where a CVE stands, version by version, for its follow-up sheet. Status: open, not concerned (VEX), exception, resolved. */
export interface DtPlace { tree_uuid: string; tree: string; env: string | null; tree_active: boolean; brick: string; version: string | null; active: boolean; instance: string | null; path: string | null;
  component_name: string | null; component_version: string | null; title: string | null; severity: keyof Vulns; vector: string | null; kev: boolean; epss: number | null;
  state: string | null; analysis_response: string | null; justification: string | null; detail: string | null; analysed_at: string | null; expires_on: string | null; attributed_at: string | null;
  status: "open" | "not_concerned" | "exception" | "resolved"; response: Response }
export interface CveSheet { key: string; places: DtPlace[]; fixed_in: { tree: string; env: string | null; tree_active: boolean; brick: string; version: string | null; active: boolean }[];
  ledger: { instance: string; path: string; opened_at: string; closed_at: string | null; priority: string | null; response: Response | null; deadline_at: string | null }[] }
export interface DtException { key: string; title: string | null; severity: keyof Vulns; kind: "exception" | "not_concerned"; state: string | null; justification: string | null; response: string | null;
  detail: string | null; analysed_at: string | null; expires_on: string | null; expired: boolean | null; brick: string; version: string | null; tree: string; instance: string | null; path: string | null }
type DtBrickRef = { uuid: string; name: string; version: string | null; components: number | null; no_purl: number | null; tree: string; instance: string | null; path: string | null };
/** What Dependency-Track says needs doing in the scope (null fields when DT is not configured). */
export interface DtWork { configured: boolean; synced_at?: string | null; no_sbom?: DtBrickRef[]; by_tag?: DtBrickRef[]; no_purl?: DtBrickRef[]; expired_exceptions?: number; stale_sources?: { name: string; completed_at: string | null; via: string }[] }
/** The five indicators for management (D11), month by month from the ledger, and today's SBOM coverage and exceptions. */
export interface Indicators { months: { month: string; critical_fixed: number; critical_on_time: number; days: Partial<Record<keyof Vulns, number | null>>; overdue_stock: number }[];
  sbom: { bricks: number; with_sbom: number } | null; exceptions: { active: number; expired: number } | null }
/** An exploitation feed read from the internal mirror: configured or not, last good read, last error. */
export interface Feed { configured: boolean; fetched_at?: string | null; rows?: number | null; published?: string | null; error?: string | null }

/** A project's environment is the GitLab topic prod, test or dev it carries; none: it carries none of them. */
export type Env = "prod" | "test" | "dev" | "none";

export interface ProjectRow {
  id: number;
  instance: string;
  path: string;
  namespace_path: string;
  default_branch: string | null;
  target_level: number;
  score: number | null;
  coverage: number | null;
  by_dimension: Record<string, number | null> | null;
  last_success_at: string | null;
  last_error: string | null;
  last_run_id: number | null;
  last_status: string | null;
  vulns: Vulns | null;
  practices: Practices | null;
  vuln_coverage: VulnCoverage;
  // GitLab topics, lower-cased.
  topics: string[];
}

export interface CheckResult {
  status: CheckStatus;
  message: string;
  action?: string;
  reused?: boolean;
}

export interface Project extends ProjectRow {
  // Dependency-Track bricks of the project, one per tree where it runs; null without DT.
  dt?: DtBrick[] | null;
  can_launch: boolean;
  active_run: number | null;
  statuses: Record<string, { status: ActivityStatus; to_confirm: boolean }> | null;
  last_run?: { id: number; commit_sha: string; finished_at: string; results: Record<string, CheckResult>; reused_from: number | null };
}

export interface Run {
  id: number;
  branch: string;
  commit_sha: string | null;
  trigger: string;
  requested_by: string | null;
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  created_at: string;
  finished_at: string | null;
  error: string | null;
  score: number | null;
  coverage: number | null;
}

export interface Check {
  id: string;
  title: string;
  source: string;
  activity: string;
  level: number;
  kind: "proof" | "hint";
  scope: { decision: "retained" | "excluded"; reason: string } | null;
  fix: Fix | null;
}

export interface Fix {
  steps: string[];
  snippet?: { file: string; lang: string; code: string };
  docs: { title: string; url: string }[];
  tier?: string;
}

export interface Activity {
  uuid: string;
  name: string;
  dimension: string;
  subdimension: string;
  level: number;
  usefulness: number;
}

export interface Branch {
  name: string;
  default: boolean;
  protected: boolean;
  committed_at: string;
}

export interface RunDetail extends Run {
  instance: string;
  path: string;
  default_branch: string;
  results: Record<string, CheckResult> | null;
}

interface DiffRow {
  check: string;
  before: CheckStatus;
  after: CheckStatus;
  before_message: string;
  after_message: string;
}

export interface Diff {
  before: Pick<Run, "id" | "branch" | "commit_sha" | "finished_at" | "score" | "coverage">;
  after: Pick<Run, "id" | "branch" | "commit_sha" | "finished_at" | "score" | "coverage">;
  gained: DiffRow[];
  lost: DiffRow[];
  changed: DiffRow[];
}

export interface RoadmapItem {
  activity: string;
  dimension: string;
  level: number;
  status: ActivityStatus;
  blocked_by: string[];
  steps: { check: string; action: string | null; message: string }[];
}

export interface ScopeRow {
  target: "check" | "activity";
  target_id: string;
  decision: "retained" | "excluded";
  reason: string | null;
  level: "organisation" | "instance" | "projet" | "défaut";
  inherited: boolean;
  author: string | null;
  updated_at: string | null;
}

export interface Me {
  sub: string;
  username: string;
  admin: boolean;
}
