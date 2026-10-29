// Client of the Periskope API: same origin, Bearer token from Keycloak, RFC 7807 errors turned into messages.
import { userManager } from "./auth";

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
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

// GitLab paths keep their slashes: each segment is encoded on its own.
export const projectUrl = (instance: string, path: string) => `/projects/${encodeURIComponent(instance)}/${path.split("/").map(encodeURIComponent).join("/")}`;

export type CheckStatus = "pass" | "fail" | "unknown" | "not_applicable";
export type ActivityStatus = "implemented" | "partial" | "not_implemented" | "unknown" | "not_applicable" | "out_of_scope";

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
}

export interface CheckResult {
  status: CheckStatus;
  message: string;
  action?: string;
  reused?: boolean;
}

export interface Project extends ProjectRow {
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
  kind: "proof" | "hint" | "secondary";
  scope: { decision: "retained" | "excluded"; reason: string } | null;
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
