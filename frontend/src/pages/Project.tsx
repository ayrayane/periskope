// Project page: score and coverage first, the launch button for maintainers, then activities, checks, to-do and history.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Activity, ActivityStatus, api, ApiError, Check, CheckResult, Project as P, projectUrl, RoadmapItem, Run } from "../api";
import BranchPicker from "../components/BranchPicker";
import ScoreChart from "../components/ScoreChart";
import { ActivityBadge, CheckBadge, RUN_LABEL, Score, TRIGGER, when } from "../components/status";
import { ScopeEditor } from "./Scope";

const TABS = [
  ["activites", "Activités"],
  ["preuves", "Preuves"],
  ["a-faire", "À faire"],
  ["historique", "Historique"],
  ["cadrage", "Cadrage"],
] as const;
type Tab = (typeof TABS)[number][0];
const SOURCE: Record<string, string> = { "API projet": "GitLab", "Dépôt": "Dépôt", SonarQube: "SonarQube", Scorecard: "Scorecard" };
const ACTIVE = ["queued", "running"];

export default function Project() {
  const { instance = "", "*": path = "" } = useParams();
  const url = projectUrl(instance, path);
  const client = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [branch, setBranch] = useState<string | null>(null);
  const [branchInvalid, setBranchInvalid] = useState(false);

  const project = useQuery({ queryKey: ["project", url], queryFn: () => api<P>(url) });
  const checks = useQuery({ queryKey: ["checks"], queryFn: () => api<Check[]>("/checks"), staleTime: Infinity });
  const activities = useQuery({ queryKey: ["activities"], queryFn: () => api<{ items: Activity[] }>("/activities"), staleTime: Infinity });
  const activeId = project.data?.active_run;
  // Live state by polling: every 3 s, every 10 s once the run is two minutes old (wherever it was launched from).
  const active = useQuery({
    queryKey: ["run", activeId],
    queryFn: () => api<Run>(`/runs/${activeId}`),
    enabled: !!activeId,
    refetchInterval: (q) => {
      const run = q.state.data;
      if (run && !ACTIVE.includes(run.status)) return false;
      return run && Date.now() - Date.parse(run.created_at) > 120_000 ? 10_000 : 3_000;
    },
  });
  const activeStatus = active.data?.status;
  useEffect(() => {
    if (activeStatus && !ACTIVE.includes(activeStatus)) client.invalidateQueries({ queryKey: ["project", url] });
  }, [activeStatus, client, url]);
  const launch = useMutation({
    mutationFn: (b: string | null) =>
      api<{ id: number }>(`${url}/runs`, { method: "POST", body: JSON.stringify(b ? { branch: b } : {}), headers: { "Idempotency-Key": crypto.randomUUID() } }),
    onSuccess: (r, b) => {
      // A branch analysis is checked on its own page, next to the comparison with the reference.
      if (b) navigate(`/r/${r.id}`);
    },
    onSettled: () => client.invalidateQueries({ queryKey: ["project", url] }),
  });

  if (project.isError) {
    const e = project.error as ApiError;
    return <p className="error" role="alert">{e.status === 404 ? "Ce projet n'existe pas ou n'est pas dans votre périmètre." : e.message}</p>;
  }
  if (!project.data) return <p className="page-status" role="status">Chargement…</p>;
  const p = project.data;
  const tabs = TABS.filter(([key]) => key !== "cadrage" || p.can_launch);
  const asked = params.get("vue") as Tab | null;
  const tab: Tab = tabs.some(([k]) => k === asked) ? asked! : "activites";
  const selectTab = (key: Tab) => setParams((prev) => { const n = new URLSearchParams(prev); n.set("vue", key); return n; }, { replace: true });
  const results = p.last_run?.results ?? {};
  const running = !!activeStatus && ACTIVE.includes(activeStatus);
  const onBranch = branch && branch !== p.default_branch ? branch : null;

  return (
    <article aria-labelledby="project-title">
      <nav className="crumbs" aria-label="Fil d'Ariane"><Link to="/">Portefeuille</Link> <span aria-hidden="true">/</span> {p.instance}</nav>
      <header className="project-head">
        <div>
          <h1 id="project-title" tabIndex={-1}>{p.path}</h1>
          <p className="muted">
            Branche de référence <code>{p.default_branch}</code> · niveau cible {p.target_level}
            {p.last_run && <> · analysé le {when(p.last_run.finished_at)} sur <code>{p.last_run.commit_sha.slice(0, 8)}</code></>}
          </p>
        </div>
        <Score score={p.score} coverage={p.coverage} size="lg" />
      </header>

      <div className="run-bar">
        {p.can_launch && (
          <>
            <BranchPicker url={url} value={p.default_branch ?? ""} onChange={(b, invalid) => { setBranch(b); setBranchInvalid(invalid); }} />
            <button type="button" className="primary" disabled={launch.isPending || branchInvalid || (running && !onBranch)}
              onClick={() => launch.mutate(onBranch)}>
              {running && !onBranch ? "Analyse en cours…" : onBranch ? "Analyser la branche" : "Lancer une analyse"}
            </button>
          </>
        )}
        <span role="status">
          {active.data && <span className={`badge ${running ? "tone-running" : activeStatus === "failed" ? "tone-fail" : "tone-pass"}`}>{RUN_LABEL[active.data.status]}</span>}
        </span>
        {launch.error && <span className="error" role="alert">{(launch.error as Error).message}</span>}
      </div>
      {p.last_error && <p className="error">Dernière analyse en échec : {p.last_error}. Le score affiché reste celui de la dernière analyse réussie.</p>}

      <div role="tablist" aria-label="Vues du projet" className="tabs">
        {tabs.map(([key, label], i) => (
          <button key={key} role="tab" id={`tab-${key}`} aria-selected={tab === key} aria-controls={`panel-${key}`} tabIndex={tab === key ? 0 : -1}
            onClick={() => selectTab(key)}
            onKeyDown={(e) => {
              const next = { ArrowRight: (i + 1) % tabs.length, ArrowLeft: (i + tabs.length - 1) % tabs.length, Home: 0, End: tabs.length - 1 }[e.key];
              if (next === undefined) return;
              e.preventDefault();
              selectTab(tabs[next][0]);
              document.getElementById(`tab-${tabs[next][0]}`)?.focus();
            }}>
            {label}
          </button>
        ))}
      </div>
      <section role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} tabIndex={0}>
        {tab === "cadrage" ? (
          <ScopeEditor where={{ instance: p.instance, project: p.path }} canEdit={p.can_launch} />
        ) : !p.last_run && tab !== "historique" ? (
          <p className="empty">Ce projet n'a pas encore été analysé.</p>
        ) : tab === "activites" ? (
          <Activities project={p} checks={checks.data ?? []} activities={activities.data?.items ?? []} />
        ) : tab === "preuves" ? (
          <Checks results={results} checks={checks.data ?? []} />
        ) : tab === "a-faire" ? (
          <Todo url={url} targetLevel={p.target_level} />
        ) : (
          <History url={url} defaultBranch={p.default_branch} />
        )}
      </section>
    </article>
  );
}

function Activities({ project, checks, activities }: { project: P; checks: Check[]; activities: Activity[] }) {
  const byDimension = new Map<string, Activity[]>();
  for (const a of activities) byDimension.set(a.dimension, [...(byDimension.get(a.dimension) ?? []), a]);
  // A dimension's score goes with its coverage too: share of its counted activities actually measured.
  const coverage = (list: Activity[]) => {
    const counted = list.filter((a) => a.level <= project.target_level && !["not_applicable", "out_of_scope"].includes(project.statuses?.[a.name]?.status ?? ""));
    const measured = counted.filter((a) => project.statuses?.[a.name] && project.statuses[a.name].status !== "unknown");
    return counted.length ? Math.round((100 * measured.length) / counted.length) : 0;
  };
  return (
    <>
      {[...byDimension].sort().map(([dimension, list]) => {
        const s = project.by_dimension?.[dimension];
        return (
          <section key={dimension} className="group">
            <h2 lang="en">{dimension} <span className="muted small" lang="fr">{s != null ? `${Math.round(s)}/100 · couverture ${coverage(list)} %` : "rien de mesuré"}</span></h2>
            <div className="table-scroll">
              <table>
                <thead><tr><th scope="col">Activité DSOMM</th><th scope="col">Niv.</th><th scope="col">Statut</th><th scope="col">Preuves</th></tr></thead>
                <tbody>
                  {list.sort((a, b) => a.level - b.level || a.name.localeCompare(b.name)).map((a) => {
                    const st = project.statuses?.[a.name];
                    const mine = checks.filter((c) => c.activity === a.name);
                    return (
                      <tr key={a.name}>
                        <td lang="en">{a.name}</td>
                        <td>{a.level}</td>
                        <td>{st ? <ActivityBadge status={st.status as ActivityStatus} toConfirm={st.to_confirm} /> : <span className="muted">Non évaluée</span>}</td>
                        <td className="small">{mine.map((c) => c.title).join(" · ")}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
    </>
  );
}

function Checks({ results, checks }: { results: Record<string, CheckResult>; checks: Check[] }) {
  const bySource = new Map<string, Check[]>();
  for (const c of checks) bySource.set(c.source, [...(bySource.get(c.source) ?? []), c]);
  return (
    <>
      {[...bySource].map(([source, list]) => (
        <section key={source} className="group">
          <h2>{SOURCE[source] ?? source}</h2>
          <div className="table-scroll">
            <table>
              <thead><tr><th scope="col">Preuve</th><th scope="col">Statut</th><th scope="col">Constat</th></tr></thead>
              <tbody>
                {list.map((c) => {
                  const r = results[c.id];
                  return (
                    <tr key={c.id}>
                      <td>{c.title}{c.kind === "hint" && <span className="muted small"> · indice</span>}<br /><span className="mono small muted">{c.id}</span></td>
                      <td>{c.scope?.decision === "excluded" ? <span className="badge tone-not_applicable" title={c.scope.reason}>Écartée</span> : r ? <CheckBadge status={r.status} /> : <span className="muted">Non collectée</span>}</td>
                      <td>{c.scope?.decision === "excluded" ? <span className="muted">{c.scope.reason}</span> : r?.message}{r?.reused && <span className="muted small"> (reprise, rien n'a changé)</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </>
  );
}

function Todo({ url, targetLevel }: { url: string; targetLevel: number }) {
  const items = useQuery({ queryKey: ["roadmap", url], queryFn: () => api<RoadmapItem[]>(`${url}/roadmap`) });
  if (items.isError) return <p className="error" role="alert">{(items.error as Error).message}</p>;
  if (!items.data) return <p className="page-status" role="status">Chargement…</p>;
  if (!items.data.length) return <p className="empty">Rien à faire jusqu'au niveau cible {targetLevel}.</p>;
  return (
    <ol className="todo">
      {items.data.map((a) => (
        <li key={a.activity}>
          <h2><span lang="en">{a.activity}</span> <span className="muted small">niveau {a.level}{a.status === "partial" ? " · partielle" : ""}</span></h2>
          {a.blocked_by.length > 0 && <p className="muted small">Prérequis : <span lang="en">{a.blocked_by.join(", ")}</span></p>}
          <ul>
            {a.steps.map((s) => <li key={s.check}>{s.action ?? s.message}{s.action && <><br /><span className="muted small">Constat : {s.message}</span></>}</li>)}
          </ul>
        </li>
      ))}
    </ol>
  );
}

function History({ url, defaultBranch }: { url: string; defaultBranch: string | null }) {
  const runs = useQuery({ queryKey: ["runs", url], queryFn: () => api<{ items: Run[] }>(`${url}/runs`) });
  if (runs.isError) return <p className="error" role="alert">{(runs.error as Error).message}</p>;
  if (!runs.data) return <p className="page-status" role="status">Chargement…</p>;
  if (!runs.data.items.length) return <p className="empty">Aucune analyse pour l'instant.</p>;
  return (
    <>
      <ScoreChart runs={runs.data.items.filter((r) => r.branch === defaultBranch)} />
      <div className="table-scroll">
        <table>
          <thead><tr><th scope="col">Date</th><th scope="col">Déclencheur</th><th scope="col">Branche</th><th scope="col">Statut</th><th scope="col">Score</th></tr></thead>
          <tbody>
            {runs.data.items.map((r) => (
              <tr key={r.id}>
                <td><Link to={`/r/${r.id}`}>{when(r.created_at)}</Link></td>
                <td>{r.trigger === "user" ? `à la demande (${r.requested_by})` : TRIGGER[r.trigger] ?? r.trigger}</td>
                <td><code>{r.branch}</code></td>
                <td>{RUN_LABEL[r.status]}{r.error && <span className="muted small"> — {r.error}</span>}</td>
                <td>{r.score != null ? `${Math.round(r.score)}/100 · couverture ${Math.round(r.coverage ?? 0)} %` : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
