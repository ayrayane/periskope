// Project page: score and coverage first, the launch button for maintainers, then activities, checks, to-do and history.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Activity, ActivityStatus, api, ApiError, Check, CheckResult, Project as P, projectUrl, Run } from "../api";
import { ActivityBadge, CheckBadge, Score, when } from "../components/status";

const TABS = [
  ["activities", "Activités"],
  ["checks", "Preuves"],
  ["todo", "À faire"],
  ["history", "Historique"],
] as const;
type Tab = (typeof TABS)[number][0];
const RUN_LABEL: Record<Run["status"], string> = {
  queued: "En file d'attente", running: "Analyse en cours", succeeded: "Terminée", failed: "Échec", cancelled: "Annulée",
};
const SOURCE: Record<string, string> = { "API projet": "GitLab", "Dépôt": "Dépôt", SonarQube: "SonarQube", Scorecard: "Scorecard" };

export default function Project() {
  const { instance = "", "*": path = "" } = useParams();
  const url = projectUrl(instance, path);
  const client = useQueryClient();
  const [tab, setTab] = useState<Tab>("activities");
  const [startedAt, setStartedAt] = useState<number | null>(null);

  const project = useQuery({ queryKey: ["project", url], queryFn: () => api<P>(url) });
  const checks = useQuery({ queryKey: ["checks"], queryFn: () => api<Check[]>("/checks"), staleTime: Infinity });
  const activities = useQuery({ queryKey: ["activities"], queryFn: () => api<{ items: Activity[] }>("/activities"), staleTime: Infinity });
  const activeId = project.data?.active_run;
  // Live state by polling: every 3 s, slowed to 10 s after 2 minutes.
  const active = useQuery({
    queryKey: ["run", activeId],
    queryFn: () => api<Run>(`/runs/${activeId}`),
    enabled: !!activeId,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      if (s && !["queued", "running"].includes(s)) {
        client.invalidateQueries({ queryKey: ["project", url] });
        return false;
      }
      return startedAt && Date.now() - startedAt > 120_000 ? 10_000 : 3_000;
    },
  });
  const launch = useMutation({
    mutationFn: () => api<{ id: number }>(`${url}/runs`, { method: "POST", body: "{}", headers: { "Idempotency-Key": crypto.randomUUID() } }),
    onSettled: () => {
      setStartedAt(Date.now());
      client.invalidateQueries({ queryKey: ["project", url] });
    },
  });

  if (project.isError) {
    const e = project.error as ApiError;
    return <p className="error" role="alert">{e.status === 404 ? "Ce projet n'existe pas ou n'est pas dans votre périmètre." : e.message}</p>;
  }
  if (!project.data) return <p className="page-status" role="status">Chargement…</p>;
  const p = project.data;
  const results = p.last_run?.results ?? {};
  const running = active.data && ["queued", "running"].includes(active.data.status);

  return (
    <article aria-labelledby="project-title">
      <nav className="crumbs" aria-label="Fil d'Ariane"><Link to="/">Portefeuille</Link> <span aria-hidden="true">/</span> {p.instance}</nav>
      <header className="project-head">
        <div>
          <h1 id="project-title">{p.path}</h1>
          <p className="muted">
            Branche de référence <code>{p.default_branch}</code> · niveau cible {p.target_level}
            {p.last_run && <> · analysé le {when(p.last_run.finished_at)} sur <code>{p.last_run.commit_sha.slice(0, 8)}</code></>}
          </p>
        </div>
        <Score score={p.score} coverage={p.coverage} size="lg" />
      </header>

      <div className="run-bar" aria-live="polite">
        {p.can_launch && (
          <button type="button" className="primary" disabled={launch.isPending || !!running} onClick={() => launch.mutate()}>
            {running ? "Analyse en cours…" : "Lancer une analyse"}
          </button>
        )}
        {active.data && <span className={`badge ${running ? "tone-unknown" : active.data.status === "failed" ? "tone-fail" : "tone-pass"}`}>{RUN_LABEL[active.data.status]}</span>}
        {launch.error && <span className="error">{(launch.error as Error).message}</span>}
        {p.last_error && <span className="error">Dernière analyse en échec : {p.last_error}. Le score affiché reste celui de la dernière analyse réussie.</span>}
      </div>

      <div role="tablist" aria-label="Vues du projet" className="tabs">
        {TABS.map(([key, label]) => (
          <button key={key} role="tab" id={`tab-${key}`} aria-selected={tab === key} aria-controls={`panel-${key}`} tabIndex={tab === key ? 0 : -1}
            onClick={() => setTab(key)}
            onKeyDown={(e) => {
              const i = TABS.findIndex(([k]) => k === tab);
              const next = e.key === "ArrowRight" ? (i + 1) % TABS.length : e.key === "ArrowLeft" ? (i + TABS.length - 1) % TABS.length : -1;
              if (next >= 0) {
                setTab(TABS[next][0]);
                document.getElementById(`tab-${TABS[next][0]}`)?.focus();
              }
            }}>
            {label}
          </button>
        ))}
      </div>
      <section role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} tabIndex={0}>
        {!p.last_run && tab !== "history" ? (
          <p className="empty">Ce projet n'a pas encore été analysé.</p>
        ) : tab === "activities" ? (
          <Activities project={p} checks={checks.data ?? []} activities={activities.data?.items ?? []} />
        ) : tab === "checks" ? (
          <Checks results={results} checks={checks.data ?? []} />
        ) : tab === "todo" ? (
          <Todo project={p} checks={checks.data ?? []} activities={activities.data?.items ?? []} />
        ) : (
          <History url={url} />
        )}
      </section>
    </article>
  );
}

function Activities({ project, checks, activities }: { project: P; checks: Check[]; activities: Activity[] }) {
  const byDimension = new Map<string, Activity[]>();
  for (const a of activities) byDimension.set(a.dimension, [...(byDimension.get(a.dimension) ?? []), a]);
  return (
    <>
      {[...byDimension].sort().map(([dimension, list]) => (
        <section key={dimension} className="group">
          <h2>{dimension} <span className="muted small">{project.by_dimension?.[dimension] != null ? `${Math.round(project.by_dimension[dimension]!)}/100` : ""}</span></h2>
          <table>
            <thead><tr><th scope="col">Activité DSOMM</th><th scope="col">Niv.</th><th scope="col">Statut</th><th scope="col">Preuves</th></tr></thead>
            <tbody>
              {list.sort((a, b) => a.level - b.level || a.name.localeCompare(b.name)).map((a) => {
                const s = project.statuses?.[a.name];
                return (
                  <tr key={a.name}>
                    <td lang="en">{a.name}</td>
                    <td>{a.level}</td>
                    <td>{s && <ActivityBadge status={s.status as ActivityStatus} toConfirm={s.to_confirm} />}</td>
                    <td className="small">{checks.filter((c) => c.activity === a.name).map((c) => c.id).join(", ")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ))}
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
          <table>
            <thead><tr><th scope="col">Preuve</th><th scope="col">Statut</th><th scope="col">Constat</th></tr></thead>
            <tbody>
              {list.map((c) => {
                const r = results[c.id];
                return (
                  <tr key={c.id}>
                    <td><span className="mono small">{c.id}</span><br />{c.title}{c.kind === "hint" && <span className="muted small"> · indice</span>}</td>
                    <td>{c.scope?.decision === "excluded" ? <span className="badge tone-not_applicable" title={c.scope.reason}>Écartée</span> : r ? <CheckBadge status={r.status} /> : <span className="muted">Non collectée</span>}</td>
                    <td>{c.scope?.decision === "excluded" ? <span className="muted">{c.scope.reason}</span> : r?.message}{r?.reused && <span className="muted small"> (reprise, commit inchangé)</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      ))}
    </>
  );
}

function Todo({ project, checks, activities }: { project: P; checks: Check[]; activities: Activity[] }) {
  const results = project.last_run?.results ?? {};
  const missing = activities
    .filter((a) => a.level <= project.target_level && ["not_implemented", "partial"].includes(project.statuses?.[a.name]?.status ?? ""))
    .sort((a, b) => a.level - b.level || b.usefulness - a.usefulness);
  if (!missing.length) return <p className="empty">Rien à faire jusqu'au niveau cible {project.target_level}.</p>;
  return (
    <ol className="todo">
      {missing.map((a) => (
        <li key={a.name}>
          <h2><span lang="en">{a.name}</span> <span className="muted small">niveau {a.level}</span></h2>
          <ul>
            {checks.filter((c) => c.activity === a.name && results[c.id]?.status === "fail").map((c) => (
              <li key={c.id}><strong>{results[c.id].action}</strong> <span className="muted small">— {results[c.id].message}</span></li>
            ))}
          </ul>
        </li>
      ))}
    </ol>
  );
}

function History({ url }: { url: string }) {
  const runs = useQuery({ queryKey: ["runs", url], queryFn: () => api<{ items: Run[] }>(`${url}/runs`) });
  if (!runs.data) return <p className="page-status" role="status">Chargement…</p>;
  return (
    <table>
      <thead><tr><th scope="col">Date</th><th scope="col">Déclencheur</th><th scope="col">Branche</th><th scope="col">Statut</th><th scope="col">Score</th></tr></thead>
      <tbody>
        {runs.data.items.map((r) => (
          <tr key={r.id}>
            <td>{when(r.created_at)}</td>
            <td>{{ user: `à la demande (${r.requested_by})`, webhook: "webhook", nightly: "revue nocturne", pipeline: "pipeline" }[r.trigger] ?? r.trigger}</td>
            <td><code>{r.branch}</code></td>
            <td>{RUN_LABEL[r.status]}{r.error && <span className="muted small"> — {r.error}</span>}</td>
            <td>{r.score != null ? `${Math.round(r.score)}/100 (${Math.round(r.coverage ?? 0)} %)` : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
