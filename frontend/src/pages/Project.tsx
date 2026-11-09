// Project page: score and coverage first, the launch button for maintainers, then activities, checks, to-do and history.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Activity, ActivityStatus, api, ApiError, Branch, BranchScore, DEMO, Check, CheckResult, Project as P, projectUrl, RoadmapItem, Run, Summary } from "../api";
import BranchPicker from "../components/BranchPicker";
import ScoreChart from "../components/ScoreChart";
import FixGuide from "../components/FixGuide";
import FixIt, { type FixOffer } from "../components/FixIt";
import GroupNav, { ScopeCrumbs, useScopeData } from "../components/GroupNav";
import { Help } from "../components/Help";
import Radar from "../components/Radar";
import { compareBy, SortTh, StatusFilter, useSort } from "../components/TableTools";
import { ActivityBadge, CheckBadge, PracticeCounts, RUN_LABEL, Score, Skeleton, TRIGGER, when } from "../components/status";
import { NOT_MEASURED, total, VulnBar } from "../components/Vulns";
import { ScopeEditor } from "./Scope";
import { dimension as dimLabel, practice } from "../labels";

const TABS = [
  ["activites", "Activités"],
  ["preuves", "Preuves"],
  ["a-faire", "À faire"],
  ["vulnerabilites", "Vulnérabilités"],
  ["branches", "Branches"],
  ["historique", "Historique"],
  ["cadrage", "Cadrage"],
] as const;
type Tab = (typeof TABS)[number][0];
const SOURCE: Record<string, string> = { "API projet": "GitLab", "Dépôt": "Dépôt", SonarQube: "SonarQube" };
const ACTIVE = ["queued", "running"];
// Most urgent first when sorting by state.
const SEVERITY: ActivityStatus[] = ["not_implemented", "partial", "unknown", "implemented", "not_applicable", "out_of_scope"];
type ActFilter = "all" | "todo" | "unknown" | "done";
const ACT_FILTER: Record<ActFilter, ActivityStatus[]> = {
  all: SEVERITY, todo: ["not_implemented", "partial"], unknown: ["unknown"], done: ["implemented"],
};
type CheckFilter = "all" | "fail" | "unknown" | "pass" | "other";
const CHECK_ORDER: CheckFilter[] = ["fail", "unknown", "pass", "other"];

export default function Project() {
  const { instance = "", "*": path = "" } = useParams();
  const url = projectUrl(instance, path);
  const client = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [branch, setBranch] = useState<string | null>(null);
  const [branchInvalid, setBranchInvalid] = useState(false);

  const project = useQuery({ queryKey: ["project", url], queryFn: () => api<P>(url) });
  const scope = useScopeData();
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
    onSettled: () => { client.invalidateQueries({ queryKey: ["project", url] }); client.invalidateQueries({ queryKey: ["branch-scores", url] }); },
  });

  if (project.isError) {
    const e = project.error as ApiError;
    return <p className="error" role="alert">{e.status === 404 ? "Ce projet n'existe pas ou n'est pas dans votre périmètre." : e.message}</p>;
  }
  if (!project.data) return <Skeleton lines={6} label="Chargement du projet…" />;
  const p = project.data;
  const gitlab = scope.instances.find((i) => i.slug === p.instance);
  // The score in words: what is counted up to the target level, what is in place, what could not be checked.
  const counted = (activities.data?.items ?? []).filter((a) => a.level <= p.target_level && !["not_applicable", "out_of_scope"].includes(p.statuses?.[a.name]?.status ?? "unknown"));
  const n = (st: ActivityStatus) => counted.filter((a) => (p.statuses?.[a.name]?.status ?? "unknown") === st).length;
  const counts = p.last_run && counted.length
    ? { counted: counted.length, done: n("implemented"), partial: n("partial"), missing: n("not_implemented"), unknown: n("unknown") } : null;
  const tabs = TABS.filter(([key]) => key !== "cadrage" || p.can_launch);
  const asked = params.get("vue") as Tab | null;
  const tab: Tab = tabs.some(([k]) => k === asked) ? asked! : "activites";
  const selectTab = (key: Tab) => setParams((prev) => { const n = new URLSearchParams(prev); n.set("vue", key); return n; }, { replace: true });
  const results = p.last_run?.results ?? {};
  const running = !!activeStatus && ACTIVE.includes(activeStatus);
  const onBranch = branch && branch !== p.default_branch ? branch : null;

  return (
    <div className="with-nav">
    <GroupNav instance={p.instance} namespace={p.namespace_path} />
    <article aria-labelledby="project-title" className="dash-main">
      <ScopeCrumbs instance={p.instance} namespace={p.namespace_path} instances={scope.instances} />
      <header className="project-head">
        <div>
          <div className="title-row">
            <h1 id="project-title" tabIndex={-1}>{p.path.split("/").at(-1)}</h1>
            {gitlab && !DEMO && <a className="gitlab-link" href={`${gitlab.url.replace(/\/$/, "")}/${p.path}`} target="_blank" rel="noreferrer">Ouvrir dans GitLab ↗<span className="sr-only"> (nouvel onglet)</span></a>}
          </div>
          <p className="muted">
            <span className="mono">{p.path}</span>{gitlab && <> sur {gitlab.name}</>} · branche de référence <code>{p.default_branch}</code> · niveau cible {p.target_level}
            {p.last_run && <> · analysé le {when(p.last_run.finished_at)} sur <code>{p.last_run.commit_sha.slice(0, 8)}</code></>}
          </p>
        </div>
        <div className="head-score">
          <Score score={p.score} coverage={p.coverage} size="lg" />
          {counts && <PracticeCounts p={counts} onMissing={() => selectTab("a-faire")} />}
          <span className="muted small">Comment lire ces chiffres <Help term="chiffres" label="le score et la couverture" /></span>
        </div>
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
      {p.last_error && <p className="banner">Dernière analyse impossible : {p.last_error}. Le score affiché reste celui de la dernière analyse réussie.</p>}

      {p.last_run && <NextSteps project={p} url={url} activities={activities.data?.items ?? []} checks={checks.data ?? []} onAll={() => selectTab("a-faire")} />}

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
        ) : tab === "branches" ? (
          <Branches url={url} project={p} busy={launch.isPending} onLaunch={(b) => launch.mutate(b === p.default_branch ? null : b)} />
        ) : !p.last_run && tab !== "historique" ? (
          <p className="empty">Ce projet n'a pas encore été analysé.</p>
        ) : tab === "activites" ? (
          <>
          <p className="panel-intro">Les pratiques DevSecOps attendues <Help term="activite" label="une pratique" /> et leur état <Help term="statuts" label="les statuts" />, rangées par dimension.</p>
          <Activities project={p} checks={checks.data ?? []} activities={activities.data?.items ?? []} />
          </>
        ) : tab === "preuves" ? (
          <>
          <p className="panel-intro">Chaque contrôle automatique <Help term="preuve" label="une preuve" />, ce qu'il a constaté et, s'il échoue, comment le corriger.</p>
          <Checks results={results} checks={checks.data ?? []} url={url} instance={p.instance} />
          </>
        ) : tab === "vulnerabilites" ? (
          <section className="card vulns vulns-project" aria-labelledby="vulns-title">
            <h2 id="vulns-title">Vulnérabilités ouvertes {p.vulns && <span className="muted">{total(p.vulns)}</span>}</h2>
            {p.vulns ? <VulnBar v={p.vulns} /> : <p className="muted">{NOT_MEASURED}</p>}
            {results["gitlab.sbom_artifact"]?.status === "fail" && <p className="banner">Aucun SBOM CycloneDX publié par le pipeline : GitLab ne peut pas rapprocher les dépendances des CVE, un zéro ici ne prouve rien.</p>}
            {p.vulns && gitlab && !DEMO && <a href={`${gitlab.url.replace(/\/$/, "")}/${p.path}/-/security/vulnerability_report`} target="_blank" rel="noreferrer">Voir le détail dans GitLab ↗<span className="sr-only"> (nouvel onglet)</span></a>}
          </section>
        ) : tab === "a-faire" ? (
          <>
          <p className="panel-intro">Le plan pour atteindre le niveau cible <Help term="cible" label="le niveau cible" />, dans l'ordre : niveaux bas et prérequis d'abord.</p>
          <Todo url={url} targetLevel={p.target_level} checks={checks.data ?? []} />
          </>
        ) : (
          <History url={url} defaultBranch={p.default_branch} />
        )}
      </section>
    </article>
    </div>
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
  const summary = useQuery({ queryKey: ["projects-summary"], queryFn: () => api<Summary>("/projects/summary"), staleTime: 30_000 });
  const sorted = [...byDimension].sort();
  const anchor = (d: string) => `dim-${d.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  const [show, setShow] = useState<ActFilter>("all");
  const [inTarget, setInTarget] = useState(true);
  const { sort, toggle } = useSort<"name" | "level" | "status">({ key: "level", dir: "asc" });
  const statusOf = (a: Activity) => (project.statuses?.[a.name]?.status ?? "unknown") as ActivityStatus;
  const scoped = activities.filter((a) => !inTarget || a.level <= project.target_level);
  const count = (f: ActFilter) => scoped.filter((a) => ACT_FILTER[f].includes(statusOf(a))).length;
  const keep = (a: Activity) => (!inTarget || a.level <= project.target_level) && ACT_FILTER[show].includes(statusOf(a));
  const order = compareBy<Activity, "name" | "level" | "status">(sort, (a, k) => (k === "name" ? practice(a.name) : k === "level" ? a.level : SEVERITY.indexOf(statusOf(a))),
    (a, b) => a.level - b.level || a.name.localeCompare(b.name));
  return (
    <>
      <div className="overview">
        <Radar title="Profil DSOMM" axes={sorted.map(([d]) => d)} series={[
          { label: "Ce projet", values: project.by_dimension ?? {}, tone: "main" },
          ...(summary.data ? [{ label: "Moyenne de votre périmètre", values: summary.data.dimensions, tone: "ref" as const }] : []),
        ]} />
        <nav className="bento" aria-label="Dimensions DSOMM">
          {sorted.map(([dimension, list]) => (
            <a key={dimension} href={`#${anchor(dimension)}`} className="dim-card">
              <Score score={project.by_dimension?.[dimension] ?? null} coverage={coverage(list)} size="lg" />
              <span className="dim-name" title={dimension}>{dimLabel(dimension)}</span>
            </a>
          ))}
        </nav>
      </div>
      <div className="table-tools">
        <StatusFilter label="Filtrer les pratiques par état" value={show} onChange={setShow} options={[
          { value: "all", label: "Toutes", count: count("all") },
          { value: "todo", label: "À mettre en place", count: count("todo"), tone: "fail" },
          { value: "unknown", label: "Indéterminées", count: count("unknown"), tone: "unknown" },
          { value: "done", label: "En place", count: count("done"), tone: "pass" },
        ]} />
        <label className="chip"><input type="checkbox" checked={inTarget} onChange={(e) => setInTarget(e.target.checked)} />
          Jusqu'au niveau cible {project.target_level} seulement</label>
      </div>
      {sorted.filter(([, list]) => list.some(keep)).length === 0 && <p className="empty">Aucune pratique ne correspond à ce filtre.</p>}
      {sorted.filter(([, list]) => list.some(keep)).map(([dimension, list]) => {
        const s = project.by_dimension?.[dimension];
        return (
          <section key={dimension} className="group" id={anchor(dimension)}>
            <h2 title={dimension}>{dimLabel(dimension)} <span className="muted small">{s != null ? `${Math.round(s)}/100 · ${coverage(list) === 100 ? "tout vérifié" : `vérifiée à ${coverage(list)} %`}` : "rien de mesuré"}</span></h2>
            <div className="table-scroll">
              <table className="t-fixed t-acts">
                <thead><tr>
                  <SortTh k="name" label="Pratique DSOMM" sort={sort} onSort={toggle} />
                  <SortTh k="level" label="Niveau" sort={sort} onSort={toggle} className="num" />
                  <SortTh k="status" label="État" sort={sort} onSort={toggle} />
                  <th scope="col">Preuves</th>
                </tr></thead>
                <tbody>
                  {list.filter(keep).sort(order).map((a) => {
                    const st = project.statuses?.[a.name];
                    const mine = checks.filter((c) => c.activity === a.name);
                    return (
                      <tr key={a.name}>
                        <td className="cell-main" title={a.name}>{practice(a.name)}</td>
                        <td className="num">{a.level}</td>
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

function Checks({ results, checks, url, instance }: { results: Record<string, CheckResult>; checks: Check[]; url: string; instance: string }) {
  const offer = useQuery({ queryKey: ["fixes", url], queryFn: () => api<FixOffer>(`${url}/fixes`) });
  const fixable = new Map((offer.data?.can_fix ? offer.data.items : []).map((i) => [i.check, i]));
  const [show, setShow] = useState<CheckFilter>("all");
  const { sort, toggle } = useSort<"title" | "status">({ key: "status", dir: "asc" });
  const stateOf = (c: Check): CheckFilter => (c.scope?.decision === "excluded" ? "other" : !results[c.id] ? "other"
    : ({ fail: "fail", unknown: "unknown", pass: "pass", not_applicable: "other" } as const)[results[c.id].status]);
  const count = (f: CheckFilter) => checks.filter((c) => f === "all" || stateOf(c) === f).length;
  const order = compareBy<Check, "title" | "status">(sort, (c, k) => (k === "title" ? c.title : CHECK_ORDER.indexOf(stateOf(c))), (a, b) => a.title.localeCompare(b.title, "fr"));
  const bySource = new Map<string, Check[]>();
  for (const c of checks.filter((c) => show === "all" || stateOf(c) === show)) bySource.set(c.source, [...(bySource.get(c.source) ?? []), c]);
  return (
    <>
      <div className="table-tools">
        <StatusFilter label="Filtrer les preuves par résultat" value={show} onChange={setShow} options={[
          { value: "all", label: "Toutes", count: count("all") },
          { value: "fail", label: "À corriger", count: count("fail"), tone: "fail" },
          { value: "unknown", label: "Indéterminées", count: count("unknown"), tone: "unknown" },
          { value: "pass", label: "Validées", count: count("pass"), tone: "pass" },
          { value: "other", label: "Sans objet ou écartées", count: count("other") },
        ]} />
      </div>
      {bySource.size === 0 && <p className="empty">Aucune preuve ne correspond à ce filtre.</p>}
      {[...bySource].map(([source, list]) => (
        <section key={source} className="group">
          <h2>{SOURCE[source] ?? source} <span className="muted small">{list.length} preuve{list.length > 1 ? "s" : ""}</span></h2>
          <div className="table-scroll">
            <table className="t-fixed t-checks">
              <thead><tr>
                <SortTh k="title" label="Preuve" sort={sort} onSort={toggle} />
                <SortTh k="status" label="Résultat" sort={sort} onSort={toggle} />
                <th scope="col">Constat</th>
              </tr></thead>
              <tbody>
                {list.sort(order).map((c) => {
                  const r = results[c.id];
                  return (
                    <tr key={c.id}>
                      <td title={c.id} className="cell-main">{c.title}{c.kind === "hint" && <span className="muted small"> · indice, à confirmer</span>}</td>
                      <td>{c.scope?.decision === "excluded" ? <span className="badge tone-not_applicable" title={c.scope.reason}>Écartée</span> : r ? <CheckBadge status={r.status} /> : <span className="muted">Non collectée</span>}</td>
                      <td>{c.scope?.decision === "excluded" ? <span className="muted">{c.scope.reason}</span> : r?.message}{r?.reused && <span className="muted small"> (inchangé depuis l'analyse précédente)</span>}
                        {c.scope?.decision !== "excluded" && r && r.status !== "pass" && r.status !== "not_applicable" && <>
                          {fixable.has(c.id) && <FixIt url={url} instance={instance} check={c.id} kind={fixable.get(c.id)!.kind} />}
                          <FixGuide fix={c.fix} /></>}</td>
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

function Todo({ url, targetLevel, checks }: { url: string; targetLevel: number; checks: Check[] }) {
  const fixes = Object.fromEntries(checks.map((c) => [c.id, c.fix]));
  const items = useQuery({ queryKey: ["roadmap", url], queryFn: () => api<RoadmapItem[]>(`${url}/roadmap`) });
  if (items.isError) return <p className="error" role="alert">{(items.error as Error).message}</p>;
  if (!items.data) return <Skeleton />;
  if (!items.data.length) return <p className="empty">Rien à faire jusqu'au niveau cible {targetLevel}.</p>;
  return (
    <ol className="todo">
      {items.data.map((a) => (
        <li key={a.activity}>
          <h2><span title={a.activity}>{practice(a.activity)}</span> <span className="muted small">niveau {a.level}{a.status === "partial" ? " · partielle" : ""}</span></h2>
          {a.blocked_by.length > 0 && <p className="muted small">Prérequis : {a.blocked_by.map(practice).join(", ")}</p>}
          <ul>
            {a.steps.map((s) => <li key={s.check}>{s.action ?? s.message}{s.action && <><br /><span className="muted small">Constat : {s.message}</span></>}<FixGuide fix={fixes[s.check]} /></li>)}
          </ul>
        </li>
      ))}
    </ol>
  );
}

/** Every branch of the repository with its latest analysis: compare a branch with the reference and analyse it again in one click. */
function Branches({ url, project, busy, onLaunch }: { url: string; project: P; busy: boolean; onLaunch: (branch: string) => void }) {
  const gitlab = useQuery({ queryKey: ["branches", url], queryFn: () => api<Branch[]>(`${url}/branches`), staleTime: 60_000 });
  const scores = useQuery({ queryKey: ["branch-scores", url], queryFn: () => api<BranchScore[]>(`${url}/branch-scores`) });
  const [filter, setFilter] = useState("");
  if (scores.isError) return <p className="error" role="alert">{(scores.error as Error).message}</p>;
  if (!scores.data || gitlab.isLoading) return <Skeleton lines={4} label="Chargement des branches…" />;
  const byName = new Map(scores.data.map((b) => [b.branch, b]));
  const live = gitlab.data ?? [];
  // GitLab's branches first (reference on top), then analysed branches since deleted in GitLab.
  const names = [...live.map((b) => b.name), ...scores.data.map((b) => b.branch).filter((n) => !live.some((b) => b.name === n))];
  const ref = byName.get(project.default_branch ?? "")?.score ?? project.score;
  const shown = names.filter((n) => n.toLowerCase().includes(filter.toLowerCase()));
  return (
    <>
      <p className="panel-intro">Les branches du dépôt et la dernière analyse de chacune ; l'écart se lit par rapport à la branche de référence <code>{project.default_branch}</code>. Les analyses de branche sont gardées le temps réglé par l'administrateur.</p>
      {gitlab.isError && <p className="banner">Liste des branches GitLab indisponible pour le moment : seules les branches déjà analysées sont affichées.</p>}
      {names.length > 8 && (
        <label className="search branch-filter"><span className="sr-only">Filtrer les branches</span>
          <input type="search" placeholder="Filtrer les branches" value={filter} onChange={(e) => setFilter(e.target.value)} /></label>
      )}
      <div className="table-scroll">
        <table>
          <thead><tr><th scope="col">Branche</th><th scope="col">Dernier commit</th><th scope="col">Score</th><th scope="col">Écart</th><th scope="col">Dernière analyse</th>{project.can_launch && <th scope="col"><span className="sr-only">Action</span></th>}</tr></thead>
          <tbody>
            {shown.map((name) => {
              const g = live.find((b) => b.name === name), s = byName.get(name);
              const active = s && ACTIVE.includes(s.last_status);
              const delta = s?.score != null && ref != null && name !== project.default_branch ? Math.round(s.score - ref) : null;
              return (
                <tr key={name}>
                  <td><code>{name}</code>{g?.default && <span className="badge tone-not_applicable branch-tag">référence</span>}
                    {g?.protected && !g.default && <span className="badge tone-not_applicable branch-tag">protégée</span>}
                    {!g && gitlab.data && <span className="muted small"> · supprimée dans GitLab</span>}</td>
                  <td>{g ? when(g.committed_at) : "—"}</td>
                  <td>{s?.score != null ? <Link to={`/r/${s.run_id}`} aria-label={`Analyse de ${name}`}><Score score={s.score} coverage={s.coverage} /></Link> : <span className="muted small">jamais analysée</span>}</td>
                  <td>{delta == null ? "" : <span className={delta < 0 ? "t-fail" : delta > 0 ? "t-pass" : "muted"}>{delta > 0 ? "+" : ""}{delta}</span>}</td>
                  <td>{s ? <>{s.last_status === "succeeded" ? when(s.finished_at) : <span className={`badge ${active ? "tone-running" : "tone-fail"}`}>{RUN_LABEL[s.last_status]}</span>}</> : "—"}</td>
                  {project.can_launch && <td>{g && <button type="button" className="secondary" disabled={busy || active} onClick={() => onLaunch(name)}>{active ? "En cours…" : "Analyser"}</button>}</td>}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function History({ url, defaultBranch }: { url: string; defaultBranch: string | null }) {
  const runs = useQuery({ queryKey: ["runs", url], queryFn: () => api<{ items: Run[] }>(`${url}/runs`) });
  if (runs.isError) return <p className="error" role="alert">{(runs.error as Error).message}</p>;
  if (!runs.data) return <Skeleton />;
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

/** The first thing a visitor needs: where the project stands, in one sentence, and the next three things to do. */
function NextSteps({ project, url, activities, checks, onAll }: { project: P; url: string; activities: Activity[]; checks: Check[]; onAll: () => void }) {
  const items = useQuery({ queryKey: ["roadmap", url], queryFn: () => api<RoadmapItem[]>(`${url}/roadmap`) });
  const count = (st: ActivityStatus) => activities.filter((a) => a.level <= project.target_level && project.statuses?.[a.name]?.status === st).length;
  const [done, partial, missing, unknown] = (["implemented", "partial", "not_implemented", "unknown"] as const).map(count);
  const fixes = Object.fromEntries(checks.map((c) => [c.id, c.fix]));
  const next = (items.data ?? []).slice(0, 3);
  return (
    <section className="next" aria-labelledby="next-title">
      <div className="next-summary">
        <h2 id="next-title">Par où commencer</h2>
        <p>
          Jusqu'au niveau cible {project.target_level} <Help term="cible" label="le niveau cible" />, ce projet a <strong className="t-pass">{done} pratique{done > 1 ? "s" : ""} en place</strong>,{" "}
          <strong className="t-amber">{partial} partielle{partial > 1 ? "s" : ""}</strong> et <strong className="t-fail">{missing} absente{missing > 1 ? "s" : ""}</strong>.
          {unknown > 0 && <> {unknown} pratique{unknown > 1 ? "s n'ont" : " n'a"} pas pu être vérifiée{unknown > 1 ? "s" : ""} <Help term="couverture" label="la couverture" />.</>}
        </p>
      </div>
      {items.data && (next.length === 0 ? <p className="t-pass"><strong>Niveau cible atteint : rien à faire.</strong></p> : (
        <ol className="next-steps">
          {next.map((a) => {
            const step = a.steps[0];
            return (
              <li key={a.activity}>
                <span className="next-what">{step?.action ?? a.activity}</span>
                <span className="muted small"> · <span title={a.activity}>{practice(a.activity)}</span>, niveau {a.level}</span>
                {step && <FixGuide fix={fixes[step.check]} />}
              </li>
            );
          })}
        </ol>
      ))}
      {(items.data?.length ?? 0) > 3 && <button type="button" className="link" onClick={onAll}>Voir tout le plan ({items.data!.length} pratiques)</button>}
    </section>
  );
}
