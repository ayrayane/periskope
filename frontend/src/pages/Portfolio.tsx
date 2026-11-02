// Portfolio: the projects in the viewer's scope, paged by the server, filters in the URL so a link can be shared.
import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, DEMO, ProjectRow, Summary } from "../api";
import GroupNav, { ScopeCrumbs, useScopeData } from "../components/GroupNav";
import { Help } from "../components/Help";
import { ExportBar, HeatmapCard, TrendCard } from "../components/Pilot";
import Radar from "../components/Radar";
import { Score, Skeleton, when } from "../components/status";
import { dimension, practice } from "../labels";

type Sort = "name" | "score" | "last_run";
const FILTERS = [
  ["below_target", "Niveau cible non atteint"],
  ["failed", "Analyse impossible"],
  ["never", "Jamais analysés"],
] as const;

export default function Portfolio() {
  const [params, setParams] = useSearchParams();
  const sort = (params.get("sort") as Sort) ?? "name";
  const query = new URLSearchParams(params);
  query.set("limit", "50");
  const projects = useInfiniteQuery({
    queryKey: ["projects", query.toString()],
    queryFn: ({ pageParam, signal }) => {
      const q = new URLSearchParams(query);
      if (pageParam) q.set("cursor", pageParam);
      return api<{ items: ProjectRow[]; next_cursor: string | null }>(`/projects?${q}`, { signal });
    },
    initialPageParam: "",
    getNextPageParam: (last) => last.next_cursor ?? undefined,
    // Coming back keeps the list for 30 s and refetches at most 10 pages, never the whole scroll history.
    staleTime: 30_000,
    maxPages: 10,
    placeholderData: keepPreviousData,
  });
  const rows = projects.data?.pages.flatMap((p) => p.items) ?? [];
  const scroller = useRef<HTMLDivElement>(null);
  // Rows wrap on a phone: each one is measured instead of assumed 56 px high.
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => scroller.current, estimateSize: () => 64, overscan: 10 });
  const [search, setSearch] = useState(params.get("q") ?? "");
  const items = virtual.getVirtualItems();
  const lastIndex = items.at(-1)?.index ?? 0;
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = projects;
  useEffect(() => {
    if (lastIndex >= rows.length - 5 && hasNextPage && !isFetchingNextPage) fetchNextPage();
  }, [lastIndex, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage]);

  // The search goes to the URL (and the API) 300 ms after the last keystroke, not on each one.
  useEffect(() => {
    const id = setTimeout(() => { if ((params.get("q") ?? "") !== search) set("q", search || null); }, 300);
    return () => clearTimeout(id);
  });
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };
  const sortHeader = (key: Sort, label: string) => (
    <div role="columnheader" aria-sort={sort === key ? (key === "name" ? "ascending" : "descending") : "none"}>
      <button type="button" className="sort" onClick={() => set("sort", key === "name" ? null : key)}>
        {label}
      </button>
    </div>
  );

  const instance = params.get("instance") ?? undefined, namespace = params.get("namespace") ?? undefined;
  const scopeQs = new URLSearchParams(Object.entries({ instance, namespace }).filter(([, v]) => v) as [string, string][]).toString();
  const summary = useQuery({ queryKey: ["projects-summary", scopeQs], queryFn: () => api<Summary>(`/projects/summary?${scopeQs}`), staleTime: 30_000, placeholderData: keepPreviousData });
  const { instances } = useScopeData();
  const inst = instances.find((i) => i.slug === instance);
  const title = namespace ? namespace.split("/").at(-1)! : inst?.name ?? instance ?? "Tableau de bord";
  const gitlabUrl = inst && `${inst.url.replace(/\/$/, "")}/${namespace ?? ""}`;
  const s = summary.data;
  const tile = (key: (typeof FILTERS)[number][0], tone: string, value?: number) => (
    <button type="button" className={`kpi kpi-${tone}`} aria-pressed={params.get(key) === "true"}
      onClick={() => set(key, params.get(key) === "true" ? null : "true")}>
      <span className="kpi-value">{value ?? "—"}</span>
      <span className="kpi-label">{FILTERS.find(([k]) => k === key)![1]}</span>
    </button>
  );

  // A team member with a handful of projects comes for those: the list goes first; a lead with many comes for the cards.
  const few = !!s && s.total <= 15;
  const cards = (
    <>
      {s && s.total > 0 && (
        <div className="dash">
          <section className="card watch" aria-labelledby="watch-title">
            <h2 id="watch-title">À surveiller</h2>
            <p className="card-sub">Les projets les plus loin de leur niveau cible</p>
            {s.lowest.map((p) => (
              <Link key={`${p.instance}/${p.path}`} to={`/p/${p.instance}/${p.path}`} className={`pastel band-${p.score >= 75 ? "high" : p.score >= 50 ? "mid" : "low"}`}>
                <span className="pastel-title">{p.path.split("/").at(-1)}</span>
                <span className="pastel-path">{p.path}</span>
                <span className="pastel-foot">
                  <span className="chip-date">{when(p.last_success_at)}</span>
                  <Score score={p.score} coverage={p.coverage} />
                </span>
              </Link>
            ))}
          </section>
          <section className="card wide" aria-labelledby="dims-title">
            <h2 id="dims-title">Profil DSOMM du périmètre</h2>
            <p className="card-sub">Score moyen de vos projets dans chaque dimension du référentiel</p>
            <div className="wide-body">
              <Radar title="Score moyen par dimension" axes={Object.keys(s.dimensions).sort()} series={[{ label: "Moyenne du périmètre", values: s.dimensions, tone: "main" }]} />
              <ul className="dim-list">
                {Object.entries(s.dimensions).sort().map(([d, v]) => (
                  <li key={d}>
                    <span className="gap-name" title={d}>{dimension(d)}</span>
                    <span className="gap-bar" aria-hidden="true"><span style={{ width: `${v}%` }} /></span>
                    <span className="gap-pct">{Math.round(v)}</span>
                  </li>
                ))}
              </ul>
            </div>
          </section>
          <section className="card gaps" aria-labelledby="gaps-title">
            <h2 id="gaps-title">Pratiques les plus absentes</h2>
            <p className="card-sub">Part des projets mesurés où la pratique est absente ou seulement partielle, jusqu'à leur niveau cible</p>
            {s.gaps.length === 0 ? <p className="muted">Aucune pratique manquante.</p> : (
              <ul className="gap-list">
                {s.gaps.map((g) => {
                  const pct = Math.round((100 * g.missing) / Math.max(1, g.measured));
                  return (
                    <li key={g.activity}>
                      <span className="gap-level" title={`Niveau ${g.level}`}>N{g.level}</span>
                      <span className="gap-body">
                        <span className="gap-name" title={g.activity}>{practice(g.activity)}</span>
                        <span className="gap-bar" aria-hidden="true"><span style={{ width: `${pct}%` }} /></span>
                        <span className="muted small">{g.missing} projet{g.missing > 1 ? "s" : ""} sur {g.measured}</span>
                      </span>
                      <span className="gap-pct">{pct} %</span>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>
          <Distribution s={s} />
          <TrendCard instance={instance} namespace={namespace} />
          <div className="heat-area"><HeatmapCard instance={instance} namespace={namespace} instances={instances} /></div>
        </div>
      )}
    </>
  );
  const myProjects = (
    <section className="my-projects" aria-labelledby="my-projects-title">
      <h2 id="my-projects-title">{few ? "Mes projets" : "Tous les projets du périmètre"} <span className="muted small">{s ? s.total : ""}</span></h2>
      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="search">
          <span className="sr-only">Rechercher un projet</span>
          <input type="search" placeholder="Rechercher un projet" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        {FILTERS.map(([key, label]) => (
          <label key={key} className="chip">
            <input type="checkbox" checked={params.get(key) === "true"} onChange={(e) => set(key, e.target.checked ? "true" : null)} />
            {label}
          </label>
        ))}
      </form>

      {projects.isError && <p className="error" role="alert">{(projects.error as Error).message}</p>}
      {projects.isLoading && <Skeleton lines={6} label="Chargement des projets…" />}
      {projects.isSuccess && rows.length === 0 && (
        <p className="empty">Aucun projet dans votre périmètre ne correspond. Vous voyez les projets dont vous êtes membre dans GitLab.</p>
      )}

      {rows.length > 0 && <div className="table" role="table" aria-label="Projets" aria-rowcount={rows.length + 1}>
        <div role="rowgroup">
          <div role="row" className="row head">
            {sortHeader("name", "Projet")}
            {sortHeader("score", "Score")}
            {sortHeader("last_run", "Dernière réussite")}
            <div role="columnheader">État</div>
          </div>
        </div>
        <div role="rowgroup" ref={scroller} className="scroller">
          <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
            {items.map((v) => {
              const p = rows[v.index];
              return (
                <div role="row" key={p.id} className={`row band-${p.score == null ? "none" : p.score >= 75 ? "high" : p.score >= 50 ? "mid" : "low"}`} aria-rowindex={v.index + 2} ref={virtual.measureElement} data-index={v.index}
                  style={{ position: "absolute", top: 0, transform: `translateY(${v.start}px)`, width: "100%" }}>
                  <div role="cell" className="name">
                    <Link to={`/p/${p.instance}/${p.path}`}>{p.path.split("/").at(-1)}</Link>
                    <span className="muted small">{instances.find((i) => i.slug === p.instance)?.name ?? p.instance} · {p.namespace_path}</span>
                  </div>
                  <div role="cell"><Score score={p.score} coverage={p.coverage} /></div>
                  <div role="cell" className="num-cell">{when(p.last_success_at)}</div>
                  <div role="cell">{p.last_error ? <span className="badge tone-not_applicable" title="L'analyse n'a pas pu lire ses sources ; le score affiché est celui de la dernière analyse réussie.">Analyse impossible : {p.last_error}</span> : p.last_status === "running" || p.last_status === "queued" ? <span className="badge tone-running">En cours</span> : p.score == null ? <span className="muted small">Jamais analysé</span> : <span className="muted small">À jour</span>}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>}
      <p className="page-status" role="status">{projects.isFetchingNextPage ? "Chargement de la suite…" : ""}</p>
    </section>
  );

  return (
    <div className="with-nav">
    <GroupNav instance={instance} namespace={namespace} />
    <section aria-labelledby="portfolio-title" className="dash-main">
      <div className="hero">
        <div>
          {instance && <ScopeCrumbs instance={instance} namespace={namespace?.split("/").slice(0, -1).join("/") || undefined} instances={instances} />}
          <div className="title-row">
            <h1 id="portfolio-title" tabIndex={-1}>{title}</h1>
            {gitlabUrl && !DEMO && <a className="gitlab-link" href={gitlabUrl} target="_blank" rel="noreferrer">Ouvrir dans GitLab ↗<span className="sr-only"> (nouvel onglet)</span></a>}
          </div>
          <p className="hero-sub">{instance
            ? <>{namespace ? `Groupe ${namespace} et ses sous-groupes` : `Tous les groupes de l'instance ${inst?.name ?? instance}`}{inst && <> · <span className="mono">{new URL(inst.url).host}</span></>}. Un score de 100 veut dire que le projet atteint son niveau cible <Help term="score" label="le score" />.</>
            : <>Toutes vos instances GitLab, analysées sur les pratiques DevSecOps (référentiel OWASP DSOMM). Choisissez une instance ou un groupe à gauche. Un score de 100 veut dire que le projet atteint son niveau cible <Help term="score" label="le score" />.</>}</p>
        </div>
        <ExportBar instance={instance} namespace={namespace} />
        <div className="kpis" aria-label="Chiffres clés" role="group">
          <div className="kpi kpi-score">
            <Score score={s?.score ?? null} coverage={s?.coverage ?? null} size="lg" />
            <span className="kpi-label">Score moyen <Help term="score" label="le score" /><br />{s ? `${s.analysed} projet${s.analysed > 1 ? "s" : ""} analysé${s.analysed > 1 ? "s" : ""} sur ${s.total}` : "…"}</span>
          </div>
          {tile("below_target", "amber", s?.below_target)}
          {tile("failed", "neutral", s?.failed)}
          {tile("never", "unknown", s?.never)}
        </div>
      </div>
      {few ? <>{myProjects}{cards}</> : <>{cards}{myProjects}</>}
    </section>
    </div>
  );
}

/** Where the projects stand: one stacked bar with every band named and counted, never colour alone. */
function Distribution({ s }: { s: Summary }) {
  const bands = [
    { key: "high", label: "75 et plus", n: s.high },
    { key: "mid", label: "50 à 74", n: s.mid },
    { key: "low", label: "Moins de 50", n: s.low },
    { key: "none", label: "Jamais analysés", n: s.never },
  ];
  return (
    <figure className="card distribution">
      <figcaption>Répartition des scores</figcaption>
      <div className="stack" role="img" aria-label={bands.map((b) => `${b.label} : ${b.n}`).join(", ")}>
        {bands.filter((b) => b.n > 0).map((b) => <span key={b.key} className={`seg seg-${b.key}`} style={{ flexGrow: b.n }} title={`${b.label} : ${b.n}`} />)}
      </div>
      <ul className="bands">
        {bands.map((b) => (
          <li key={b.key}><span className={`swatch seg-${b.key}`} aria-hidden="true" /><span>{b.label}</span><strong>{b.n}</strong>
            <span className="muted small">{s.total ? Math.round((100 * b.n) / s.total) : 0} %</span></li>
        ))}
      </ul>
    </figure>
  );
}
