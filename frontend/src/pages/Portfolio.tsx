// Dashboard of a scope in three tabs: Inventaire (the projects, by environment), Mesure (the figures), Analyse (the work to do).
// Tab, environment and filters live in the URL so a link can be shared.
import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, DEMO, DtWork, ProjectRow, Summary } from "../api";
import GroupNav, { ScopeCrumbs, useScopeData } from "../components/GroupNav";
import { Help } from "../components/Help";
import { ENVS, EnvFilter, ExportBar, HeatmapCard, scopeQuery, TrendCard } from "../components/Pilot";
import Radar from "../components/Radar";
import { PracticeCell, PracticeCounts, Score, Skeleton, when } from "../components/status";
import { dimension, practice } from "../labels";
import { FAMILIES, FamilyIcon, familySlot } from "../components/Dsomm";

type Sort = "name" | "score" | "last_run";
// What moves at a low maturity: the level-1 foundation, the trend, and what is not measured at all.
// "Below target" says nothing when nearly every project is below it.
const FILTERS = [
  ["foundation_missing", "true", "Socle niveau 1 incomplet"],
  ["trend", "up", "En progrès sur 30 jours"],
  ["trend", "down", "En recul sur 30 jours"],
  ["unmeasured", "true", "Non mesurés"],
] as const;
const TABS = [["inventaire", "Inventaire"], ["mesure", "Mesure"], ["analyse", "Analyse"]] as const;
type Tab = (typeof TABS)[number][0];

export default function Portfolio() {
  const [params, setParams] = useSearchParams();
  const sort = (params.get("sort") as Sort) ?? "name";
  const query = new URLSearchParams(params);
  query.delete("onglet");
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


  const instance = params.get("instance") ?? undefined, namespace = params.get("namespace") ?? undefined, env = params.get("env") ?? undefined;
  const scopeQs = scopeQuery(instance, namespace, env);
  const summary = useQuery({ queryKey: ["projects-summary", scopeQs], queryFn: () => api<Summary>(`/projects/summary?${scopeQs}`), staleTime: 30_000, placeholderData: keepPreviousData });
  const dt = useQuery({ queryKey: ["dt-work", scopeQs], queryFn: () => api<DtWork>(`/dt/work?${scopeQs}`), staleTime: 60_000 }).data;
  const { instances } = useScopeData();
  const inst = instances.find((i) => i.slug === instance);
  const title = namespace ? namespace.split("/").at(-1)! : inst?.name ?? instance ?? "Tableau de bord";
  const gitlabUrl = inst && `${inst.url.replace(/\/$/, "")}/${namespace ?? ""}`;
  const s = summary.data;
  const on = (key: string, value: string) => params.get(key) === value;
  const tab: Tab = TABS.find(([k]) => k === params.get("onglet"))?.[0] ?? "inventaire";
  // A tab's URL; from a figure, with the one filter that lists the projects behind it.
  const tabUrl = (key: Tab, filter?: Record<string, string>) => {
    const next = new URLSearchParams(params);
    if (key === "inventaire") next.delete("onglet"); else next.set("onglet", key);
    if (filter) {
      for (const [k] of FILTERS) next.delete(k);
      for (const [k, v] of Object.entries(filter)) next.set(k, v);
    }
    return `?${next}`;
  };
  const tile = (to: string, tone: string, figure: string, label: string, sub: string) => (
    <Link to={to} className={`kpi kpi-${tone}`}>
      <span className="kpi-value">{figure}</span>
      <span className="kpi-label">{label}<span className="kpi-sub">{sub}</span></span>
    </Link>
  );
  const nothing = s?.total === 0 && <p className="empty">{env ? "Aucun projet dans cet environnement." : "Aucun projet dans votre périmètre. Vous voyez les projets dont vous êtes membre dans GitLab."}</p>;

  const mesure = (
    <>
      <div className="kpis" aria-label="Chiffres clés" role="group">
        <div className="kpi kpi-score">
          <Score score={s?.score ?? null} coverage={s?.coverage ?? null} size="lg" />
          <span className="kpi-label">Score moyen <Help term="score" label="le score" /><br />{s ? `${s.analysed} projet${s.analysed > 1 ? "s" : ""} analysé${s.analysed > 1 ? "s" : ""} sur ${s.total}` : "…"}</span>
        </div>
        {tile(tabUrl("inventaire", { foundation_missing: "true" }), "pass", s ? `${s.foundation_ok}` : "—", "Socle niveau 1 en place",
          s ? `sur ${s.analysed} analysés · ${s.analysed - s.foundation_ok} à compléter` : "")}
        {tile(tabUrl("inventaire", { trend: "up" }), "accent", s?.compared ? `${s.improving}` : "—", "En progrès sur 30 jours",
          s?.compared ? `${s.declining} en recul · ${s.compared} comparables` : "historique de moins de 30 jours")}
        {tile(tabUrl("analyse"), "fail", s?.practices ? `${Math.round(s.practices.missing)}` : "—", "Pratiques absentes par projet",
          s?.practices ? `en moyenne, sur ${Math.round(s.practices.counted)} attendues` : "aucun projet analysé")}
        {tile(tabUrl("inventaire", { unmeasured: "true" }), "unknown", s ? `${s.unmeasured}` : "—", "Non mesurés",
          s ? `${s.never} jamais analysés · ${s.failed} en échec` : "")}
      </div>
      {nothing}
      {s && s.total > 0 && (
        <div className="dash">
          <section className="card wide" aria-labelledby="dims-title">
            <h2 id="dims-title">Profil DSOMM du périmètre</h2>
            <p className="card-sub">Score moyen de vos projets dans chaque dimension du référentiel</p>
            <div className="wide-body">
              <Radar title="Score moyen par dimension" axes={Object.keys(s.dimensions).sort()} series={[{ label: "Moyenne du périmètre", values: s.dimensions, tone: "main" }]} />
              <ul className="dim-list">
                {Object.entries(s.dimensions).sort().map(([d, v]) => (
                  <li key={d} className={`fam-${familySlot(d)}`}>
                    <FamilyIcon dim={d} size={32} />
                    <span className="gap-name" title={d}>{dimension(d)}</span>
                    <span className="gap-bar" aria-hidden="true"><span style={{ width: `${v}%` }} /></span>
                    <span className="gap-pct">{Math.round(v)}</span>
                  </li>
                ))}
              </ul>
            </div>
          </section>
          {s.practices && (
            <section className="card practices-card" aria-labelledby="practices-title">
              <h2 id="practices-title">Ce que veut dire le score moyen</h2>
              <p className="card-sub">Pratiques attendues jusqu'au niveau cible, en moyenne par projet analysé</p>
              <PracticeCounts p={s.practices} />
            </section>
          )}
          <Distribution s={s} />
          <TrendCard instance={instance} namespace={namespace} env={env} />
          <div className="heat-area"><HeatmapCard instance={instance} namespace={namespace} env={env} instances={instances} /></div>
        </div>
      )}
    </>
  );

  const overdue = Object.values(s?.vulns?.overdue ?? {}).reduce((a, b) => a + b, 0);
  // The work a lead has to hand out, most urgent first; a line appears only when there is something behind it.
  const work = (!s ? [] : [
    [overdue, "Vulnérabilités hors délai", "Ouvertes depuis plus longtemps que le délai de leur réponse SSVC", `/vulnerabilites?${scopeQs}`],
    [s.vulns?.by_response.immediate ?? 0, "Vulnérabilités à traiter en Immédiat", "Exploitées ou très probablement exploitées, en prod : 7 jours", `/vulnerabilites?${scopeQs}`],
    [dt?.no_sbom?.length ?? 0, "Déployées sans SBOM", "Briques qui tournent sans SBOM dans Dependency-Track : leur zéro CVE ne prouve rien", "/vulnerabilites?vue=versions"],
    [dt?.by_tag?.length ?? 0, "Déployées par tag", "Briques déployées par tag et non par digest : l'image peut changer sans que le SBOM suive", "/vulnerabilites?vue=versions"],
    [dt?.expired_exceptions ?? 0, "Exceptions expirées", "Risques acceptés dont l'échéance est passée : à revoir avec le référent et le RSSI", `/vulnerabilites?vue=exceptions&${scopeQs}`],
    [dt?.stale_sources?.length ?? 0, "Sources de CVE pas à jour", `Plus de 2 jours sans mise à jour (${dt?.stale_sources?.map((x) => x.name).join(", ")}) : les nouvelles CVE ne sont plus signalées`, `/vulnerabilites?${scopeQs}`],
    [s.analysed - s.foundation_ok, "Socle niveau 1 incomplet", "Projets où une pratique de base manque encore : à traiter en premier", tabUrl("inventaire", { foundation_missing: "true" })],
    [s.declining, "En recul sur 30 jours", "Projets dont le score a baissé depuis un mois", tabUrl("inventaire", { trend: "down" })],
    [s.unmeasured, "Non mesurés", "Projets jamais analysés ou dont la dernière analyse a échoué : leur maturité est inconnue", tabUrl("inventaire", { unmeasured: "true" })],
    [dt?.no_purl?.length ?? 0, "Composants sans purl", "Briques dont des composants n'ont pas de purl : DT ne les rapproche d'aucune CVE (souvent internes, à vérifier)", "/vulnerabilites?vue=versions"],
    [env ? 0 : s.envs.none, "Sans environnement", "Projets sans topic prod, test ou dev : l'ajouter dans GitLab pour les classer", tabUrl("inventaire", { env: "none" })],
  ] as [number, string, string, string][]).filter(([n]) => n > 0);
  const analyse = nothing || (s && (
    <div className="dash analyse">
      <section className="card work" aria-labelledby="work-title">
        <h2 id="work-title">Travail à faire</h2>
        <p className="card-sub">Ce qui demande une action dans ce périmètre, le plus urgent d'abord. Chaque ligne ouvre la liste concernée.</p>
        {work.length === 0 ? <p className="trend-ok">Rien à signaler.</p> : (
          <ul className="work-list">
            {work.map(([n, label, sub, to]) => (
              <li key={label}><Link to={to}><strong>{n}</strong><span>{label}<span className="kpi-sub muted">{sub}</span></span><span aria-hidden="true">›</span></Link></li>
            ))}
          </ul>
        )}
      </section>
      <Gaps gaps={s.gaps} />
      {s.lowest.length > 0 && <section className="card watch" aria-labelledby="watch-title">
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
      </section>}
    </div>
  ));

  const inventaire = (
    <section className="my-projects" aria-labelledby="my-projects-title">
      <h2 id="my-projects-title">{s && s.envs.total <= 15 ? "Mes projets" : "Tous les projets du périmètre"} <span className="muted small">{s ? s.total : ""}</span></h2>
      {env === "none" && <p className="muted small">Ces projets ne portent aucun des topics <span className="mono">prod</span>, <span className="mono">test</span> ou <span className="mono">dev</span>. Ajoutez-en un dans GitLab (Paramètres › Général › Topics) : le projet est classé à la synchronisation suivante.</p>}
      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="search">
          <span className="sr-only">Rechercher un projet</span>
          <input type="search" placeholder="Rechercher un projet" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        {FILTERS.map(([key, value, label]) => (
          <label key={`${key}=${value}`} className="chip">
            <input type="checkbox" checked={on(key, value)} onChange={(e) => set(key, e.target.checked ? value : null)} />
            {label}
          </label>
        ))}
      </form>

      {projects.isError && <p className="error" role="alert">{(projects.error as Error).message}</p>}
      {projects.isLoading && <Skeleton lines={6} label="Chargement des projets…" />}
      {projects.isSuccess && rows.length === 0 && (
        <p className="empty">{env && env !== "none"
          ? `Aucun projet ne correspond avec le topic « ${env} ». Les topics GitLab sont relus à chaque synchronisation.`
          : "Aucun projet dans votre périmètre ne correspond. Vous voyez les projets dont vous êtes membre dans GitLab."}</p>
      )}

      {rows.length > 0 && <div className="table" role="table" aria-label="Projets" aria-rowcount={rows.length + 1}>
        <div role="rowgroup">
          <div role="row" className="row head">
            {sortHeader("name", "Projet")}
            <div role="columnheader">Environnement</div>
            {sortHeader("score", "Score")}
            <div role="columnheader">Pratiques</div>
            {sortHeader("last_run", "Dernière réussite")}
            <div role="columnheader">État</div>
          </div>
        </div>
        <div role="rowgroup" ref={scroller} className="scroller">
          <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
            {items.map((v) => {
              const p = rows[v.index];
              const envs = ENVS.filter(([k]) => p.topics.includes(k));
              return (
                <div role="row" key={p.id} className={`row band-${p.score == null ? "none" : p.score >= 75 ? "high" : p.score >= 50 ? "mid" : "low"}`} aria-rowindex={v.index + 2} ref={virtual.measureElement} data-index={v.index}
                  style={{ position: "absolute", top: 0, transform: `translateY(${v.start}px)`, width: "100%" }}>
                  <div role="cell" className="name">
                    <Link to={`/p/${p.instance}/${p.path}`}>{p.path.split("/").at(-1)}</Link>
                    <span className="muted small" title={p.path}>{instances.find((i) => i.slug === p.instance)?.name ?? p.instance} · {p.namespace_path}</span>
                  </div>
                  <div role="cell" className="envs">{envs.length ? envs.map(([k, label]) => <span key={k} className={`badge env-${k}`}>{label}</span>) : <span className="muted small">Non classé</span>}</div>
                  <div role="cell"><Score score={p.score} coverage={p.coverage} /></div>
                  <div role="cell"><PracticeCell p={p.practices} /></div>
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
        <ExportBar instance={instance} namespace={namespace} env={env} />
      </div>
      <div className="tab-bar">
        <div role="tablist" aria-label="Vues du tableau de bord" className="tabs">
          {TABS.map(([key, label], i) => (
            <button key={key} role="tab" id={`tab-${key}`} aria-selected={tab === key} aria-controls={`panel-${key}`} tabIndex={tab === key ? 0 : -1}
              onClick={() => set("onglet", key === "inventaire" ? null : key)}
              onKeyDown={(e) => {
                const next = { ArrowRight: (i + 1) % TABS.length, ArrowLeft: (i + TABS.length - 1) % TABS.length, Home: 0, End: TABS.length - 1 }[e.key];
                if (next === undefined) return;
                e.preventDefault();
                set("onglet", next ? TABS[next][0] : null);
                document.getElementById(`tab-${TABS[next][0]}`)?.focus();
              }}>
              {label}
            </button>
          ))}
        </div>
        <EnvFilter counts={s?.envs} />
      </div>
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === "mesure" ? mesure : tab === "analyse" ? analyse : inventaire}
      </div>
    </section>
    </div>
  );
}

/** Where the projects stand: one stacked bar with every band named and counted, never colour alone. */
/** Every absent practice of the scope, most widespread first, with its DSOMM family; one family at a time on demand. */
export function Gaps({ gaps }: { gaps: Summary["gaps"] }) {
  const [family, setFamily] = useState<string | null>(null);
  const count = (d: string) => gaps.filter((g) => g.dimension === d).length;
  const shown = family ? gaps.filter((g) => g.dimension === family) : gaps;
  return (
    <section className="card gaps" aria-labelledby="gaps-title">
      <h2 id="gaps-title">Pratiques absentes <span className="muted small">{gaps.length}</span></h2>
      <p className="card-sub">Toutes les pratiques qui manquent dans ce périmètre, les plus répandues d'abord : part des projets mesurés où la pratique est absente ou seulement partielle, jusqu'à leur niveau cible</p>
      {gaps.length === 0 ? <p className="muted">Aucune pratique manquante.</p> : (
        <>
          <div className="fam-filter" role="group" aria-label="Famille DSOMM">
            <button type="button" aria-pressed={!family} onClick={() => setFamily(null)}>Toutes <span className="sf-count">{gaps.length}</span></button>
            {FAMILIES.filter(count).map((d) => (
              <button key={d} type="button" aria-pressed={family === d} onClick={() => setFamily(family === d ? null : d)}>
                <FamilyIcon dim={d} size={22} />{dimension(d)} <span className="sf-count">{count(d)}</span>
              </button>
            ))}
          </div>
          <ul className="gap-list fam-gaps">
            {shown.map((g) => {
              const pct = Math.round((100 * g.missing) / Math.max(1, g.measured));
              return (
                <li key={g.activity} className={`fam-${familySlot(g.dimension)}`}>
                  <FamilyIcon dim={g.dimension} />
                  <span className="gap-body">
                    <span className="gap-name" title={g.activity}>{practice(g.activity)}</span>
                    <span className="gap-meta"><span className="gap-level" title={`Niveau DSOMM ${g.level}`}>N{g.level}</span>{dimension(g.dimension)}</span>
                    <span className="gap-bar" role="img" aria-label={`${pct} % des projets mesurés`}><span style={{ width: `${pct}%` }} /></span>
                    <span className="muted small">{g.missing} projet{g.missing > 1 ? "s" : ""} sur {g.measured}</span>
                  </span>
                  <span className="gap-pct">{pct}<small> %</small></span>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}

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
