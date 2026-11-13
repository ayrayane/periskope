// Open vulnerabilities of the scope, by CVE (search one, see every project it touches) or by project (most impacted first).
import { keepPreviousData, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, DtWork, Feed, ProjectRow, Sla, Source, Summary, VulnByProject, VulnCoverage, VulnItem, VulnProject } from "../api";
import { Exceptions, Versions } from "../components/Dtrack";
import { useScopeData } from "../components/GroupNav";
import { EnvFilter, scopeQuery } from "../components/Pilot";
import { Score, Skeleton } from "../components/status";
import { Age, NOT_MEASURED, Priority, Response, RESPONSES, Severity, SevTag, span, urgent, VulnBar } from "../components/Vulns";

const SCANNER: Record<string, string> = {
  dependency_scanning: "Dépendances", container_scanning: "Image de conteneur", sast: "Code (SAST)", dast: "Application (DAST)",
  secret_detection: "Secrets", api_fuzzing: "Fuzzing d'API", coverage_fuzzing: "Fuzzing", cluster_image_scanning: "Cluster",
  dependency_track: "Dependency-Track",
};
const LEVELS: [Severity | "", string][] = [["", "Toutes les sévérités"], ["critical", "Critiques"], ["high", "Hautes"], ["medium", "Moyennes"], ["low", "Basses"]];

const COVERAGE: [VulnCoverage, string, string][] = [
  ["reporting", "Remontent des vulnérabilités", "Le rapport de vulnérabilités GitLab est alimenté."],
  ["clean", "SBOM publié, aucune vulnérabilité", "Le pipeline publie un SBOM CycloneDX et GitLab n'y trouve aucune CVE : un vrai zéro."],
  ["blind", "Sans SBOM CycloneDX", "Aucun SBOM dans les artefacts du pipeline : GitLab ne peut rien rapprocher des CVE, leur zéro ne prouve rien."],
  ["unmeasured", "Non mesurés", "Jamais analysés, artefacts illisibles ou GitLab sans licence Ultimate."],
];

export default function Vulnerabilities() {
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? undefined;
  const instance = get("instance"), namespace = get("namespace"), key = get("cve"), severity = get("severite") ?? "";
  const view = get("vue"), byProject = view === "projets", byCve = !view;
  const set = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };
  const [search, setSearch] = useState(get("q") ?? "");
  useEffect(() => {
    // Only a real change of the search: a no-op write 250 ms after load would undo a click made in between.
    const t = setTimeout(() => { if ((get("q") ?? "") !== search.trim()) set({ q: search.trim() || null }); }, 250);
    return () => clearTimeout(t);
  }, [search]);

  const scope = new URLSearchParams(scopeQuery(instance, namespace, get("env")));
  const listQs = new URLSearchParams(scope);
  if (get("q")) listQs.set("q", get("q")!);
  const list = useQuery({ queryKey: ["vulns", listQs.toString()], enabled: byCve, queryFn: () => api<{ measured: number; items: VulnItem[]; sla_hours: Sla }>(`/vulnerabilities?${listQs}`), placeholderData: keepPreviousData });
  const projects = useQuery({
    queryKey: ["vuln-projects", key, scope.toString()], enabled: !!key,
    queryFn: () => api<VulnProject[]>(`/vulnerabilities/projects?${new URLSearchParams({ ...Object.fromEntries(scope), key: key! })}`),
  });
  const summary = useQuery({ queryKey: ["projects-summary", scope.toString()], queryFn: () => api<Summary>(`/projects/summary?${scope}`), staleTime: 30_000, placeholderData: keepPreviousData });
  const bucket = get("couverture") as VulnCoverage | undefined;
  const inBucket = useQuery({
    queryKey: ["projects", "coverage", bucket, scope.toString()], enabled: !!bucket,
    queryFn: () => api<{ items: ProjectRow[]; next_cursor: string | null }>(`/projects?${new URLSearchParams({ ...Object.fromEntries(scope), vuln_coverage: bucket!, limit: "50" })}`),
  });
  const dt = useQuery({ queryKey: ["dt-work", scope.toString()], queryFn: () => api<DtWork>(`/dt/work?${scope}`), staleTime: 60_000 });
  const { instances } = useScopeData();
  const name = (slug: string) => instances.find((i) => i.slug === slug)?.name ?? slug;
  const items = (list.data?.items ?? []).filter((v) => !severity || v.severity === severity);
  const selected = list.data?.items.find((v) => v.key === key);

  return (
    <article className="vulns-page">
      <header className="page-head">
        <h1 tabIndex={-1}>Vulnérabilités</h1>
        <p className="muted">
          {namespace ? `Groupe ${namespace}` : instance ? name(instance) : "Toutes les instances GitLab"}
          {list.data && list.data.measured > 0 && <> · {list.data.measured} projet{list.data.measured > 1 ? "s" : ""} mesuré{list.data.measured > 1 ? "s" : ""}</>}
          {" "}· vulnérabilités ouvertes de la branche par défaut
        </p>
      </header>

      <div className="tab-bar">
      <div className="status-filter" role="group" aria-label="Regrouper par">
        <button type="button" aria-pressed={!byProject} onClick={() => { setSearch(""); set({ vue: null, q: null }); }}>Par CVE</button>
        <button type="button" aria-pressed={byProject} onClick={() => { setSearch(""); set({ vue: "projets", q: null, cve: null }); }}>Par projet</button>
        {dt.data?.configured && <>
          <button type="button" aria-pressed={view === "versions"} onClick={() => { setSearch(""); set({ vue: "versions", q: null, cve: null }); }}>Par version livrée</button>
          <button type="button" aria-pressed={view === "exceptions"} onClick={() => { setSearch(""); set({ vue: "exceptions", q: null, cve: null }); }}>Exceptions et VEX</button>
        </>}
      </div>
      <EnvFilter counts={summary.data?.envs} />
      </div>

      {view === "versions" && <Versions />}
      {view === "exceptions" && <Exceptions qs={scope} />}
      {(byCve || byProject) && <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="search">
          <span className="sr-only">{byProject ? "Rechercher un projet" : "Rechercher une CVE ou un titre"}</span>
          <input type="search" placeholder={byProject ? "Nom du projet" : "CVE ou titre"} value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label className="chip">
          <span className="sr-only">Instance GitLab</span>
          <select value={instance ?? ""} onChange={(e) => set({ instance: e.target.value || null, namespace: null, cve: null })}>
            <option value="">Toutes les instances</option>
            {instances.map((i) => <option key={i.slug} value={i.slug}>{i.name}</option>)}
          </select>
        </label>
        {namespace && <button type="button" className="chip" onClick={() => set({ namespace: null, cve: null })} aria-label={`Retirer le filtre groupe ${namespace}`}>Groupe {namespace} ✕</button>}
        {!byProject && <label className="chip">
          <span className="sr-only">Sévérité</span>
          <select value={severity} onChange={(e) => set({ severite: e.target.value || null })}>
            {LEVELS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
          </select>
        </label>}
      </form>}

      {(byCve || byProject) && summary.data && summary.data.total > 0 && <Coverage s={summary.data} bucket={bucket} onBucket={(b) => set({ couverture: b === bucket ? null : b })}
        projects={inBucket.data} loading={inBucket.isLoading} name={name} />}
      {(byCve || byProject) && summary.data?.vulns && (
        <section className="card vulns vulns-overview" aria-labelledby="overview-title">
          <h2 id="overview-title">Vulnérabilités ouvertes par sévérité</h2>
          <p className="card-sub">{dt.data?.configured ? "Dépendances et images d'après Dependency-Track, code, secrets et application (SAST, DAST) d'après GitLab, non corrigées ni écartées"
            : "CVE et autres failles détectées par les scanners de GitLab (dépendances, conteneurs, SAST, DAST), non corrigées ni écartées"}</p>
          <div className="vulns-body">
            <div>
              <VulnBar v={summary.data.vulns} />
              <Deadlines v={summary.data.vulns} feeds={summary.data.feeds} sources={summary.data.sources} />
            </div>
            <div>
              <h3 className="vulns-sub">Projets les plus exposés {!byProject && <button type="button" className="link small" onClick={() => set({ vue: "projets", q: null, cve: null })}>Tout voir</button>}</h3>
              {summary.data.vulns.exposed.length === 0 ? <p className="muted">Aucune vulnérabilité critique ou haute.</p> : (
                <ul className="exposed">
                  {summary.data.vulns.exposed.map((e) => (
                    <li key={`${e.instance}/${e.path}`}>
                      <Link to={`/p/${e.instance}/${e.path}?vue=vulnerabilites`}>{e.path.split("/").at(-1)}</Link>
                      <span className="muted small" title={e.path}>{e.path}</span>
                      <span className="badge tone-fail">{urgent(e.vulns)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </section>
      )}

      {byProject && <ByProject qs={listQs} sla={summary.data?.vulns?.sla_hours} name={name} />}
      {byCve && list.isError && <p className="error" role="alert">{(list.error as Error).message}</p>}
      {byCve && list.isLoading && <Skeleton lines={8} label="Chargement des vulnérabilités…" />}
      {byCve && list.data && list.data.measured === 0 && <p className="empty">{NOT_MEASURED}</p>}
      {byCve && list.data && list.data.measured > 0 && (
        <div className="vulns-split">
          <section className="card" aria-labelledby="vuln-list-title">
            <h2 id="vuln-list-title">{items.length}{items.length === 1000 ? "+" : ""} vulnérabilité{items.length > 1 ? "s" : ""}</h2>
            {items.length === 0 ? <p className="muted">Aucune vulnérabilité ouverte ne correspond.</p> : (
              <table className="vuln-table">
                <thead><tr><th scope="col">Identifiant</th><th scope="col">Sévérité</th><th scope="col">Priorité et réponse</th><th scope="col">Ouverte depuis</th><th scope="col" className="num">Projets</th></tr></thead>
                <tbody>
                  {items.map((v) => (
                    <tr key={v.key} aria-selected={v.key === key} className={v.key === key ? "selected" : undefined}>
                      <td>
                        <button type="button" className="link vuln-key" onClick={() => set({ cve: v.key })}>{v.cve ? v.key : v.title}</button>
                        {v.cve && <span className="muted small vuln-title">{v.title}</span>}
                      </td>
                      <td><SevTag s={v.severity} /></td>
                      <td><Priority p={v.priority} kev={v.kev} epss={v.epss} /> <Response r={v.response} /></td>
                      <td><Age since={v.detected_at} overdue={v.overdue > 0} deadline={list.data!.sla_hours[v.response]} />
                        {v.overdue > 0 && v.overdue < v.projects && <span className="muted small vuln-title">{v.overdue} projet{v.overdue > 1 ? "s" : ""} sur {v.projects}</span>}</td>
                      <td className="num">{v.projects}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="card vuln-detail" aria-labelledby="vuln-detail-title" aria-live="polite">
            {!key ? <p className="muted">Choisissez une vulnérabilité pour voir les projets touchés.</p> : (
              <>
                <h2 id="vuln-detail-title">{selected?.cve || !selected ? key : selected.title}</h2>
                {/* Hidden from the list by a search, the chosen CVE keeps its severity: the worst of its projects, which come first. */}
                {(selected || projects.data?.[0]) && <p className="vuln-meta"><span className="muted small">Sévérité</span> <SevTag s={selected?.severity ?? projects.data![0].severity} />
                  {selected && <><span className="muted small">Priorité</span> <Priority p={selected.priority} kev={selected.kev} epss={selected.epss} />
                    <span className="muted small">Réponse</span> <Response r={selected.response} /></>}{selected?.cve && <span>{selected.title}</span>}
                  <Link to={`/vulnerabilites/cve/${encodeURIComponent(key)}`}>Fiche de suivi</Link>
                  {key.startsWith("CVE-") && <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(key)}`} target="_blank" rel="noreferrer">Fiche NVD</a>}</p>}
                {projects.isLoading && <Skeleton lines={4} label="Chargement des projets…" />}
                {projects.data && (
                  <>
                    <h3 className="vulns-sub">{projects.data.length} projet{projects.data.length > 1 ? "s" : ""} touché{projects.data.length > 1 ? "s" : ""}</h3>
                    <table className="vuln-table">
                      <thead><tr><th scope="col">Projet</th><th scope="col">Détectée par</th><th scope="col">Réponse</th><th scope="col">Ouverte depuis</th><th scope="col">Score</th></tr></thead>
                      <tbody>
                        {projects.data.map((p) => (
                          <tr key={`${p.instance}/${p.path}`}>
                            <td><Link to={`/p/${p.instance}/${p.path}`}>{p.path}</Link><span className="muted small vuln-title">{name(p.instance)}</span></td>
                            <td>{SCANNER[p.type] ?? p.type}{p.trees && <span className="muted small vuln-title">{p.trees.join(", ")}{p.components?.length ? ` · ${p.components.join(", ")}` : ""}</span>}</td>
                            <td><Response r={p.response} /></td>
                            <td><Age since={p.detected_at} overdue={p.overdue} deadline={list.data?.sla_hours[p.response]} /></td>
                            <td><Score score={p.score} coverage={p.coverage} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </>
            )}
          </section>
        </div>
      )}
    </article>
  );
}

const PRIORITY_COLS: [keyof VulnByProject["by_priority"], string][] = [["critical", "Critique"], ["high", "Élevée"], ["medium", "Moyenne"], ["low", "Faible"]];

/** Projects with open vulnerabilities, most impacted first (by priority, then past deadline); more load while scrolling. */
function ByProject({ qs, sla, name }: { qs: URLSearchParams; sla?: Sla; name: (slug: string) => string }) {
  const pages = useInfiniteQuery({
    queryKey: ["vulns-by-project", qs.toString()],
    queryFn: ({ pageParam, signal }) => api<{ items: VulnByProject[]; next_offset: number | null }>(`/vulnerabilities/by-project?${new URLSearchParams({ ...Object.fromEntries(qs), offset: String(pageParam) })}`, { signal }),
    initialPageParam: 0,
    getNextPageParam: (last) => last.next_offset ?? undefined,
    placeholderData: keepPreviousData,
  });
  const rows = pages.data?.pages.flatMap((p) => p.items) ?? [];
  const end = useRef<HTMLDivElement>(null);
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = pages;
  useEffect(() => {
    if (!end.current || !hasNextPage) return;
    const seen = new IntersectionObserver(([e]) => { if (e.isIntersecting && !isFetchingNextPage) fetchNextPage(); }, { rootMargin: "200px" });
    seen.observe(end.current);
    return () => seen.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);
  if (pages.isError) return <p className="error" role="alert">{(pages.error as Error).message}</p>;
  if (pages.isLoading) return <Skeleton lines={8} label="Chargement des projets…" />;
  return (
    <section className="card" aria-labelledby="by-project-title">
      <h2 id="by-project-title">Projets touchés, les plus impactés d'abord</h2>
      <p className="card-sub">Vulnérabilités ouvertes par priorité (sévérité corrigée par KEV et EPSS) et à traiter en réponse Immédiat ;
        hors délai selon la réponse SSVC{sla ? ` (${RESPONSES.filter(([k]) => sla[k]).map(([k, l]) => `${l.toLowerCase()} ${span(sla[k]!)}`).join(", ")})` : ""}</p>
      {rows.length === 0 ? <p className="muted">Aucun projet avec une vulnérabilité ouverte.</p> : (
        <table className="vuln-table">
          <thead><tr><th scope="col">Projet</th>{PRIORITY_COLS.map(([k, l]) => <th key={k} scope="col" className="num">{l}</th>)}
            <th scope="col" className="num">Immédiat</th><th scope="col" className="num">Hors délai</th><th scope="col" className="num">Exploitées (KEV)</th><th scope="col" className="num">Total</th><th scope="col">Score</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.instance}/${r.path}`}>
                <td><Link to={`/p/${r.instance}/${r.path}?vue=vulnerabilites`}>{r.path}</Link><span className="muted small vuln-title">{name(r.instance)}</span></td>
                {PRIORITY_COLS.map(([k]) => <td key={k} className="num">{r.by_priority[k] ? <span className="sev-tag"><span className={`swatch sev-${k}`} aria-hidden="true" />{r.by_priority[k]}</span> : <span className="muted">0</span>}</td>)}
                <td className="num">{r.by_response?.immediate ? <span className="badge tone-fail">{r.by_response.immediate}</span> : 0}</td>
                <td className="num">{r.overdue ? <span className="badge tone-fail">{r.overdue}</span> : 0}</td>
                <td className="num">{r.kev || 0}</td>
                <td className="num">{r.total}</td>
                <td><Score score={r.score} coverage={r.coverage} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div ref={end} />
      {hasNextPage && <p><button type="button" className="link" disabled={isFetchingNextPage} onClick={() => fetchNextPage()}>{isFetchingNextPage ? "Chargement…" : "Afficher plus de projets"}</button></p>}
    </section>
  );
}

/** Can the vulnerability counts be trusted? Share of projects whose zero means something, and which ones are blind. */
function Coverage({ s, bucket, onBucket, projects, loading, name }: {
  s: Summary; bucket?: VulnCoverage; onBucket: (b: VulnCoverage) => void; loading: boolean;
  projects?: { items: ProjectRow[]; next_cursor: string | null }; name: (slug: string) => string;
}) {
  const c = s.vuln_coverage;
  const pct = s.total ? Math.round((100 * (c.reporting + c.clean)) / s.total) : 0;
  const label = COVERAGE.find(([k]) => k === bucket);
  return (
    <section className="card coverage" aria-labelledby="coverage-title">
      <h2 id="coverage-title">Couverture de l'analyse des vulnérabilités</h2>
      <p className="cov-head"><span className="cov-pct">{pct} %</span>
        <span>des projets ({c.reporting + c.clean} sur {s.total}) ont des vulnérabilités qui remontent ou un SBOM CycloneDX qui prouve qu'ils n'en ont pas.</span></p>
      <div className="stack" role="img" aria-label={COVERAGE.map(([k, l]) => `${l} : ${c[k]}`).join(", ")}>
        {COVERAGE.filter(([k]) => c[k] > 0).map(([k, l]) => <span key={k} className={`seg seg-${k}`} style={{ flexGrow: c[k] }} title={`${l} : ${c[k]}`} />)}
      </div>
      <ul className="bands cov-bands">
        {COVERAGE.map(([k, l, help]) => (
          <li key={k}>
            <button type="button" aria-pressed={bucket === k} onClick={() => onBucket(k)} title={help}>
              <span className={`swatch seg-${k}`} aria-hidden="true" /><span>{l}</span><strong>{c[k]}</strong>
            </button>
          </li>
        ))}
      </ul>
      {label && (
        <div className="cov-list" aria-live="polite">
          <h3 className="vulns-sub">{label[1]}</h3>
          <p className="muted small">{label[2]}</p>
          {loading && <Skeleton lines={3} label="Chargement des projets…" />}
          {projects && (projects.items.length === 0 ? <p className="muted">Aucun projet.</p> : (
            <ul>
              {projects.items.map((p) => (
                <li key={p.id}>
                  <Link to={`/p/${p.instance}/${p.path}?vue=${bucket === "blind" ? "preuves" : "vulnerabilites"}`}>{p.path}</Link>
                  <span className="muted small">{name(p.instance)}</span>
                </li>
              ))}
              {projects.next_cursor && <li className="muted small">Les 50 premiers seulement : choisissez une instance ou un groupe pour affiner.</li>}
            </ul>
          ))}
          {bucket === "blind" && <p className="small">Pour corriger : publier un rapport CycloneDX dans les artefacts du pipeline (<code>artifacts:reports:cyclonedx</code>), par exemple avec l'analyse des dépendances de GitLab.</p>}
        </div>
      )}
    </section>
  );
}

const day = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString("fr-FR") : "");
const STALE_MS = 2 * 86_400_000;

/** Correction deadlines by SSVC response, counted from the first detection, how many are past them, and how fresh every CVE source is. */
function Deadlines({ v, feeds, sources }: { v: NonNullable<Summary["vulns"]>; feeds: Summary["feeds"]; sources: Source[] }) {
  const late = RESPONSES.reduce((n, [k]) => n + (v.overdue[k] ?? 0), 0);
  const feed = (name: string, f: Feed) => !f.configured ? `${name} non configuré`
    : f.fetched_at ? `${name} du ${day(f.published && !f.published.includes(".") ? f.published : f.fetched_at)} (${f.rows?.toLocaleString("fr-FR")} CVE)${f.error ? ", dernière lecture en échec" : ""}`
    : `${name} jamais lu${f.error ? ` : ${f.error}` : ""}`;
  const none = !feeds.kev.configured && !feeds.epss.configured && !sources.some((x) => x.via === "dependency-track");
  const mirrors = sources.filter((x) => x.via === "dependency-track");
  const stale = (x: Source) => !x.completed_at || Date.now() - Date.parse(x.completed_at) > STALE_MS;
  return (
    <div className="deadlines">
      <h3 className="vulns-sub">Délais de correction par réponse SSVC <span className="muted small">{late} hors délai{v.kev ? ` · ${v.kev} exploitée${v.kev > 1 ? "s" : ""} (KEV)` : ""}</span></h3>
      <table className="vuln-table">
        <thead><tr><th scope="col">Réponse</th><th scope="col">Délai</th><th scope="col" className="num">Ouvertes</th><th scope="col" className="num">Hors délai</th></tr></thead>
        <tbody>
          {RESPONSES.map(([k, , why]) => (
            <tr key={k}>
              <td><Response r={k} /><span className="muted small vuln-title">{why}</span></td>
              <td>{v.sla_hours[k] ? span(v.sla_hours[k]!) : "sans délai"}</td>
              <td className="num">{v.by_response?.[k] ?? 0}</td>
              <td className="num">{v.overdue[k] ? <span className="badge tone-fail">{v.overdue[k]}</span> : v.sla_hours[k] ? 0 : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">{none ? "KEV et EPSS non configurés (miroir interne, valeurs vulnFeeds du chart) : l'exploitation n'est pas connue, la réponse suit la sévérité et l'environnement."
        : `Exploitation : ${feed("KEV", feeds.kev)} · ${feed("EPSS", feeds.epss)}.`}</p>
      {mirrors.length > 0 && <p className="small sources">Sources de CVE de Dependency-Track : {mirrors.map((x, i) => (
        <span key={x.name}>{i > 0 && " · "}{x.name} {x.completed_at ? `du ${day(x.completed_at)}` : "jamais mise à jour"}
          {stale(x) && <span className="badge tone-fail">plus de 2 jours</span>}</span>))}</p>}
      {v.dated === 0 && <p className="muted small">Dates de détection pas encore lues : elles arrivent avec la prochaine analyse de chaque projet.</p>}
    </div>
  );
}
