// Open vulnerabilities of the scope by CVE: search one, see every project it touches.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, VulnItem, VulnProject } from "../api";
import { useScopeData } from "../components/GroupNav";
import { Score, Skeleton } from "../components/status";
import { NOT_MEASURED, Severity, SevTag } from "../components/Vulns";

const SCANNER: Record<string, string> = {
  dependency_scanning: "Dépendances", container_scanning: "Image de conteneur", sast: "Code (SAST)", dast: "Application (DAST)",
  secret_detection: "Secrets", api_fuzzing: "Fuzzing d'API", coverage_fuzzing: "Fuzzing", cluster_image_scanning: "Cluster",
};
const LEVELS: [Severity | "", string][] = [["", "Toutes les sévérités"], ["critical", "Critiques"], ["high", "Hautes"], ["medium", "Moyennes"], ["low", "Basses"]];

export default function Vulnerabilities() {
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? undefined;
  const instance = get("instance"), namespace = get("namespace"), key = get("cve"), severity = get("severite") ?? "";
  const set = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(changes)) if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };
  const [search, setSearch] = useState(get("q") ?? "");
  useEffect(() => {
    const t = setTimeout(() => set({ q: search.trim() || null }), 250);
    return () => clearTimeout(t);
  }, [search]);

  const scope = new URLSearchParams(Object.entries({ instance, namespace }).filter(([, v]) => v) as [string, string][]);
  const listQs = new URLSearchParams(scope);
  if (get("q")) listQs.set("q", get("q")!);
  const list = useQuery({ queryKey: ["vulns", listQs.toString()], queryFn: () => api<{ measured: number; items: VulnItem[] }>(`/vulnerabilities?${listQs}`), placeholderData: keepPreviousData });
  const projects = useQuery({
    queryKey: ["vuln-projects", key, scope.toString()], enabled: !!key,
    queryFn: () => api<VulnProject[]>(`/vulnerabilities/projects?${new URLSearchParams({ ...Object.fromEntries(scope), key: key! })}`),
  });
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
          {" "}· vulnérabilités ouvertes de la branche par défaut, regroupées par CVE
        </p>
      </header>

      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="search">
          <span className="sr-only">Rechercher une CVE ou un titre</span>
          <input type="search" placeholder="CVE ou titre" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label className="chip">
          <span className="sr-only">Instance GitLab</span>
          <select value={instance ?? ""} onChange={(e) => set({ instance: e.target.value || null, namespace: null, cve: null })}>
            <option value="">Toutes les instances</option>
            {instances.map((i) => <option key={i.slug} value={i.slug}>{i.name}</option>)}
          </select>
        </label>
        {namespace && <button type="button" className="chip" onClick={() => set({ namespace: null, cve: null })} aria-label={`Retirer le filtre groupe ${namespace}`}>Groupe {namespace} ✕</button>}
        <label className="chip">
          <span className="sr-only">Sévérité</span>
          <select value={severity} onChange={(e) => set({ severite: e.target.value || null })}>
            {LEVELS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
          </select>
        </label>
      </form>

      {list.isError && <p className="error" role="alert">{(list.error as Error).message}</p>}
      {list.isLoading && <Skeleton lines={8} label="Chargement des vulnérabilités…" />}
      {list.data && list.data.measured === 0 && <p className="empty">{NOT_MEASURED}</p>}
      {list.data && list.data.measured > 0 && (
        <div className="vulns-split">
          <section className="card" aria-labelledby="vuln-list-title">
            <h2 id="vuln-list-title">{items.length}{items.length === 1000 ? "+" : ""} vulnérabilité{items.length > 1 ? "s" : ""}</h2>
            {items.length === 0 ? <p className="muted">Aucune vulnérabilité ouverte ne correspond.</p> : (
              <table className="vuln-table">
                <thead><tr><th scope="col">Identifiant</th><th scope="col">Sévérité</th><th scope="col" className="num">Projets</th></tr></thead>
                <tbody>
                  {items.map((v) => (
                    <tr key={v.key} aria-selected={v.key === key} className={v.key === key ? "selected" : undefined}>
                      <td>
                        <button type="button" className="link vuln-key" onClick={() => set({ cve: v.key })}>{v.cve ? v.key : v.title}</button>
                        {v.cve && <span className="muted small vuln-title">{v.title}</span>}
                      </td>
                      <td><SevTag s={v.severity} /></td>
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
                {(selected || projects.data?.[0]) && <p className="vuln-meta"><SevTag s={selected?.severity ?? projects.data![0].severity} />{selected?.cve && <span>{selected.title}</span>}
                  {key.startsWith("CVE-") && <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(key)}`} target="_blank" rel="noreferrer">Fiche NVD</a>}</p>}
                {projects.isLoading && <Skeleton lines={4} label="Chargement des projets…" />}
                {projects.data && (
                  <>
                    <h3 className="vulns-sub">{projects.data.length} projet{projects.data.length > 1 ? "s" : ""} touché{projects.data.length > 1 ? "s" : ""}</h3>
                    <table className="vuln-table">
                      <thead><tr><th scope="col">Projet</th><th scope="col">Détectée par</th><th scope="col">Score</th></tr></thead>
                      <tbody>
                        {projects.data.map((p) => (
                          <tr key={`${p.instance}/${p.path}`}>
                            <td><Link to={`/p/${p.instance}/${p.path}`}>{p.path}</Link><span className="muted small vuln-title">{name(p.instance)}</span></td>
                            <td>{SCANNER[p.type] ?? p.type}</td>
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
