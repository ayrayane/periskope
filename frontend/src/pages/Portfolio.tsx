// Portfolio: the projects in the viewer's scope, paged by the server, filters in the URL so a link can be shared.
import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ProjectRow } from "../api";
import { Score, Skeleton, when } from "../components/status";

type Sort = "name" | "score" | "last_run";
const FILTERS = [
  ["below_target", "Sous la cible"],
  ["failed", "En échec"],
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

  return (
    <section aria-labelledby="portfolio-title">
      <div className="page-head">
        <h1 id="portfolio-title" tabIndex={-1}>Portefeuille</h1>
      </div>
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
                <div role="row" key={p.id} className="row" aria-rowindex={v.index + 2} ref={virtual.measureElement} data-index={v.index}
                  style={{ position: "absolute", top: 0, transform: `translateY(${v.start}px)`, width: "100%" }}>
                  <div role="cell" className="name">
                    <Link to={`/p/${p.instance}/${p.path}`}>{p.path}</Link>
                    <span className="muted small">{p.instance}</span>
                  </div>
                  <div role="cell"><Score score={p.score} coverage={p.coverage} /></div>
                  <div role="cell">{when(p.last_success_at)}</div>
                  <div role="cell">{p.last_error ? <span className="badge tone-fail">Échec : {p.last_error}</span> : p.last_status === "running" || p.last_status === "queued" ? <span className="badge tone-running">En cours</span> : null}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>}
      <p className="page-status" role="status">{projects.isFetchingNextPage ? "Chargement de la suite…" : ""}</p>
    </section>
  );
}
