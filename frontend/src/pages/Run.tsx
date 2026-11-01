// One analysis: its results, a banner when it is not the reference branch, and what changed against the reference or the previous run.
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { StatusFilter } from "../components/TableTools";
import { Link, useParams } from "react-router-dom";
import { api, ApiError, Check, Diff, RunDetail } from "../api";
import FixGuide from "../components/FixGuide";
import { CheckBadge, RUN_LABEL as LABEL, Score, Skeleton, when } from "../components/status";

export default function Run() {
  const { id = "" } = useParams();
  const [startedAt] = useState(Date.now());
  const [show, setShow] = useState<"all" | "fail" | "unknown" | "pass">("all");
  const run = useQuery({
    queryKey: ["run-detail", id],
    queryFn: () => api<RunDetail>(`/runs/${id}`),
    refetchInterval: (q) => (["queued", "running"].includes(q.state.data?.status ?? "") ? (Date.now() - startedAt > 120_000 ? 10_000 : 3_000) : false),
  });
  // Fetched alongside the run, not after it: the API picks the comparison (previous run on the reference, the reference for a branch).
  const diff = useQuery({
    queryKey: ["diff", id, run.data?.status],
    queryFn: () => api<Diff>(`/runs/${id}/diff`),
    enabled: run.data?.status !== "queued" && run.data?.status !== "running",
    retry: false,
  });
  const checks = useQuery({ queryKey: ["checks"], queryFn: () => api<Check[]>("/checks"), staleTime: Infinity });
  if (run.isError) return <p className="error" role="alert">{(run.error as ApiError).status === 404 ? "Analyse introuvable." : (run.error as Error).message}</p>;
  if (!run.data) return <Skeleton lines={6} label="Chargement de l'analyse…" />;
  const r = run.data;
  const listed = (checks.data ?? []).filter((c) => r.results?.[c.id]);
  const reference = r.branch === r.default_branch;
  const done = r.status === "succeeded";

  return (
    <article aria-labelledby="run-title">
      <nav className="crumbs" aria-label="Fil d'Ariane">
        <Link to="/">Tableau de bord</Link> / <Link to={`/p/${r.instance}/${r.path}`}>{r.path}</Link> / analyse {r.id}
      </nav>
      {!reference && (
        <p className="banner" role="note">
          Branche <code>{r.branch}</code>, pas la référence du projet (<code>{r.default_branch}</code>) : cette analyse ne change pas la note du projet.
        </p>
      )}
      <header className="project-head">
        <div>
          <h1 id="run-title" tabIndex={-1}>Analyse de <code>{r.branch}</code></h1>
          <p className="muted" role="status">
            {LABEL[r.status]}{r.finished_at && <> le {when(r.finished_at)}</>}{r.commit_sha && <> sur <code>{r.commit_sha.slice(0, 8)}</code></>}
            {r.requested_by && <> · lancée par {r.requested_by}</>}
          </p>
        </div>
        {done && <Score score={r.score} coverage={r.coverage} size="lg" />}
      </header>
      {r.status === "failed" && <p className="error" role="alert">Échec : {r.error}</p>}
      {(r.status === "queued" || r.status === "running") && <p className="empty">Analyse {r.status === "queued" ? "en file d'attente" : "en cours"} : la page se met à jour toute seule.</p>}
      {done && (
        <>
          <DiffView diff={diff.data} error={diff.error as Error | null} id={r.id}
            title={reference ? "Changements depuis l'analyse précédente" : "Comparaison avec la branche de référence"} />
          <section className="group">
            <h2>Preuves</h2>
            <div className="table-tools">
              <StatusFilter label="Filtrer les preuves par résultat" value={show} onChange={setShow} options={[
                { value: "all", label: "Toutes", count: listed.length },
                { value: "fail", label: "À corriger", count: listed.filter((c) => r.results![c.id].status === "fail").length, tone: "fail" },
                { value: "unknown", label: "Indéterminées", count: listed.filter((c) => r.results![c.id].status === "unknown").length, tone: "unknown" },
                { value: "pass", label: "Validées", count: listed.filter((c) => r.results![c.id].status === "pass").length, tone: "pass" },
              ]} />
            </div>
            <div className="table-scroll"><table>
              <thead><tr><th scope="col">Preuve</th><th scope="col">Statut</th><th scope="col">Constat</th></tr></thead>
              <tbody>
                {listed.filter((c) => show === "all" || r.results![c.id].status === show).map((c) => (
                  <tr key={c.id}>
                    <td title={c.id} className="cell-main">{c.title}</td>
                    <td><CheckBadge status={r.results![c.id].status} /></td>
                    <td>{r.results![c.id].message}{!["pass", "not_applicable"].includes(r.results![c.id].status) && <FixGuide fix={c.fix} />}</td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          </section>
        </>
      )}
    </article>
  );
}

function DiffView({ diff, error, id, title }: { diff?: Diff; error: Error | null; id: number; title: string }) {
  if (error) return <p className="muted">{error.message}</p>;
  if (!diff) return null;
  const d = diff;
  const delta = d.after.score != null && d.before.score != null ? Math.round(d.after.score - d.before.score) : null;
  const rows = (list: Diff["gained"], label: string, tone: string) =>
    list.length > 0 && (
      <div className="diff-group">
        <h3 className={tone}>{label} ({list.length})</h3>
        <ul>{list.map((x) => <li key={x.check}>{x.after_message}<span className="muted small"> (avant : {x.before_message}) · <span className="mono">{x.check}</span></span></li>)}</ul>
      </div>
    );
  return (
    <section className="group diff" aria-labelledby={`diff-${id}`}>
      <h2 id={`diff-${id}`}>{title}</h2>
      <p className="muted small">
        Par rapport à l'analyse {d.before.id} sur <code>{d.before.branch}</code> du {when(d.before.finished_at)}
        {delta != null && <> · score {delta > 0 ? `+${delta}` : delta}</>}
      </p>
      {!d.gained.length && !d.lost.length && !d.changed.length ? <p className="muted">Aucun changement.</p> : (
        <>
          {rows(d.lost, "Perdues", "lost")}
          {rows(d.gained, "Gagnées", "gained")}
          {rows(d.changed, "Autres changements", "")}
        </>
      )}
    </section>
  );
}
