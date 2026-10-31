// Committee report of a scope: everything on one printable page, saved as PDF from the browser's print dialog.
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, ProjectRow, Summary } from "../api";
import { scopeQuery, HeatmapCard, TrendCard } from "../components/Pilot";
import { useScopeData } from "../components/GroupNav";
import { Skeleton, when } from "../components/status";

async function allProjects(qs: string): Promise<ProjectRow[]> {
  const out: ProjectRow[] = [];
  let cursor = "";
  // shortcut: stops at 5 000 projects; beyond that the CSV export is the right tool.
  for (let page = 0; page < 25; page++) {
    const r = await api<{ items: ProjectRow[]; next_cursor: string | null }>(`/projects?limit=200&sort=score${qs ? `&${qs}` : ""}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
    out.push(...r.items);
    if (!r.next_cursor) break;
    cursor = r.next_cursor;
  }
  return out;
}

export default function Report() {
  const [params] = useSearchParams();
  const instance = params.get("instance") ?? undefined, namespace = params.get("namespace") ?? undefined;
  const qs = scopeQuery(instance, namespace);
  const { instances } = useScopeData();
  const inst = instances.find((i) => i.slug === instance);
  const summary = useQuery({ queryKey: ["projects-summary", qs], queryFn: () => api<Summary>(`/projects/summary?${qs}`) });
  const projects = useQuery({ queryKey: ["report-projects", qs], queryFn: () => allProjects(qs) });
  const s = summary.data;
  const scope = namespace ? `Groupe ${namespace}${inst ? ` · ${inst.name}` : ""}` : inst ? inst.name : "Toutes les instances GitLab";
  const today = new Intl.DateTimeFormat("fr-FR", { dateStyle: "long", timeStyle: "short" }).format(new Date());

  if (!s) return <Skeleton lines={8} label="Préparation du rapport…" />;
  const pct = (n: number) => (s.total ? Math.round((100 * n) / s.total) : 0);
  return (
    <article className="report" aria-labelledby="report-title">
      <div className="report-actions no-print">
        <button type="button" className="btn-ink" onClick={() => window.print()}>Imprimer ou enregistrer en PDF</button>
        <span className="muted small">Dans la fenêtre d'impression, choisissez « Enregistrer au format PDF ».</span>
      </div>
      <header className="report-head">
        <p className="report-eyebrow">Rapport DevSecOps · référentiel OWASP DSOMM 5.0.2</p>
        <h1 id="report-title" tabIndex={-1}>{scope}</h1>
        <p className="muted">Établi par Periskope le {today}, à partir des dernières analyses de la branche de référence de chaque projet.</p>
      </header>

      <section className="report-kpis" aria-label="Chiffres clés">
        <div><b className={s.score == null ? "" : `t-${s.score >= 75 ? "pass" : s.score >= 50 ? "amber" : "fail"}`}>{s.score == null ? "—" : Math.round(s.score)}</b><span>score moyen sur 100</span></div>
        <div><b>{s.total}</b><span>projets, dont {s.analysed} analysés</span></div>
        <div><b>{s.coverage == null ? "—" : `${Math.round(s.coverage)} %`}</b><span>couverture moyenne</span></div>
        <div><b className="t-fail">{s.below_target}</b><span>sous leur niveau cible</span></div>
        <div><b>{s.failed}</b><span>en échec d'analyse</span></div>
      </section>

      <section className="report-block">
        <h2>Répartition des scores</h2>
        <table className="report-table">
          <thead><tr><th scope="col">Tranche</th><th scope="col">Projets</th><th scope="col">Part</th></tr></thead>
          <tbody>
            <tr><td>75 et plus</td><td>{s.high}</td><td>{pct(s.high)} %</td></tr>
            <tr><td>50 à 74</td><td>{s.mid}</td><td>{pct(s.mid)} %</td></tr>
            <tr><td>Moins de 50</td><td>{s.low}</td><td>{pct(s.low)} %</td></tr>
            <tr><td>Jamais analysés</td><td>{s.never}</td><td>{pct(s.never)} %</td></tr>
          </tbody>
        </table>
      </section>

      <section className="report-block">
        <h2>Score moyen par dimension</h2>
        <table className="report-table">
          <thead><tr><th scope="col">Dimension DSOMM</th><th scope="col">Score moyen</th></tr></thead>
          <tbody>{Object.entries(s.dimensions).sort().map(([d, v]) => <tr key={d}><td lang="en">{d}</td><td>{Math.round(v)}/100</td></tr>)}</tbody>
        </table>
      </section>

      <section className="report-block">
        <h2>Pratiques les plus souvent absentes ou partielles</h2>
        {s.gaps.length === 0 ? <p>Aucune.</p> : (
          <table className="report-table">
            <thead><tr><th scope="col">Pratique</th><th scope="col">Niveau</th><th scope="col">Projets concernés</th></tr></thead>
            <tbody>{s.gaps.map((g) => <tr key={g.activity}><td lang="en">{g.activity}</td><td>{g.level}</td><td>{g.missing} sur {g.measured} ({Math.round((100 * g.missing) / Math.max(1, g.measured))} %)</td></tr>)}</tbody>
          </table>
        )}
      </section>

      <div className="report-two"><TrendCard instance={instance} namespace={namespace} /></div>
      <HeatmapCard instance={instance} namespace={namespace} instances={instances} />

      <section className="report-block">
        <h2>Projets du périmètre</h2>
        {!projects.data ? <Skeleton lines={4} label="Chargement des projets…" /> : (
          <table className="report-table">
            <thead><tr><th scope="col">Projet</th><th scope="col">Instance</th><th scope="col">Score</th><th scope="col">Couverture</th><th scope="col">Dernière analyse réussie</th><th scope="col">État</th></tr></thead>
            <tbody>
              {projects.data.map((p) => (
                <tr key={p.id}>
                  <td>{p.path}</td>
                  <td>{instances.find((i) => i.slug === p.instance)?.name ?? p.instance}</td>
                  <td>{p.score == null ? "—" : `${Math.round(p.score)}/100`}</td>
                  <td>{p.coverage == null ? "—" : `${Math.round(p.coverage)} %`}</td>
                  <td>{when(p.last_success_at)}</td>
                  <td>{p.last_error ? `Échec : ${p.last_error}` : p.score == null ? "Jamais analysé" : "À jour"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small">Le détail des preuves de chaque projet, pratique par pratique, est dans l'export « CSV détaillé » du tableau de bord.</p>
      </section>
    </article>
  );
}
