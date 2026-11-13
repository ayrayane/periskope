// Committee report of a scope: everything on one printable page, saved as PDF from the browser's print dialog.
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api, DEMO, Indicators, ProjectRow, Summary } from "../api";
import { ENVS, scopeQuery, HeatmapCard, TrendCard } from "../components/Pilot";
import { useScopeData } from "../components/GroupNav";
import { Skeleton, when } from "../components/status";
import { dimension, practice } from "../labels";
import { NOT_MEASURED, urgent } from "../components/Vulns";

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
  const instance = params.get("instance") ?? undefined, namespace = params.get("namespace") ?? undefined, env = params.get("env") ?? undefined;
  const qs = scopeQuery(instance, namespace, env);
  const { instances } = useScopeData();
  const inst = instances.find((i) => i.slug === instance);
  const summary = useQuery({ queryKey: ["projects-summary", qs], queryFn: () => api<Summary>(`/projects/summary?${qs}`) });
  const projects = useQuery({ queryKey: ["report-projects", qs], queryFn: () => allProjects(qs) });
  const indicators = useQuery({ queryKey: ["indicators", qs], queryFn: () => api<Indicators>(`/indicators?${qs}${qs ? "&" : ""}months=6`) });
  const s = summary.data;
  const scope = (namespace ? `Groupe ${namespace}${inst ? ` · ${inst.name}` : ""}` : inst ? inst.name : "Toutes les instances GitLab")
    + (env ? ` · Environnement : ${ENVS.find(([k]) => k === env)?.[1] ?? env}` : "");
  const today = new Intl.DateTimeFormat("fr-FR", { dateStyle: "long", timeStyle: "short" }).format(new Date());

  if (!s) return <Skeleton lines={8} label="Préparation du rapport…" />;
  const weakest = Object.entries(s.dimensions).sort((a, b) => a[1] - b[1])[0];
  const pct = (n: number) => (s.total ? Math.round((100 * n) / s.total) : 0);
  return (
    <article className="report" aria-labelledby="report-title">
      {!DEMO && <div className="report-actions no-print">
        <button type="button" className="btn-ink" onClick={() => window.print()}>Imprimer ou enregistrer en PDF</button>
        <span className="muted small">Dans la fenêtre d'impression, choisissez « Enregistrer au format PDF ».</span>
      </div>}
      <header className="report-head">
        <p className="report-eyebrow">Rapport DevSecOps · référentiel OWASP DSOMM 5.0.2</p>
        <h1 id="report-title" tabIndex={-1}>{scope}</h1>
        <p className="muted">Établi par Periskope le {today}, à partir des dernières analyses de la branche de référence de chaque projet.</p>
      </header>

      <p className="report-summary">
        {s.score == null ? "Aucun projet n'a encore été analysé." : <>Score moyen de <b>{Math.round(s.score)}/100</b> sur {s.analysed} projet{s.analysed > 1 ? "s" : ""} analysé{s.analysed > 1 ? "s" : ""}, {s.below_target} sous leur niveau cible.</>}
        {weakest && <> Dimension la plus faible : <b>{dimension(weakest[0])}</b> ({Math.round(weakest[1])}/100).</>}
        {s.gaps[0] && <> Pratique la plus souvent manquante : <b>{practice(s.gaps[0].activity)}</b>, absente ou partielle dans {s.gaps[0].missing} projet{s.gaps[0].missing > 1 ? "s" : ""} sur {s.gaps[0].measured}.</>}
      </p>
      <section className="report-kpis" aria-label="Chiffres clés">
        <div><b className={s.score == null ? "" : `t-${s.score >= 75 ? "pass" : s.score >= 50 ? "amber" : "fail"}`}>{s.score == null ? "—" : Math.round(s.score)}</b><span>score moyen sur 100</span></div>
        <div><b>{s.total}</b><span>projets, dont {s.analysed} analysés</span></div>
        <div><b>{s.coverage == null ? "—" : `${Math.round(s.coverage)} %`}</b><span>couverture moyenne</span></div>
        <div><b className="t-amber">{s.below_target}</b><span>sous leur niveau cible</span></div>
        <div><b>{s.failed}</b><span>analyses impossibles (source injoignable)</span></div>
      </section>

      {indicators.data && <Kpis i={indicators.data} />}

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
        <h2>Vulnérabilités ouvertes</h2>
        {!s.vulns ? <p>{NOT_MEASURED}</p> : (
          <>
            <p>{s.vulns.total} vulnérabilité{s.vulns.total > 1 ? "s" : ""} ouverte{s.vulns.total > 1 ? "s" : ""} sur la branche de référence de {s.vulns.projects} projet{s.vulns.projects > 1 ? "s" : ""} mesuré{s.vulns.projects > 1 ? "s" : ""}.</p>
            <table className="report-table">
              <thead><tr><th scope="col">Sévérité</th><th scope="col">Vulnérabilités</th></tr></thead>
              <tbody>
                <tr><td>Critiques</td><td>{s.vulns.critical}</td></tr>
                <tr><td>Hautes</td><td>{s.vulns.high}</td></tr>
                <tr><td>Moyennes</td><td>{s.vulns.medium}</td></tr>
                <tr><td>Basses</td><td>{s.vulns.low}</td></tr>
                <tr><td>Autres</td><td>{s.vulns.info + s.vulns.unknown}</td></tr>
              </tbody>
            </table>
            {s.vulns.exposed.length > 0 && (
              <table className="report-table">
                <thead><tr><th scope="col">Projets les plus exposés</th><th scope="col">Instance</th><th scope="col">Critiques et hautes</th></tr></thead>
                <tbody>{s.vulns.exposed.map((e) => <tr key={`${e.instance}/${e.path}`}><td>{e.path}</td><td>{instances.find((i) => i.slug === e.instance)?.name ?? e.instance}</td><td>{urgent(e.vulns)}</td></tr>)}</tbody>
              </table>
            )}
          </>
        )}
      </section>

      <section className="report-block">
        <h2>Score moyen par dimension</h2>
        <table className="report-table">
          <thead><tr><th scope="col">Dimension DSOMM</th><th scope="col">Score moyen</th></tr></thead>
          <tbody>{Object.entries(s.dimensions).sort().map(([d, v]) => <tr key={d}><td title={d}>{dimension(d)}</td><td>{Math.round(v)}/100</td></tr>)}</tbody>
        </table>
      </section>

      <section className="report-block">
        <h2>Pratiques les plus souvent absentes ou partielles</h2>
        {s.gaps.length === 0 ? <p>Aucune.</p> : (
          <table className="report-table">
            <thead><tr><th scope="col">Pratique</th><th scope="col">Niveau</th><th scope="col">Projets concernés</th></tr></thead>
            <tbody>{s.gaps.slice(0, 5).map((g) => <tr key={g.activity}><td title={g.activity}>{practice(g.activity)}</td><td>{g.level}</td><td>{g.missing} sur {g.measured} ({Math.round((100 * g.missing) / Math.max(1, g.measured))} %)</td></tr>)}</tbody>
          </table>
        )}
      </section>

      <div className="report-two"><TrendCard instance={instance} namespace={namespace} env={env} /></div>
      <HeatmapCard instance={instance} namespace={namespace} env={env} instances={instances} />

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
                  <td>{p.last_error ? `Analyse impossible : ${p.last_error}` : p.score == null ? "Jamais analysé" : "À jour"}</td>
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

const MONTH = new Intl.DateTimeFormat("fr-FR", { month: "long", year: "numeric" });
const days = (d: number | null | undefined) => (d == null ? "—" : `${Math.round(d)} j`);

/** The five indicators for management (D11): the commitment kept on critical CVEs, real speed, the debt, SBOM trust, accepted risks. */
function Kpis({ i }: { i: Indicators }) {
  const last = i.months.at(-1)!;
  const onTime = (m: Indicators["months"][number]) => (m.critical_fixed ? `${Math.round((100 * m.critical_on_time) / m.critical_fixed)} %` : "—");
  const trend = i.months.length > 1 ? last.overdue_stock - i.months.at(-2)!.overdue_stock : 0;
  return (
    <section className="report-block">
      <h2>Indicateurs de suivi des vulnérabilités</h2>
      <p>Cibles proposées : 90 % des CVE critiques corrigées dans les délais, critiques corrigées en 7 jours en moyenne, stock hors délai en baisse chaque mois,
        100 % des briques en prod avec un SBOM, aucune exception expirée. Une CVE est corrigée quand elle ne reste dans aucune version en service.</p>
      <section className="report-kpis" aria-label="Indicateurs du mois">
        <div><b className={last.critical_fixed && last.critical_on_time / last.critical_fixed >= 0.9 ? "t-pass" : last.critical_fixed ? "t-fail" : ""}>{onTime(last)}</b>
          <span>critiques corrigées dans les délais ce mois-ci ({last.critical_on_time} sur {last.critical_fixed})</span></div>
        <div><b className={last.days.critical != null && last.days.critical > 7 ? "t-fail" : ""}>{days(last.days.critical)}</b><span>délai moyen de correction d'une critique</span></div>
        <div><b className={trend > 0 ? "t-fail" : "t-pass"}>{last.overdue_stock}</b><span>CVE ouvertes hors délai ({trend > 0 ? `+${trend}` : trend} sur un mois)</span></div>
        <div><b className={i.sbom && i.sbom.bricks && i.sbom.with_sbom < i.sbom.bricks ? "t-fail" : "t-pass"}>{i.sbom?.bricks ? `${Math.round((100 * i.sbom.with_sbom) / i.sbom.bricks)} %` : "—"}</b>
          <span>briques en prod avec un SBOM{i.sbom ? ` (${i.sbom.with_sbom} sur ${i.sbom.bricks})` : " (Dependency-Track non configuré)"}</span></div>
        <div><b className={i.exceptions?.expired ? "t-fail" : ""}>{i.exceptions ? i.exceptions.expired : "—"}</b><span>exceptions expirées, sur {i.exceptions ? i.exceptions.active + i.exceptions.expired : 0} acceptées</span></div>
      </section>
      <table className="report-table">
        <thead><tr><th scope="col">Mois</th><th scope="col">Critiques corrigées dans les délais</th><th scope="col">Délai moyen (critique / élevée / moyenne)</th><th scope="col">Stock hors délai en fin de mois</th></tr></thead>
        <tbody>
          {i.months.map((m) => (
            <tr key={m.month}><td>{MONTH.format(new Date(m.month))}</td><td>{onTime(m)}{m.critical_fixed ? ` (${m.critical_on_time}/${m.critical_fixed})` : ""}</td>
              <td>{days(m.days.critical)} / {days(m.days.high)} / {days(m.days.medium)}</td><td>{m.overdue_stock}</td></tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
