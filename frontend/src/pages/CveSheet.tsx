// Follow-up sheet of one CVE, from detection to closure: every version where DT finds it with its analysis, the versions already
// updated, and when each project opened and closed it.
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, CveSheet as Sheet, DtPlace } from "../api";
import { treeKind } from "../components/Dtrack";
import { Skeleton } from "../components/status";
import { Response, SevTag } from "../components/Vulns";

const day = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString("fr-FR") : "—");
const STATUS: Record<DtPlace["status"], [string, string]> = {
  open: ["Ouverte", "tone-fail"], exception: ["Exception", "tone-warn"], not_concerned: ["Non concernée", "tone-pass"], resolved: ["Résolue", "tone-pass"],
};
// DT's vendor response: the patch on its way, as the referent recorded it.
const ANSWER: Record<string, string> = { UPDATE: "mise à jour", ROLLBACK: "retour arrière", WORKAROUND_AVAILABLE: "contournement", WILL_NOT_FIX: "ne sera pas corrigée", CAN_NOT_FIX: "ne peut pas être corrigée" };

export default function CveSheet() {
  const { key = "" } = useParams();
  const q = useQuery({ queryKey: ["cve-sheet", key], queryFn: () => api<Sheet>(`/dt/cve/${encodeURIComponent(key)}`) });
  const first = q.data?.places[0];
  const open = q.data?.places.filter((p) => p.status === "open" && p.active && p.tree_active) ?? [];
  return (
    <article>
      <p className="crumbs"><Link to={`/vulnerabilites?cve=${encodeURIComponent(key)}`}>Vulnérabilités</Link> › Fiche de suivi</p>
      <header className="page-head">
        <h1 tabIndex={-1}>{key}</h1>
        {first && <p className="vuln-meta"><SevTag s={first.severity} /> <Response r={open[0]?.response ?? first.response} />
          {first.kev && <span className="badge tone-fail kev" title="Au catalogue KEV de la CISA : exploitée dans la nature">Exploitée (KEV)</span>}{first.title && <span>{first.title}</span>}
          {key.startsWith("CVE-") && <a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(key)}`} target="_blank" rel="noreferrer">Fiche NVD</a>}</p>}
      </header>
      {q.isError && <p className="error" role="alert">{(q.error as Error).message}</p>}
      {q.isLoading && <Skeleton lines={8} label="Chargement de la fiche…" />}
      {q.data && (
        <>
          <section className="card" aria-labelledby="places-title">
            <h2 id="places-title">Versions touchées {open.length > 0 ? <span className="badge tone-fail">{open.length} ouverte{open.length > 1 ? "s" : ""} en service</span> : <span className="badge tone-pass">aucune ouverte en service</span>}</h2>
            <p className="card-sub">Chaque version de brique où Dependency-Track trouve la CVE, avec sa réponse SSVC et la décision prise dans DT (fichier VEX du dépôt)</p>
            {q.data.places.length === 0 ? <p className="muted">Dependency-Track ne la trouve dans aucune version visible : elle vient de GitLab (voir l'historique).</p> : (
              <table className="vuln-table">
                <thead><tr><th scope="col">Version</th><th scope="col">Brique</th><th scope="col">Composant</th><th scope="col">État</th><th scope="col">Réponse</th><th scope="col">Décision dans DT</th></tr></thead>
                <tbody>
                  {q.data.places.map((p, i) => (
                    <tr key={i}>
                      <td>{p.tree}<span className="muted small vuln-title">{treeKind(p.env)}{!p.tree_active || !p.active ? " · ne tourne plus" : ""}</span></td>
                      <td>{p.path ? <Link to={`/p/${p.instance}/${p.path}?vue=vulnerabilites`}>{p.brick}</Link> : p.brick} {p.version}</td>
                      <td className="small">{p.component_name}@{p.component_version}</td>
                      <td><span className={`badge ${STATUS[p.status][1]}`}>{STATUS[p.status][0]}</span>
                        {p.status === "exception" && p.expires_on && <span className="muted small vuln-title">jusqu'au {day(p.expires_on)}</span>}</td>
                      <td><Response r={p.status === "open" && p.active && p.tree_active ? p.response : null} /></td>
                      <td className="small">{p.analysis_response && ANSWER[p.analysis_response] ? `${ANSWER[p.analysis_response]}. ` : ""}{p.detail ?? (p.state && p.state !== "NOT_SET" ? p.state.toLowerCase() : "—")}
                        {p.analysed_at && <span className="muted small vuln-title">le {day(p.analysed_at)}</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
          <div className="vulns-split">
            <section className="card" aria-labelledby="fixed-title">
              <h2 id="fixed-title">Versions déjà mises à jour</h2>
              <p className="card-sub">Les mêmes briques, dans une version où la CVE n'est plus : le correctif y est</p>
              {q.data.fixed_in.length === 0 ? <p className="muted">Aucune pour l'instant.</p> : (
                <ul className="plain">{q.data.fixed_in.map((f, i) => <li key={i}><strong>{f.brick} {f.version}</strong> dans {f.tree}<span className="muted small"> · {treeKind(f.env)}{!f.tree_active || !f.active ? ", ne tourne plus" : ""}</span></li>)}</ul>
              )}
            </section>
            <section className="card" aria-labelledby="ledger-title">
              <h2 id="ledger-title">Historique par projet</h2>
              <p className="card-sub">Ouverture, échéance et clôture : une CVE est corrigée quand elle ne reste dans aucune version en service (D15)</p>
              {q.data.ledger.length === 0 ? <p className="muted">Pas encore d'historique.</p> : (
                <table className="vuln-table">
                  <thead><tr><th scope="col">Projet</th><th scope="col">Ouverte</th><th scope="col">Échéance</th><th scope="col">Fermée</th></tr></thead>
                  <tbody>
                    {q.data.ledger.map((l, i) => {
                      const late = l.deadline_at && (l.closed_at ?? new Date().toISOString()) > l.deadline_at;
                      return (
                        <tr key={i}>
                          <td><Link to={`/p/${l.instance}/${l.path}?vue=vulnerabilites`}>{l.path}</Link><span className="muted small vuln-title"><Response r={l.response} /></span></td>
                          <td>{day(l.opened_at)}</td>
                          <td>{l.deadline_at ? day(l.deadline_at) : "sans délai"}</td>
                          <td>{l.closed_at ? <>{day(l.closed_at)} {late && <span className="badge tone-fail">après l'échéance</span>}</> : late ? <span className="badge tone-fail">ouverte, hors délai</span> : "ouverte"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </section>
          </div>
        </>
      )}
    </article>
  );
}
