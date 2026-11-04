// Steering cards for a scope: score trend and declining projects, heat map of children × DSOMM dimensions, exports.
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api, download, Heatmap, Instance, Trend } from "../api";
import { scopeUrl } from "./GroupNav";
import { dimension } from "../labels";


export const scopeQuery = (instance?: string, namespace?: string) =>
  new URLSearchParams(Object.entries({ instance, namespace }).filter(([, v]) => v) as [string, string][]).toString();

const band = (v: number) => (v >= 75 ? "high" : v >= 50 ? "mid" : "low");
const MONTH = new Intl.DateTimeFormat("fr-FR", { month: "short", year: "2-digit" });

export function TrendCard({ instance, namespace }: { instance?: string; namespace?: string }) {
  const qs = scopeQuery(instance, namespace);
  const trend = useQuery({ queryKey: ["trend", qs], queryFn: () => api<Trend>(`/projects/trend?${qs}`), staleTime: 60_000 });
  const t = trend.data;
  const pts = t?.months ?? [];
  const W = 340, H = 124, P = 26;
  const x = (i: number) => P + (i / Math.max(1, pts.length - 1)) * (W - 2 * P);
  const y = (v: number) => P + (1 - v / 100) * (H - 2 * P);
  const line = pts.map((m, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(m.score).toFixed(1)}`).join("");
  return (
    <section className="card trend" aria-labelledby="trend-title">
      <h2 id="trend-title">Tendance</h2>
      <p className="card-sub">Score moyen du périmètre, mois par mois, et projets qui ont perdu plus de 5 points en 30 jours</p>
      {pts.length >= 2 ? (
        <svg viewBox={`0 0 ${W} ${H}`} className="trend-chart" role="img"
          aria-label={`Score moyen de ${Math.round(pts[0].score)} à ${Math.round(pts.at(-1)!.score)} sur ${pts.length} mois`}>
          {[0, 50, 100].map((v) => <g key={v}><line className="grid" x1={P} x2={W - P} y1={y(v)} y2={y(v)} /><text className="axis" x={P - 4} y={y(v) + 3} textAnchor="end">{v}</text></g>)}
          <text className="axis" x={x(0)} y={H - 1} textAnchor="start">{MONTH.format(new Date(pts[0].month))}</text>
          <text className="axis" x={x(pts.length - 1)} y={H - 1} textAnchor="end">{MONTH.format(new Date(pts.at(-1)!.month))}</text>
          <path className="area" d={`${line}L${x(pts.length - 1)},${H - P}L${x(0)},${H - P}Z`} />
          <path className="series" d={line} />
          {pts.map((m, i) => <circle key={m.month} className="point" cx={x(i)} cy={y(m.score)} r={i === pts.length - 1 ? 4.5 : 3}>
            <title>{`${MONTH.format(new Date(m.month))} : ${Math.round(m.score)}/100 sur ${m.projects} projet${m.projects > 1 ? "s" : ""}`}</title></circle>)}
        </svg>
      ) : t && <p className="muted small">{pts.length === 1 ? `Un seul mois d'historique (${Math.round(pts[0].score)}/100) : la courbe apparaît au deuxième mois.` : "Pas encore d'historique mensuel."}</p>}
      {t && (t.declining.length === 0 ? <p className="trend-ok">Aucun projet en baisse sur 30 jours.</p> : (
        <ul className="decl-list">
          {t.declining.map((d) => (
            <li key={`${d.instance}/${d.path}`}>
              <Link to={`/p/${d.instance}/${d.path}`}>{d.path.split("/").at(-1)}</Link>
              <span className="muted small" title={d.path}>{d.path}</span>
              <span className="decl-delta">{Math.round(d.before)} → {Math.round(d.score)} <b>▼ {Math.round(d.before - d.score)}</b></span>
            </li>
          ))}
        </ul>
      ))}
    </section>
  );
}

export function HeatmapCard({ instance, namespace, instances }: { instance?: string; namespace?: string; instances: Instance[] }) {
  const qs = scopeQuery(instance, namespace);
  const heat = useQuery({ queryKey: ["heatmap", qs], queryFn: () => api<Heatmap>(`/groups/heatmap?${qs}`), staleTime: 60_000 });
  const h = heat.data;
  if (!h || h.rows.length === 0) return null;
  const level = !instance ? "Instance GitLab" : namespace ? "Sous-groupe" : "Groupe";
  const label = (k: string) => (!instance ? instances.find((i) => i.slug === k)?.name ?? k : k || "Projets du groupe");
  const target = (k: string) => (!instance ? scopeUrl(k) : k ? scopeUrl(instance, namespace ? `${namespace}/${k}` : k) : null);
  return (
    <section className="card heat" aria-labelledby="heat-title">
      <h2 id="heat-title">Carte de chaleur</h2>
      <p className="card-sub">Score moyen {!instance ? "de chaque instance GitLab" : namespace ? "de chaque sous-groupe" : "de chaque groupe"} dans chaque dimension DSOMM. <span className="no-print">Cliquez un nom pour y descendre.</span></p>
      <div className="heat-scroll">
        <table className="heat-table">
          <thead><tr><th scope="col">{level}</th>{h.dimensions.map((d) => <th scope="col" key={d} title={d}>{dimension(d)}</th>)}</tr></thead>
          <tbody>
            {h.rows.map((r) => {
              const to = target(r.key);
              return (
                <tr key={r.key}>
                  <th scope="row">{to ? <Link to={to}>{label(r.key)}</Link> : label(r.key)} <span className="muted small">{r.projects}</span></th>
                  {h.dimensions.map((d) => {
                    const v = r.cells[d];
                    return <td key={d} className={v == null ? "heat-none" : `heat-${band(v)}`} style={v == null ? undefined : { ["--v" as string]: `${v}%` }}>
                      {v == null ? "—" : Math.round(v)}
                    </td>;
                  })}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="heat-legend small"><span className="heat-low">moins de 50</span><span className="heat-mid">50 à 74</span><span className="heat-high">75 et plus</span></p>
    </section>
  );
}

export function ExportBar({ instance, namespace }: { instance?: string; namespace?: string }) {
  const qs = scopeQuery(instance, namespace);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const get = (detail: boolean) => {
    setBusy(detail ? "detail" : "projets"); setError(null);
    download(`/projects/export.csv?${qs}${detail ? `${qs ? "&" : ""}detail=true` : ""}`).catch((e) => setError((e as Error).message)).finally(() => setBusy(null));
  };
  return (
    <div className="export-bar" role="group" aria-label="Exports">
      <Link className="btn-ink" to={`/rapport${qs ? `?${qs}` : ""}`}>Rapport du périmètre</Link>
      <button type="button" className="btn-soft" disabled={!!busy} onClick={() => get(false)}>{busy === "projets" ? "Export…" : "CSV des projets"}</button>
      <button type="button" className="btn-soft" disabled={!!busy} onClick={() => get(true)}>{busy === "detail" ? "Export…" : "CSV détaillé (justifications)"}</button>
      {error && <span className="error" role="alert">{error}</span>}
    </div>
  );
}

