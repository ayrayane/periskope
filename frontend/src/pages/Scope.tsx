// Scope: retain or exclude checks and activities, with a reason, one by one or in bulk after filtering. Shows inherited decisions.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, Check, Me, ScopeRow } from "../api";
import { when } from "../components/status";

type Where = { instance?: string; project?: string };
const qs = (w: Where) => new URLSearchParams(Object.entries(w).filter(([, v]) => v) as [string, string][]).toString();

export function ScopeEditor({ where, canEdit }: { where: Where; canEdit: boolean }) {
  const client = useQueryClient();
  const key = ["scope", qs(where)];
  const rows = useQuery({ queryKey: key, queryFn: () => api<ScopeRow[]>(`/scope?${qs(where)}`) });
  const checks = useQuery({ queryKey: ["checks"], queryFn: () => api<Check[]>("/checks"), staleTime: Infinity });
  const [filter, setFilter] = useState({ q: "", target: "all", decision: "all" });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [reason, setReason] = useState("");
  const titles = useMemo(() => Object.fromEntries((checks.data ?? []).map((c) => [c.id, c.title])), [checks.data]);
  const here = where.project ? "projet" : where.instance ? "instance" : "organisation";

  const save = useMutation({
    mutationFn: (body: { decision: "retained" | "excluded"; ids: string[] }) =>
      // A reason is asked to exclude; retaining again records a default one.
      api(`/scope`, { method: "PUT", body: JSON.stringify({ ...where, items: body.ids.map((k) => {
        const [target, ...id] = k.split(":");
        return { target, target_id: id.join(":"), decision: body.decision, reason: reason.trim() || "retenue à nouveau" };
      }) }) }),
    onSuccess: () => {
      setSelected(new Set()); setReason("");
      for (const key of ["scope", "project", "checks", "roadmap"]) client.invalidateQueries({ queryKey: [key] });
    },
  });
  const withdraw = useMutation({
    mutationFn: (r: ScopeRow) => api(`/scope/${encodeURIComponent(r.target_id)}?${qs({ ...where, target: r.target } as Where)}`, { method: "DELETE" }),
    onSuccess: () => { for (const key of ["scope", "project", "checks", "roadmap"]) client.invalidateQueries({ queryKey: [key] }); },
  });

  const visible = (rows.data ?? []).filter((r) =>
    (filter.target === "all" || r.target === filter.target) && (filter.decision === "all" || r.decision === filter.decision) &&
    (!filter.q || `${r.target_id} ${titles[r.target_id] ?? ""}`.toLowerCase().includes(filter.q.toLowerCase())));
  const k = (r: ScopeRow) => `${r.target}:${r.target_id}`;
  const allSelected = visible.length > 0 && visible.every((r) => selected.has(k(r)));
  // Only what the filter shows is acted on: a selection hidden by a later filter never changes silently.
  const acting = [...selected].filter((s) => visible.some((r) => k(r) === s));
  const hidden = selected.size - acting.length;

  return (
    <section aria-label="Cadrage du périmètre">
      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <label className="search"><span className="sr-only">Filtrer</span>
          <input type="search" placeholder="Filtrer les preuves et activités" value={filter.q} onChange={(e) => setFilter({ ...filter, q: e.target.value })} />
        </label>
        <label className="chip">Type
          <select value={filter.target} onChange={(e) => setFilter({ ...filter, target: e.target.value })}>
            <option value="all">tous</option><option value="check">preuves</option><option value="activity">activités</option>
          </select>
        </label>
        <label className="chip">Décision
          <select value={filter.decision} onChange={(e) => setFilter({ ...filter, decision: e.target.value })}>
            <option value="all">toutes</option><option value="retained">retenues</option><option value="excluded">écartées</option>
          </select>
        </label>
      </form>

      {canEdit && selected.size > 0 && (
        <div className="bulk" role="region" aria-label="Décision en masse">
          <strong>{acting.length} sélection{acting.length > 1 ? "s" : ""}{hidden > 0 && <span className="muted"> (et {hidden} masquée{hidden > 1 ? "s" : ""} par le filtre, non concernée{hidden > 1 ? "s" : ""})</span>}</strong>
          <label>Motif <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Pourquoi écarter (obligatoire)" /></label>
          <button type="button" className="primary" disabled={reason.trim().length < 3 || save.isPending || !acting.length} onClick={() => save.mutate({ decision: "excluded", ids: acting })}>Écarter</button>
          <button type="button" className="secondary" disabled={save.isPending || !acting.length} onClick={() => save.mutate({ decision: "retained", ids: acting })}>Retenir</button>
          {save.error && <span className="error" role="alert">{(save.error as Error).message}</span>}
        </div>
      )}

      {withdraw.error && <p className="error" role="alert">{(withdraw.error as Error).message}</p>}
      {rows.isError && <p className="error" role="alert">{(rows.error as Error).message}</p>}
      {rows.isLoading && <p className="page-status" role="status">Chargement…</p>}
      {rows.data && !visible.length && <p className="empty">Aucune preuve ni activité ne correspond au filtre.</p>}
      {visible.length > 0 && <div className="table-scroll"><table>
        <thead>
          <tr>
            {canEdit && <th scope="col"><input type="checkbox" aria-label="Tout sélectionner" checked={allSelected}
              onChange={(e) => setSelected(e.target.checked ? new Set(visible.map(k)) : new Set())} /></th>}
            <th scope="col">Cible</th><th scope="col">Décision</th><th scope="col">Motif</th><th scope="col">Origine</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((r) => (
            <tr key={k(r)}>
              {canEdit && <td><input type="checkbox" aria-label={`Sélectionner ${r.target_id}`} checked={selected.has(k(r))}
                onChange={(e) => { const s = new Set(selected); if (e.target.checked) s.add(k(r)); else s.delete(k(r)); setSelected(s); }} /></td>}
              <td>
                {r.target === "check" ? <>{titles[r.target_id]}<br /><span className="mono small muted">{r.target_id}</span></> : <span lang="en">{r.target_id}</span>}
                <span className="muted small"> · {r.target === "check" ? "preuve" : "activité"}</span>
              </td>
              <td><span className={`badge ${r.decision === "excluded" ? "tone-not_applicable" : "tone-pass"}`}>{r.decision === "excluded" ? "Écartée" : "Retenue"}</span></td>
              <td>{r.reason ?? <span className="muted">—</span>}</td>
              <td className="small">
                {r.level === "défaut" ? <span className="muted">par défaut</span> : <>
                  {r.inherited ? `héritée (${r.level})` : r.level}{r.author && <span className="muted"> · {r.author}, {when(r.updated_at)}</span>}
                </>}
                {canEdit && !r.inherited && r.level === here && <> <button type="button" className="link" aria-label={`Retirer la décision sur ${r.target_id}`} onClick={() => withdraw.mutate(r)}>retirer</button></>}
              </td>
            </tr>
          ))}
        </tbody>
      </table></div>}
    </section>
  );
}

export default function ScopePage() {
  const me = useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/me"), staleTime: 60_000 });
  const instances = useQuery({ queryKey: ["instances"], queryFn: () => api<{ slug: string; name: string }[]>("/instances") });
  const [instance, setInstance] = useState("");
  return (
    <section aria-labelledby="scope-title">
      <div className="page-head">
        <h1 id="scope-title" tabIndex={-1}>Cadrage</h1>
        <label className="chip">Niveau
          <select value={instance} onChange={(e) => setInstance(e.target.value)}>
            <option value="">Organisation</option>
            {instances.data?.map((i) => <option key={i.slug} value={i.slug}>Instance {i.name}</option>)}
          </select>
        </label>
      </div>
      <p className="muted">Une preuve ou une activité écartée sort du score, de la couverture et de la feuille de route. La décision la plus précise l'emporte : projet, puis instance, puis organisation. Les analyses passées ne changent pas.</p>
      <ScopeEditor where={{ instance: instance || undefined }} canEdit={!!me.data?.admin} />
    </section>
  );
}
