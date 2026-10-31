// Administration: instances and their collectors, the queue, hot settings, excluded projects and the audit log.
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { api, projectUrl } from "../api";
import { TRIGGER, when } from "../components/status";

interface Overview {
  instances: { slug: string; name: string; url: string; enterprise: boolean; space_dormant: boolean; last_sync_at: string | null; tracked: number;
    excluded: number; oldest_overdue: string | null; queued: number; collector: { j_complete?: number; j_failed?: number; j_ongoing?: number } | null }[];
  runs_24h: { status: string; trigger: string; n: number; reused: number; calls: number }[];
  active: { id: number; branch: string; trigger: string; requested_by: string | null; status: string; created_at: string; instance: string; path: string }[];
  failures_24h: { error: string; n: number }[];
}
interface SettingsBody { values: Record<string, string | number>; changed: Record<string, { updated_by: string; updated_at: string }> }
const STATUS: Record<string, string> = { queued: "en file", running: "en cours", succeeded: "réussies", failed: "en échec", cancelled: "annulées" };

export default function Admin() {
  const client = useQueryClient();
  const overview = useQuery({ queryKey: ["admin-overview"], queryFn: () => api<Overview>("/admin/overview"), refetchInterval: 10_000 });
  const sync = useMutation({ mutationFn: (slug: string) => api(`/admin/instances/${slug}/sync`, { method: "POST" }) });
  const cancel = useMutation({
    mutationFn: (id: number) => api(`/runs/${id}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["admin-overview"] }),
  });
  if (overview.isError) return <p className="error" role="alert">{(overview.error as Error).message}</p>;
  if (!overview.data) return <p className="page-status" role="status">Chargement…</p>;
  const o = overview.data;

  return (
    <section aria-labelledby="admin-title" className="admin">
      <h1 id="admin-title" tabIndex={-1}>Administration</h1>
      <p className="muted">Les instances, leurs quotas et le déploiement se règlent dans <code>periskope-deploy</code>, par merge request. Ici : l'état du service et les réglages à chaud.</p>

      <section className="group" aria-labelledby="a-instances">
        <h2 id="a-instances">Instances GitLab</h2>
        <table>
          <thead><tr><th scope="col">Instance</th><th scope="col">Projets</th><th scope="col">Synchronisation</th><th scope="col">File</th><th scope="col">Collecteur</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {o.instances.map((i) => (
              <tr key={i.slug}>
                <td><strong>{i.name}</strong><br /><span className="muted small">{i.slug} · {i.enterprise ? "Ultimate" : "CE"}{i.space_dormant ? " · projets dormants espacés" : ""}</span></td>
                <td>{i.tracked} suivis<br /><span className="muted small">{i.excluded} exclus</span></td>
                <td>{when(i.last_sync_at)}{i.oldest_overdue && <><br /><span className="error small">en retard depuis {when(i.oldest_overdue)}</span></>}</td>
                <td>{i.queued}</td>
                <td>{i.collector ? <span className="badge tone-pass">actif · {i.collector.j_ongoing ?? 0} en cours</span> : <span className="badge tone-fail">aucun collecteur</span>}</td>
                <td><button type="button" className="secondary" disabled={sync.isPending} aria-label={`Synchroniser ${i.name}`} onClick={() => sync.mutate(i.slug)}>Synchroniser</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="small" role="status">
          {sync.isSuccess && <span className="muted">Synchronisation de {o.instances.find((i) => i.slug === sync.variables)?.name} demandée.</span>}
          {sync.isError && <span className="error">{(sync.error as Error).message}</span>}
        </p>
      </section>

      <div className="admin-grid">
        <section className="group" aria-labelledby="a-runs">
          <h2 id="a-runs">Analyses des dernières 24 h</h2>
          {!o.runs_24h.length ? <p className="muted">Aucune analyse.</p> : (
            <table>
              <thead><tr><th scope="col">Statut</th><th scope="col">Déclencheur</th><th scope="col">Nombre</th><th scope="col">Réutilisées</th><th scope="col">Appels GitLab</th></tr></thead>
              <tbody>{o.runs_24h.map((r) => <tr key={r.status + r.trigger}><td>{STATUS[r.status] ?? r.status}</td><td>{TRIGGER[r.trigger] ?? r.trigger}</td><td>{r.n}</td><td>{r.reused}</td><td>{r.calls}</td></tr>)}</tbody>
            </table>
          )}
          {!!o.failures_24h.length && (
            <>
              <h3>Causes d'échec</h3>
              <ul>{o.failures_24h.map((f) => <li key={f.error}>{f.error} <span className="muted">({f.n})</span></li>)}</ul>
            </>
          )}
        </section>
        <section className="group" aria-labelledby="a-queue">
          <h2 id="a-queue">En file et en cours</h2>
          {!o.active.length ? <p className="muted">Rien en attente.</p> : (
            <table>
              <thead><tr><th scope="col">Projet</th><th scope="col">Branche</th><th scope="col">Depuis</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {o.active.map((r) => (
                  <tr key={r.id}>
                    <td><Link to={`/r/${r.id}`}>{r.path}</Link><br /><span className="muted small">{STATUS[r.status]} · {TRIGGER[r.trigger] ?? r.trigger}{r.requested_by ? ` · ${r.requested_by}` : ""}</span></td>
                    <td><code>{r.branch}</code></td>
                    <td>{when(r.created_at)}</td>
                    <td><button type="button" className="secondary" aria-label={`Arrêter l'analyse de ${r.path}`}
                      onClick={() => confirm(`Arrêter l'analyse de ${r.path} (${r.branch}) ?`) && cancel.mutate(r.id)}>Arrêter</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {cancel.isError && <p className="error" role="alert">{(cancel.error as Error).message}</p>}
        </section>
      </div>

      <SettingsForm />
      <Excluded />
      <Audit />
    </section>
  );
}

const FIELDS: { key: string; label: string; type: "time" | "number"; help: string; max?: number }[] = [
  { key: "sync_at", label: "Synchronisation des projets", type: "time", help: "Heure de Paris" },
  { key: "catch_up_at", label: "Revue nocturne", type: "time", help: "Heure de Paris" },
  { key: "rollup_at", label: "Agrégat mensuel et purge", type: "time", help: "Heure de Paris" },
  { key: "on_demand_per_hour", label: "Analyses à la demande par utilisateur et par heure", type: "number", help: "1 à 1000", max: 1000 },
  { key: "evidence_days", label: "Conservation des preuves brutes (jours)", type: "number", help: "1 à 90", max: 90 },
  { key: "branch_run_days", label: "Conservation des analyses de branche (jours)", type: "number", help: "1 à 365", max: 365 },
  { key: "alert_drop", label: "Alerte si le score baisse d'au moins (points)", type: "number", help: "1 à 100 ; envoi au webhook d'alerte s'il est configuré", max: 100 },
];

function SettingsForm() {
  const client = useQueryClient();
  const settings = useQuery({ queryKey: ["admin-settings"], queryFn: () => api<SettingsBody>("/admin/settings") });
  const [draft, setDraft] = useState<Record<string, string>>({});
  const save = useMutation({
    mutationFn: (body: Record<string, string | number>) => api("/admin/settings", { method: "PUT", body: JSON.stringify(body) }),
    onSuccess: () => { setDraft({}); client.invalidateQueries({ queryKey: ["admin-settings"] }); },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(Object.fromEntries(Object.entries(draft).map(([k, v]) => [k, FIELDS.find((f) => f.key === k)!.type === "number" ? Number(v) : v])));
  };
  const s = settings.data;
  return (
    <section className="group" aria-labelledby="a-settings">
      <h2 id="a-settings">Réglages</h2>
      <form className="settings" onSubmit={submit}>
        {FIELDS.map((f) => (
          <label key={f.key}>
            <span>{f.label}</span>
            <input type={f.type} required min={f.type === "number" ? 1 : undefined} max={f.max} value={draft[f.key] ?? String(s?.values[f.key] ?? "")}
              onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })} aria-describedby={`help-${f.key}`} />
            <span id={`help-${f.key}`} className="muted small">
              {f.help}{s?.changed[f.key] && <> · modifié par {s.changed[f.key].updated_by} le {when(s.changed[f.key].updated_at)}</>}
            </span>
          </label>
        ))}
        <div className="actions">
          <button type="submit" className="primary" disabled={!Object.keys(draft).length || save.isPending}>Enregistrer</button>
          {save.isError && <span className="error">{(save.error as Error).message}</span>}
          {save.isSuccess && <span className="muted" role="status">Enregistré : pris en compte sans redémarrage.</span>}
        </div>
      </form>
    </section>
  );
}

function Excluded() {
  const client = useQueryClient();
  const list = useQuery({ queryKey: ["admin-excluded"], queryFn: () => api<{ items: { id: number; instance: string; path: string; excluded_reason: string | null }[] }>("/admin/projects/excluded") });
  const reinstate = useMutation({
    mutationFn: (p: { instance: string; path: string }) => api(projectUrl(p.instance, p.path), { method: "PATCH", body: JSON.stringify({ enabled: true }) }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["admin-excluded"] }),
  });
  return (
    <section className="group" aria-labelledby="a-excluded">
      <h2 id="a-excluded">Projets exclus</h2>
      <p className="muted small">Exclus à la synchronisation (projets personnels, archivés, vides, namespaces exclus). Réintégrer un projet l'emporte sur la règle automatique.</p>
      {list.data && !list.data.items.length ? <p className="muted">Aucun projet exclu.</p> : (
        <table>
          <thead><tr><th scope="col">Projet</th><th scope="col">Motif</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {list.data?.items.map((p) => (
              <tr key={p.id}>
                <td>{p.path}<br /><span className="muted small">{p.instance}</span></td>
                <td>{p.excluded_reason ?? "—"}</td>
                <td><button type="button" className="secondary" aria-label={`Réintégrer ${p.path}`} onClick={() => reinstate.mutate(p)}>Réintégrer</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {reinstate.isError && <p className="error" role="alert">{(reinstate.error as Error).message}</p>}
    </section>
  );
}

function Audit() {
  const [action, setAction] = useState("");
  const log = useInfiniteQuery({
    queryKey: ["admin-audit", action],
    queryFn: ({ pageParam }) => api<{ items: { at: string; actor: string; action: string; target: string; before: unknown; after: unknown }[]; next_before: string | null }>(
      `/admin/audit?${new URLSearchParams({ ...(action ? { action } : {}), ...(pageParam ? { before: pageParam } : {}) })}`),
    initialPageParam: "",
    getNextPageParam: (last) => last.next_before ?? undefined,
  });
  const rows = log.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <section className="group" aria-labelledby="a-audit">
      <h2 id="a-audit">Journal d'audit</h2>
      <label className="chip">Action
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">toutes</option><option value="run">lancements</option><option value="scope">cadrage</option>
          <option value="project">projets</option><option value="settings">réglages</option><option value="instance">instances</option>
        </select>
      </label>
      {log.data && !rows.length ? <p className="muted">Aucune entrée.</p> : (
        <div className="table-scroll"><table>
          <thead><tr><th scope="col">Date</th><th scope="col">Auteur</th><th scope="col">Action</th><th scope="col">Cible</th><th scope="col">Détail</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.at}-${r.target}`}>
                <td>{when(r.at)}</td><td>{r.actor}</td><td><code>{r.action}</code></td><td className="small">{r.target}</td>
                <td className="small">{r.after || r.before ? (
                  <details><summary>voir</summary>
                    {r.before ? <p className="mono">avant : {JSON.stringify(r.before)}</p> : null}
                    {r.after ? <p className="mono">après : {JSON.stringify(r.after)}</p> : null}
                  </details>
                ) : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
      {log.hasNextPage && <button type="button" className="secondary" onClick={() => log.fetchNextPage()}>Plus ancien</button>}
    </section>
  );
}
