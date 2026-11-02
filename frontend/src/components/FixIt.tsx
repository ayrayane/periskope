// « Corriger dans GitLab »: a preview first, then the person applies the fix with their own GitLab account. Nothing happens without that click.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../api";

export interface FixOffer { enabled: boolean; can_fix: boolean; connected: boolean; items: { check: string; kind: "setting" | "mr"; label: string; needs: string | null }[] }
interface Preview { summary: string; changes?: { what: string; before: string; after: string }[]; files?: { path: string; content: string }[]; note?: string }

export default function FixIt({ url, instance, check, kind }: { url: string; instance: string; check: string; kind: "setting" | "mr" }) {
  const client = useQueryClient();
  const preview = useMutation({
    mutationFn: async () => {
      try {
        return await api<Preview>(`${url}/fixes/${encodeURIComponent(check)}/preview`, { method: "POST" });
      } catch (e) {
        if (!(e instanceof ApiError && e.status === 428)) throw e;
        // First fix of the session: GitLab asks the person to authorise Periskope, then brings them back here.
        const login = await api<{ url: string }>(`/fixit/${encodeURIComponent(instance)}/login`, { method: "POST", body: JSON.stringify({ return_to: location.pathname + location.search }) });
        location.assign(login.url);
        return new Promise<never>(() => {});
      }
    },
  });
  const apply = useMutation({
    mutationFn: () => api<{ done: string; url?: string; run?: string }>(`${url}/fixes/${encodeURIComponent(check)}`, { method: "POST" }),
    onSuccess: () => ["project", "runs", "fixes"].forEach((k) => client.invalidateQueries({ queryKey: [k, url] })),
  });

  if (apply.data) {
    return (
      <p className="fixit-done" role="status">{apply.data.done}{" "}
        {apply.data.url && <a href={apply.data.url} target="_blank" rel="noreferrer">Voir la merge request<span className="sr-only"> (nouvel onglet)</span> ↗</a>}
        {apply.data.run && <span className="muted small">Nouvelle analyse lancée.</span>}
      </p>
    );
  }
  const p = preview.data;
  return (
    <div className="fixit">
      {!p && (
        <button type="button" className="secondary" onClick={() => preview.mutate()} disabled={preview.isPending}>
          {preview.isPending ? "Préparation…" : kind === "mr" ? "Proposer une merge request" : "Corriger dans GitLab"}
        </button>
      )}
      {p && (
        <div className="fixit-preview">
          <p><strong>{p.summary}</strong></p>
          {p.changes && (
            <table className="t-fixed">
              <thead><tr><th scope="col">Réglage</th><th scope="col">Avant</th><th scope="col">Après</th></tr></thead>
              <tbody>{p.changes.map((c) => <tr key={c.what}><td>{c.what}</td><td>{c.before}</td><td>{c.after}</td></tr>)}</tbody>
            </table>
          )}
          {p.files?.map((f) => (
            <div key={f.path} className="snippet">
              <div className="snippet-head"><span className="mono">{f.path}</span></div>
              <pre><code>{f.content}</code></pre>
            </div>
          ))}
          {p.note && <p className="muted small">{p.note}</p>}
          <p className="muted small">{kind === "mr" ? "Une branche et une merge request seront créées avec votre compte GitLab : rien n'est poussé sur la branche principale." : "La modification sera faite avec votre compte GitLab et tracée dans son journal d'audit."}</p>
          <div className="fixit-actions">
            <button type="button" className="primary" onClick={() => apply.mutate()} disabled={apply.isPending}>{apply.isPending ? "Application…" : kind === "mr" ? "Ouvrir la merge request" : "Appliquer"}</button>
            <button type="button" className="secondary" onClick={() => preview.reset()} disabled={apply.isPending}>Annuler</button>
          </div>
        </div>
      )}
      {(preview.error || apply.error) && <p className="error" role="alert">{((preview.error || apply.error) as Error).message}</p>}
    </div>
  );
}
