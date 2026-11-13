// Dependency-Track views: delivered versions (and two side by side), exceptions and VEX, a project's bricks.
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { api, DtBrick, DtCompare, DtException, DtFinding, DtTree, DtVersion } from "../api";
import { Skeleton } from "./status";
import { Response, SevTag } from "./Vulns";

const day = (iso?: string | null) => (iso ? new Date(iso).toLocaleDateString("fr-FR") : "");
const ENV: Record<string, string> = { prod: "Production", test: "Test", dev: "Développement" };
export const treeKind = (env: string | null) => (env ? ENV[env] ?? env : "Version livrée");

/** Every tree DT holds: environments, then delivered versions; one to open, two to compare (?version=, ?avec=). */
export function Versions() {
  const [params, setParams] = useSearchParams();
  const a = params.get("version"), b = params.get("avec");
  const set = (k: string, v: string | null) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v); else next.delete(k);
    setParams(next, { replace: true });
  };
  const trees = useQuery({ queryKey: ["dt-versions"], queryFn: () => api<DtTree[]>("/dt/versions") });
  if (trees.isError) return <p className="error" role="alert">{(trees.error as Error).message}</p>;
  if (trees.isLoading) return <Skeleton lines={6} label="Chargement des versions…" />;
  const list = trees.data ?? [];
  return (
    <>
      <section className="card" aria-labelledby="versions-title">
        <h2 id="versions-title">Versions suivies dans Dependency-Track</h2>
        <p className="card-sub">Un arbre par environnement (job GitOps) et un par version livrée en JAR. Les versions qui ne tournent plus restent consultables toute leur durée de service.</p>
        {list.length === 0 ? <p className="muted">Aucun arbre dans Dependency-Track pour les projets que vous voyez.</p> : (
          <table className="vuln-table">
            <thead><tr><th scope="col">Version</th><th scope="col">Type</th><th scope="col" className="num">Briques</th><th scope="col" className="num">Sans SBOM</th>
              <th scope="col" className="num">CVE ouvertes</th><th scope="col" className="num">Immédiat</th><th scope="col">Comparer</th></tr></thead>
            <tbody>
              {list.map((t) => (
                <tr key={t.uuid} aria-selected={t.uuid === a} className={t.uuid === a ? "selected" : undefined}>
                  <td><button type="button" className="link vuln-key" onClick={() => set("version", t.uuid)}>{t.name}</button>
                    {!t.active && <span className="muted small vuln-title">ne tourne plus</span>}</td>
                  <td>{treeKind(t.env)}</td>
                  <td className="num">{t.bricks}</td>
                  <td className="num">{t.no_sbom ? <span className="badge tone-fail">{t.no_sbom}</span> : 0}</td>
                  <td className="num">{t.open}</td>
                  <td className="num">{t.immediate ? <span className="badge tone-fail">{t.immediate}</span> : 0}</td>
                  <td>{a && a !== t.uuid ? <button type="button" className="link" aria-pressed={b === t.uuid} onClick={() => set("avec", b === t.uuid ? null : t.uuid)}>
                    {b === t.uuid ? "Comparée" : "Comparer"}</button> : <span className="muted small">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      {a && b ? <Compare a={a} b={b} /> : a ? <Version uuid={a} /> : list.length > 0 && <p className="muted">Choisissez une version pour voir ses briques et ses CVE, puis une seconde pour les comparer.</p>}
    </>
  );
}

function Findings({ items, empty }: { items: DtFinding[]; empty: string }) {
  if (items.length === 0) return <p className="muted">{empty}</p>;
  return (
    <table className="vuln-table">
      <thead><tr><th scope="col">CVE</th><th scope="col">Sévérité</th><th scope="col">Réponse</th><th scope="col">Où</th></tr></thead>
      <tbody>
        {items.map((f) => (
          <tr key={f.key}>
            <td><Link to={`/vulnerabilites/cve/${encodeURIComponent(f.key)}`} className="vuln-key">{f.key}</Link>
              {f.kev && <span className="badge tone-fail kev">Exploitée (KEV)</span>}{f.title && <span className="muted small vuln-title">{f.title}</span>}</td>
            <td><SevTag s={f.severity} /></td>
            <td><Response r={f.response} /></td>
            <td className="small">{f.where.join(" ; ")}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Version({ uuid }: { uuid: string }) {
  const v = useQuery({ queryKey: ["dt-version", uuid], queryFn: () => api<DtVersion>(`/dt/versions/${uuid}`) });
  if (v.isError) return <p className="error" role="alert">{(v.error as Error).message}</p>;
  if (!v.data) return <Skeleton lines={6} label="Chargement de la version…" />;
  const { tree, bricks, findings } = v.data;
  return (
    <div className="vulns-split">
      <section className="card" aria-labelledby="version-bricks">
        <h2 id="version-bricks">{tree.name}</h2>
        <p className="card-sub">{treeKind(tree.env)} · lu dans Dependency-Track le {day(tree.synced_at)}</p>
        <Bricks rows={bricks.map((b) => ({ ...b, label: b.path ? <Link to={`/p/${b.instance}/${b.path}?vue=vulnerabilites`}>{b.name}</Link> : <>{b.name} <span className="muted small">sans projet GitLab</span></> }))} />
      </section>
      <section className="card" aria-labelledby="version-cves">
        <h2 id="version-cves">{findings.length} CVE ouverte{findings.length > 1 ? "s" : ""}</h2>
        <Findings items={findings} empty="Aucune CVE ouverte dans cette version." />
      </section>
    </div>
  );
}

function Compare({ a, b }: { a: string; b: string }) {
  const c = useQuery({ queryKey: ["dt-compare", a, b], queryFn: () => api<DtCompare>(`/dt/compare?a=${a}&b=${b}`) });
  if (c.isError) return <p className="error" role="alert">{(c.error as Error).message}</p>;
  if (!c.data) return <Skeleton lines={6} label="Comparaison…" />;
  const d = c.data;
  return (
    <section className="card" aria-labelledby="compare-title">
      <h2 id="compare-title">{d.a.name} → {d.b.name}</h2>
      <h3 className="vulns-sub">Briques dont la version change</h3>
      {d.bricks.length === 0 ? <p className="muted">Mêmes versions de briques.</p> : (
        <ul className="plain">{d.bricks.map((x) => <li key={x.name}><strong>{x.name}</strong> : {x.a ?? "absente"} → {x.b ?? "absente"}</li>)}</ul>
      )}
      <div className="vulns-split">
        <div><h3 className="vulns-sub">Seulement dans {d.a.name} ({d.only_a.length})</h3><Findings items={d.only_a} empty="Aucune." /></div>
        <div><h3 className="vulns-sub">Seulement dans {d.b.name} ({d.only_b.length})</h3><Findings items={d.only_b} empty="Aucune." /></div>
      </div>
      <h3 className="vulns-sub">Présentes dans les deux ({d.both.length})</h3>
      <Findings items={d.both} empty="Aucune." />
    </section>
  );
}

type BrickRow = Pick<DtBrick, "version" | "sbom" | "by_tag" | "components" | "no_purl"> & { label: React.ReactNode };

/** Bricks with their SBOM state: missing, deployed by tag, components without purl (DT matches them to no CVE). */
export function Bricks({ rows, first = "Brique" }: { rows: BrickRow[]; first?: string }) {
  return (
    <table className="vuln-table">
      <thead><tr><th scope="col">{first}</th><th scope="col">Version</th><th scope="col">SBOM</th><th scope="col" className="num">Composants</th><th scope="col" className="num">Sans purl</th></tr></thead>
      <tbody>
        {rows.map((b, i) => (
          <tr key={i}>
            <td>{b.label}</td>
            <td>{b.version ?? "—"}</td>
            <td>{b.sbom ? "oui" : <span className="badge tone-fail">aucun SBOM</span>}{b.by_tag && <span className="badge tone-warn" title="Déployée par tag : l'image peut changer sans changer de version">par tag</span>}</td>
            <td className="num">{b.components ?? "—"}</td>
            <td className="num">{b.no_purl ? <span className="badge tone-warn" title="Sans purl, DT ne rapproche ce composant d'aucune CVE">{b.no_purl}</span> : b.components == null ? "—" : 0}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** A project's bricks, one per tree where it runs. */
export function ProjectBricks({ bricks }: { bricks: DtBrick[] }) {
  return (
    <section className="card" aria-labelledby="dt-bricks-title">
      <h2 id="dt-bricks-title">Versions déployées (Dependency-Track)</h2>
      <p className="card-sub">Les dépendances et images de ce projet sont suivies par Dependency-Track dans chaque environnement et chaque version livrée.</p>
      <Bricks first="Où elle tourne" rows={bricks.map((b) => ({ ...b, label: <>{b.tree}<span className="muted small vuln-title">{treeKind(b.env)}</span></> }))} />
    </section>
  );
}

const JUSTIFICATION: Record<string, string> = {
  CODE_NOT_PRESENT: "code absent", CODE_NOT_REACHABLE: "code jamais atteint", REQUIRES_CONFIGURATION: "demande une configuration absente",
  REQUIRES_DEPENDENCY: "demande une dépendance absente", REQUIRES_ENVIRONMENT: "demande un environnement absent",
  PROTECTED_BY_COMPILER: "protégé par le compilateur", PROTECTED_AT_RUNTIME: "protégé à l'exécution", PROTECTED_AT_PERIMETER: "protégé en périphérie",
  PROTECTED_BY_MITIGATING_CONTROL: "protégé par une mesure compensatoire",
};

/** Accepted exceptions with their end (lapsed ones first, in red), and the CVEs declared not concerned with their justification. */
export function Exceptions({ qs }: { qs: URLSearchParams }) {
  const q = useQuery({ queryKey: ["dt-exceptions", qs.toString()], queryFn: () => api<{ exceptions: DtException[]; not_concerned: DtException[] }>(`/dt/exceptions?${qs}`) });
  if (q.isError) return <p className="error" role="alert">{(q.error as Error).message}</p>;
  if (!q.data) return <Skeleton lines={6} label="Chargement des exceptions…" />;
  const { exceptions, not_concerned } = q.data;
  const where = (e: DtException) => <>{e.path ? <Link to={`/p/${e.instance}/${e.path}?vue=vulnerabilites`}>{e.brick}</Link> : e.brick}<span className="muted small vuln-title">{e.tree} · {e.version}</span></>;
  const expired = exceptions.filter((e) => e.expired).length;
  return (
    <div className="vulns-split">
      <section className="card" aria-labelledby="exc-title">
        <h2 id="exc-title">{exceptions.length} exception{exceptions.length > 1 ? "s" : ""} {expired > 0 && <span className="badge tone-fail">{expired} expirée{expired > 1 ? "s" : ""}</span>}</h2>
        <p className="card-sub">Risques acceptés par le référent et le RSSI (fichier VEX du dépôt, envoyé à DT), 90 jours au plus sans échéance écrite</p>
        {exceptions.length === 0 ? <p className="muted">Aucune exception.</p> : (
          <table className="vuln-table">
            <thead><tr><th scope="col">CVE</th><th scope="col">Brique</th><th scope="col">Échéance</th><th scope="col">Motif</th></tr></thead>
            <tbody>
              {exceptions.map((e, i) => (
                <tr key={i}>
                  <td><Link to={`/vulnerabilites/cve/${encodeURIComponent(e.key)}`}>{e.key}</Link> <SevTag s={e.severity} /></td>
                  <td>{where(e)}</td>
                  <td>{e.expired ? <span className="badge tone-fail">expirée le {day(e.expires_on)}</span> : day(e.expires_on)}</td>
                  <td className="small">{e.detail ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <section className="card" aria-labelledby="vex-title">
        <h2 id="vex-title">{not_concerned.length} CVE non concernée{not_concerned.length > 1 ? "s" : ""} (VEX)</h2>
        <p className="card-sub">Déclarées sans effet sur la brique, revues à chaque version dans la MR qui change le fichier VEX</p>
        {not_concerned.length === 0 ? <p className="muted">Aucune.</p> : (
          <table className="vuln-table">
            <thead><tr><th scope="col">CVE</th><th scope="col">Brique</th><th scope="col">Justification</th><th scope="col">Décidée le</th></tr></thead>
            <tbody>
              {not_concerned.map((e, i) => (
                <tr key={i}>
                  <td><Link to={`/vulnerabilites/cve/${encodeURIComponent(e.key)}`}>{e.key}</Link></td>
                  <td>{where(e)}</td>
                  <td className="small">{(e.justification && JUSTIFICATION[e.justification]) ?? (e.state === "FALSE_POSITIVE" ? "faux positif" : "—")}{e.detail && <span className="muted small vuln-title">{e.detail}</span>}</td>
                  <td>{day(e.analysed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
