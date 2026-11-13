// Open vulnerabilities as GitLab counts them (CVE and other findings of its scanners), by severity: one bar, every count written.
import type { Vulns } from "../api";

// GitLab's severities follow the CVSS qualitative scale (FIRST); their colours are GitLab's own.
const SEVERITIES = [
  ["critical", "Critiques", "CVSS 9,0 à 10"],
  ["high", "Hautes", "CVSS 7,0 à 8,9"],
  ["medium", "Moyennes", "CVSS 4,0 à 6,9"],
  ["low", "Basses", "CVSS 0,1 à 3,9"],
  ["other", "Autres", "sans score CVSS"],
] as const;
export const CVSS: Record<string, string> = Object.fromEntries(SEVERITIES.map(([k, , range]) => [k, range]));

export const total = (v: Vulns) => v.critical + v.high + v.medium + v.low + v.info + v.unknown;

export function VulnBar({ v }: { v: Vulns }) {
  const n = { ...v, other: v.info + v.unknown };
  return (
    <>
      <div className="stack" role="img" aria-label={SEVERITIES.map(([k, label]) => `${label} : ${n[k]}`).join(", ")}>
        {SEVERITIES.filter(([k]) => n[k] > 0).map(([k, label]) => <span key={k} className={`seg sev-${k}`} style={{ flexGrow: n[k] }} title={`${label} : ${n[k]}`} />)}
        {total(v) === 0 && <span className="seg seg-none" style={{ flexGrow: 1 }} />}
      </div>
      <ul className="bands sev-bands">
        {SEVERITIES.map(([k, label]) => (
          <li key={k}><span className={`swatch sev-${k}`} aria-hidden="true" /><span>{label}<span className="muted small cvss-range">{CVSS[k]}</span></span><strong>{n[k]}</strong></li>
        ))}
      </ul>
    </>
  );
}

/** "2 critiques · 5 hautes": the part that calls for action, for a list line. */
export function urgent(v: Vulns) {
  return [v.critical && `${v.critical} critique${v.critical > 1 ? "s" : ""}`, v.high && `${v.high} haute${v.high > 1 ? "s" : ""}`].filter(Boolean).join(" · ");
}

export const NOT_MEASURED = "Non mesuré : GitLab ne donne les vulnérabilités qu'avec la licence Ultimate.";

export type Severity = keyof Vulns;
const ONE: Record<Severity, string> = { critical: "Critique", high: "Haute", medium: "Moyenne", low: "Basse", info: "Info", unknown: "Inconnue" };

/** One severity as a coloured dot and its word: the colour never speaks alone. */
export function SevTag({ s }: { s: Severity }) {
  const k = s === "unknown" ? "other" : s;
  return <span className="sev-tag" title={CVSS[k === "info" ? "other" : k]}><span className={`swatch sev-${k}`} aria-hidden="true" />{ONE[s]}</span>;
}

const PRIORITY: Record<string, string> = { critical: "Critique", high: "Élevée", medium: "Moyenne", low: "Faible" };

/** The priority that sets the deadline: severity corrected by exploitation (KEV, EPSS). Colour of the matching CVSS level. */
export function Priority({ p, kev, epss }: { p: Severity; kev?: boolean; epss?: number | null }) {
  const label = PRIORITY[p];
  return (
    <span className="priority">
      {label ? <span className="sev-tag"><span className={`swatch sev-${p}`} aria-hidden="true" />{label}</span> : <span className="muted small">—</span>}
      {kev && <span className="badge tone-fail kev" title="Au catalogue KEV de la CISA : exploitée dans la nature">Exploitée (KEV)</span>}
      {epss != null && <span className="muted small epss" title="Probabilité d'exploitation dans les 30 jours (EPSS)">EPSS {epss < 0.001 ? "< 0,1" : (epss * 100).toLocaleString("fr-FR", { maximumFractionDigits: 1 })} %</span>}
    </span>
  );
}

/** Days and hours as a person says them: "3 h", "12 j", "1 an". */
export function span(hours: number) {
  return hours < 48 ? `${Math.round(hours)} h` : hours < 730 * 24 ? `${Math.round(hours / 24)} j` : `${Math.round(hours / 8760)} an${hours >= 1.5 * 8760 ? "s" : ""}`;
}

/** How long a vulnerability has been open, and whether it is past the correction deadline of its severity. */
export function Age({ since, overdue, deadline }: { since: string | null; overdue: boolean; deadline?: number }) {
  if (!since) return <span className="muted small">date inconnue</span>;
  const age = span((Date.now() - Date.parse(since)) / 3_600_000);
  return overdue
    ? <span className="badge tone-fail age-late" title={deadline ? `Délai de correction : ${span(deadline)}` : undefined}>{age} · hors délai</span>
    : <span className="muted small" title={deadline ? `Délai de correction : ${span(deadline)}` : undefined}>{age}</span>;
}

// SSVC responses (D14), most urgent first, with what puts a vulnerability there and the tone of their badge.
export const RESPONSES = [
  ["immediate", "Immédiat", "exploitée (KEV) en prod, ou exploitation probable (EPSS) d'une faille automatisable ou critique en prod", "tone-fail"],
  ["out_of_cycle", "Hors cycle", "exploitée hors prod, exploitation probable en prod, ou faille automatisable ou critique en prod", "tone-warn"],
  ["scheduled", "Planifié", "exploitation probable hors prod, ou autre faille en prod (une version livrée compte comme prod)", "tone-info"],
  ["deferred", "Différé", "faille non exploitée hors prod, ou sans sévérité : sans délai, à la prochaine maintenance", "tone-muted"],
] as const;
const RESPONSE = Object.fromEntries(RESPONSES.map(([k, label, why, tone]) => [k, { label, why, tone }]));

/** The SSVC response that sets the deadline, as a badge with its word. */
export function Response({ r }: { r?: string | null }) {
  const x = r ? RESPONSE[r] : undefined;
  return x ? <span className={`badge ${x.tone}`} title={x.why}>{x.label}</span> : <span className="muted small">—</span>;
}
