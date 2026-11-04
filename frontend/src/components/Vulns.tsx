// Open vulnerabilities as GitLab counts them (CVE and other findings of its scanners), by severity: one bar, every count written.
import type { Vulns } from "../api";

const SEVERITIES = [
  ["critical", "Critiques"],
  ["high", "Hautes"],
  ["medium", "Moyennes"],
  ["low", "Basses"],
  ["other", "Autres"],
] as const;

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
          <li key={k}><span className={`swatch sev-${k}`} aria-hidden="true" /><span>{label}</span><strong>{n[k]}</strong></li>
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
  return <span className="sev-tag"><span className={`swatch sev-${s === "info" || s === "unknown" ? "other" : s}`} aria-hidden="true" />{ONE[s]}</span>;
}
