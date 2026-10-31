// Shared visual vocabulary: score with its coverage, and statuses that never show "unknown" as a failure.
import type { ActivityStatus, CheckStatus } from "../api";
import type { CSSProperties } from "react";

type IconName = "check" | "cross" | "question" | "dash" | "half";
// One stroke icon set (24-unit grid, 2.5 stroke) instead of text glyphs, decorative next to the visible label.
const PATHS: Record<IconName, string> = {
  check: "M5 12.5l4.5 4.5L19 7.5",
  cross: "M6.5 6.5l11 11M17.5 6.5l-11 11",
  question: "M9.2 9.3a3 3 0 1 1 4.3 2.7c-.9.5-1.5 1.1-1.5 2.1v.4M12 18.2h.01",
  dash: "M6.5 12h11",
  half: "M12 4a8 8 0 1 0 0 16zM12 4a8 8 0 1 1 0 16",
};

export function Icon({ name }: { name: IconName }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" focusable="false">
      <path d={PATHS[name]} fill={name === "half" ? "currentColor" : "none"} stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

const CHECK: Record<CheckStatus, { label: string; icon: IconName }> = {
  pass: { label: "Validée", icon: "check" },
  fail: { label: "Manquante", icon: "cross" },
  unknown: { label: "Indéterminée", icon: "question" },
  not_applicable: { label: "Sans objet", icon: "dash" },
};

const ACTIVITY: Record<ActivityStatus, { label: string; icon: IconName; tone: CheckStatus }> = {
  implemented: { label: "En place", icon: "check", tone: "pass" },
  partial: { label: "Partielle", icon: "half", tone: "fail" },
  not_implemented: { label: "Absente", icon: "cross", tone: "fail" },
  unknown: { label: "Indéterminée", icon: "question", tone: "unknown" },
  not_applicable: { label: "Sans objet", icon: "dash", tone: "not_applicable" },
  out_of_scope: { label: "Écartée", icon: "dash", tone: "not_applicable" },
};

export function CheckBadge({ status }: { status: CheckStatus }) {
  const s = CHECK[status];
  return (
    <span className={`badge tone-${status}`}>
      <Icon name={s.icon} /> {s.label}
    </span>
  );
}

export function ActivityBadge({ status, toConfirm }: { status: ActivityStatus; toConfirm?: boolean }) {
  const s = ACTIVITY[status];
  return (
    <span className={`badge tone-${s.tone}`}>
      <Icon name={s.icon} /> {s.label}
      {toConfirm && <span className="to-confirm"> · à confirmer</span>}
    </span>
  );
}

/** Score and coverage always go together: 40/100 at 95 % is not 40/100 at 50 %. */
export function Score({ score, coverage, size = "md" }: { score: number | null; coverage: number | null; size?: "md" | "lg" }) {
  if (score == null) {
    return <span className={`score score-${size} muted`}>{coverage == null ? "Jamais analysé" : "Rien de mesuré"}</span>;
  }
  // The number stays the message; the colour and gauge only reinforce it.
  const band = score >= 75 ? "high" : score >= 50 ? "mid" : "low";
  if (size === "lg") {
    // Ring: circumference 100 on r=15.915, so the dash length is the score itself.
    return (
      <span className={`score-ring band-${band}`}>
        <svg viewBox="0 0 36 36" aria-hidden="true" focusable="false">
          <circle className="track" cx="18" cy="18" r="15.915" />
          <circle className="value" cx="18" cy="18" r="15.915" strokeDasharray={`${score} ${100 - score}`} />
        </svg>
        <span className="ring-label"><strong>{Math.round(score)}</strong><span className="of">/100</span></span>
        <span className="coverage" title="Part des activités réellement mesurées">couverture {Math.round(coverage ?? 0)} %</span>
      </span>
    );
  }
  return (
    <span className={`score score-${size} band-${band}`} style={{ "--pct": `${score}%` } as CSSProperties}>
      <strong>{Math.round(score)}</strong>
      <span className="of">/100</span>
      <span className="gauge" aria-hidden="true" />
      <span className="coverage" title="Part des activités réellement mesurées">couverture {Math.round(coverage ?? 0)} %</span>
    </span>
  );
}

export const RUN_LABEL: Record<string, string> = {
  queued: "En file d'attente", running: "Analyse en cours", succeeded: "Terminée", failed: "Échec", cancelled: "Annulée",
};
export const TRIGGER: Record<string, string> = { user: "à la demande", webhook: "push sur la branche", nightly: "revue nocturne" };

/** Placeholder rows while data loads (progressive loading), hidden from assistive tech, which hears the status text. */
export function Skeleton({ lines = 4, label = "Chargement…" }: { lines?: number; label?: string }) {
  return (
    <div className="skeleton" role="status">
      <span className="sr-only">{label}</span>
      {Array.from({ length: lines }, (_, i) => <span key={i} className="skeleton-line" aria-hidden="true" style={{ width: `${92 - (i % 3) * 14}%` }} />)}
    </div>
  );
}

export const when = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" }) : "—";
