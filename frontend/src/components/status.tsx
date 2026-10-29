// Shared visual vocabulary: score with its coverage, and statuses that never show "unknown" as a failure.
import type { ActivityStatus, CheckStatus } from "../api";

const CHECK: Record<CheckStatus, { label: string; icon: string }> = {
  pass: { label: "Validée", icon: "✓" },
  fail: { label: "Manquante", icon: "✕" },
  unknown: { label: "Indéterminée", icon: "?" },
  not_applicable: { label: "Sans objet", icon: "–" },
};

const ACTIVITY: Record<ActivityStatus, { label: string; icon: string; tone: CheckStatus }> = {
  implemented: { label: "En place", icon: "✓", tone: "pass" },
  partial: { label: "Partielle", icon: "◐", tone: "fail" },
  not_implemented: { label: "Absente", icon: "✕", tone: "fail" },
  unknown: { label: "Indéterminée", icon: "?", tone: "unknown" },
  not_applicable: { label: "Sans objet", icon: "–", tone: "not_applicable" },
  out_of_scope: { label: "Écartée", icon: "–", tone: "not_applicable" },
};

export function CheckBadge({ status }: { status: CheckStatus }) {
  const s = CHECK[status];
  return (
    <span className={`badge tone-${status}`}>
      <span aria-hidden="true">{s.icon}</span> {s.label}
    </span>
  );
}

export function ActivityBadge({ status, toConfirm }: { status: ActivityStatus; toConfirm?: boolean }) {
  const s = ACTIVITY[status];
  return (
    <span className={`badge tone-${s.tone}`}>
      <span aria-hidden="true">{s.icon}</span> {s.label}
      {toConfirm && <span className="to-confirm"> · à confirmer</span>}
    </span>
  );
}

/** Score and coverage always go together: 40/100 at 95 % is not 40/100 at 50 %. */
export function Score({ score, coverage, size = "md" }: { score: number | null; coverage: number | null; size?: "md" | "lg" }) {
  if (score == null) {
    return <span className={`score score-${size} muted`}>{coverage == null ? "Jamais analysé" : "Rien de mesuré"}</span>;
  }
  return (
    <span className={`score score-${size}`}>
      <strong>{Math.round(score)}</strong>
      <span className="of">/100</span>
      <span className="coverage" title="Part des activités réellement mesurées">couverture {Math.round(coverage ?? 0)} %</span>
    </span>
  );
}

export const RUN_LABEL: Record<string, string> = {
  queued: "En file d'attente", running: "Analyse en cours", succeeded: "Terminée", failed: "Échec", cancelled: "Annulée",
};
export const TRIGGER: Record<string, string> = { user: "à la demande", webhook: "push sur la branche", nightly: "revue nocturne" };

export const when = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" }) : "—";
