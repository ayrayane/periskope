// Score of the reference branch over time: one series, a crosshair that snaps to the nearest analysis, click to open it.
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { Run } from "../api";
import { when } from "./status";

const W = 720, H = 200, PAD = { top: 12, right: 16, bottom: 28, left: 36 };

export default function ScoreChart({ runs }: { runs: Run[] }) {
  const navigate = useNavigate();
  const svg = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);
  const points = runs.filter((r) => r.status === "succeeded" && r.score != null).sort((a, b) => a.created_at.localeCompare(b.created_at));
  if (points.length < 2) return <p className="muted small">La courbe apparaît après deux analyses réussies de la branche de référence.</p>;

  const t0 = Date.parse(points[0].created_at), t1 = Date.parse(points.at(-1)!.created_at);
  const x = (r: Run) => PAD.left + ((Date.parse(r.created_at) - t0) / Math.max(1, t1 - t0)) * (W - PAD.left - PAD.right);
  const y = (score: number) => PAD.top + (1 - score / 100) * (H - PAD.top - PAD.bottom);
  const path = points.map((r, i) => `${i ? "L" : "M"}${x(r).toFixed(1)},${y(r.score!).toFixed(1)}`).join("");
  const nearest = (clientX: number) => {
    const box = svg.current!.getBoundingClientRect();
    const px = ((clientX - box.left) / box.width) * W;
    return points.reduce((best, r, i) => (Math.abs(x(r) - px) < Math.abs(x(points[best]) - px) ? i : best), 0);
  };
  const h = hover != null ? points[hover] : null;

  return (
    <figure className="chart">
      <figcaption>Score de la branche de référence</figcaption>
      <div className="chart-box">
        <svg ref={svg} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Score de ${points[0].score?.toFixed(0)} à ${points.at(-1)!.score?.toFixed(0)} sur ${points.length} analyses`}
          onPointerMove={(e) => setHover(nearest(e.clientX))} onPointerLeave={() => setHover(null)}
          onClick={(e) => navigate(`/r/${points[nearest(e.clientX)].id}`)}>
          {[0, 50, 100].map((v) => (
            <g key={v} className="grid">
              <line x1={PAD.left} x2={W - PAD.right} y1={y(v)} y2={y(v)} />
              <text x={PAD.left - 6} y={y(v) + 4} textAnchor="end">{v}</text>
            </g>
          ))}
          <text className="axis" x={PAD.left} y={H - 8}>{when(points[0].created_at)}</text>
          <text className="axis" x={W - PAD.right} y={H - 8} textAnchor="end">{when(points.at(-1)!.created_at)}</text>
          <path d={path} className="series" />
          {h && <line className="crosshair" x1={x(h)} x2={x(h)} y1={PAD.top} y2={H - PAD.bottom} />}
          {points.map((r, i) => (
            <circle key={r.id} cx={x(r)} cy={y(r.score!)} r={hover === i ? 6 : 4} className="point" />
          ))}
        </svg>
        {h && (
          // No live region: the history table below gives the same values to keyboard and screen-reader users.
          <div className="tooltip" style={{ left: `${Math.min(85, Math.max(15, (x(h) / W) * 100))}%` }}>
            <strong>{Math.round(h.score!)}/100</strong> <span className="muted">couverture {Math.round(h.coverage ?? 0)} %</span>
            <br /><span className="muted small">{when(h.created_at)} · cliquer pour ouvrir</span>
          </div>
        )}
      </div>
    </figure>
  );
}
