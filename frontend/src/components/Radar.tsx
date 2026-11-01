// Radar of DSOMM dimensions: one closed shape per series, 0 at the centre, 100 at the rim. Unmeasured axes sit at 0 and say so.
import { dimension } from "../labels";
type Series = { label: string; values: Record<string, number | null>; tone: "main" | "ref" };

const W = 520, H = 350, C = { x: 260, y: 175 }, R = 118;
// Long dimension names go on two balanced lines so they stay inside the frame on a phone.
const lines = (label: string) => {
  const w = label.split(" ");
  if (label.length < 14 || w.length < 2) return [label];
  let cut = 1;
  while (cut < w.length - 1 && w.slice(0, cut + 1).join(" ").length <= label.length / 2) cut++;
  return [w.slice(0, cut).join(" "), w.slice(cut).join(" ")];
};

export default function Radar({ axes, series, title }: { axes: string[]; series: Series[]; title: string }) {
  if (axes.length < 3) return null;
  const at = (i: number, v: number) => {
    const a = -Math.PI / 2 + (2 * Math.PI * i) / axes.length;
    return [C.x + Math.cos(a) * R * (v / 100), C.y + Math.sin(a) * R * (v / 100)] as const;
  };
  const shape = (values: Record<string, number | null>) => axes.map((d, i) => at(i, values[d] ?? 0).map((n) => n.toFixed(1)).join(",")).join(" ");
  const main = series.find((s) => s.tone === "main")!;
  return (
    <figure className="chart radar">
      <figcaption>{title}</figcaption>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${title} : ${axes.map((d) => `${dimension(d)} ${main.values[d] == null ? "non mesuré" : Math.round(main.values[d]!)}`).join(", ")}`}>
        {[25, 50, 75, 100].map((v) => <polygon key={v} className="ring" points={axes.map((_, i) => at(i, v).join(",")).join(" ")} />)}
        {axes.map((d, i) => {
          const [x, y] = at(i, 100), [lx, ly] = at(i, 118);
          const anchor = Math.abs(lx - C.x) < 8 ? "middle" : lx > C.x ? "start" : "end";
          return (
            <g key={d}>
              <line className="spoke" x1={C.x} y1={C.y} x2={x} y2={y} />
              <text className="axis-label" x={lx} y={ly + (ly > C.y + 8 ? 12 : ly < C.y - 8 ? -4 - (lines(dimension(d)).length - 1) * 14 : 4 - (lines(dimension(d)).length - 1) * 7)} textAnchor={anchor}>
                {lines(dimension(d)).map((l, k) => <tspan key={k} x={lx} dy={k ? 14 : 0}>{l}</tspan>)}
              </text>
            </g>
          );
        })}
        {[...series].reverse().map((s) => (
          <g key={s.label} className={`series-${s.tone}`}>
            <polygon className="area" points={shape(s.values)} />
            {axes.map((d, i) => {
              const [x, y] = at(i, s.values[d] ?? 0);
              return <circle key={d} className="dot" cx={x} cy={y} r={s.tone === "main" ? 5 : 3.5}>
                <title>{`${s.label} · ${dimension(d)} : ${s.values[d] == null ? "non mesuré" : Math.round(s.values[d]!)}`}</title>
              </circle>;
            })}
          </g>
        ))}
      </svg>
      {series.length > 1 && (
        <ul className="legend">
          {series.map((s) => <li key={s.label}><span className={`swatch swatch-${s.tone}`} aria-hidden="true" />{s.label}</li>)}
        </ul>
      )}
    </figure>
  );
}
