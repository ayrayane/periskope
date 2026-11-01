// Table helpers: sortable column headers that announce their state (aria-sort), and a status filter that shows its counts.
import { useState } from "react";

export type SortState<K extends string> = { key: K; dir: "asc" | "desc" };

export function useSort<K extends string>(initial: SortState<K>) {
  const [sort, setSort] = useState(initial);
  const toggle = (key: K) => setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" }));
  return { sort, toggle };
}

/** Compares two rows on the sorted column, ties broken by the given fallback so the order is always stable. */
export function compareBy<T, K extends string>(sort: SortState<K>, value: (row: T, key: K) => string | number, tie: (a: T, b: T) => number) {
  return (a: T, b: T) => {
    const x = value(a, sort.key), y = value(b, sort.key);
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), "fr");
    return (sort.dir === "asc" ? c : -c) || tie(a, b);
  };
}

export function SortTh<K extends string>({ k, label, sort, onSort, className }: { k: K; label: string; sort: SortState<K>; onSort: (k: K) => void; className?: string }) {
  const active = sort.key === k;
  return (
    <th scope="col" className={className} aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
      <button type="button" className="th-sort" onClick={() => onSort(k)}>
        {label}<span className="th-arrow" aria-hidden="true">{active ? (sort.dir === "asc" ? "↑" : "↓") : "↕"}</span>
      </button>
    </th>
  );
}

export function StatusFilter<V extends string>({ label, options, value, onChange }: {
  label: string; options: { value: V; label: string; count: number; tone?: string }[]; value: V; onChange: (v: V) => void;
}) {
  return (
    <div className="status-filter" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={value === o.value} className={o.tone ? `sf-${o.tone}` : undefined} onClick={() => onChange(o.value)}>
          {o.label} <span className="sf-count">{o.count}</span>
        </button>
      ))}
    </div>
  );
}
