// Navigation by GitLab instance, then group and subgroup, as GitLab itself nests them. Counts and scores roll up to parents.
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Group, Instance } from "../api";

type Node = { path: string; name: string; projects: number; analysed: number; sum: number; children: Map<string, Node> };

export const scopeUrl = (instance?: string, namespace?: string) => {
  const q = new URLSearchParams();
  if (instance) q.set("instance", instance);
  if (namespace) q.set("namespace", namespace);
  return q.size ? `/?${q}` : "/";
};

/** One tree per instance; a group without projects of its own still appears when a subgroup has some. */
export function buildTree(groups: Group[], instance: string): Node {
  const root: Node = { path: "", name: instance, projects: 0, analysed: 0, sum: 0, children: new Map() };
  for (const g of groups.filter((x) => x.instance === instance)) {
    let node = root;
    const add = (n: Node) => { n.projects += g.projects; n.analysed += g.analysed; n.sum += g.score_sum; };
    add(root);
    g.path.split("/").forEach((seg, i, all) => {
      const path = all.slice(0, i + 1).join("/");
      if (!node.children.has(seg)) node.children.set(seg, { path, name: seg, projects: 0, analysed: 0, sum: 0, children: new Map() });
      node = node.children.get(seg)!;
      add(node);
    });
  }
  return root;
}

function ScoreChip({ n }: { n: Node }) {
  if (!n.analysed) return <span className="nav-score muted" title="Aucun projet analysé">—</span>;
  const v = Math.round(n.sum / n.analysed);
  return <span className={`nav-score band-${v >= 75 ? "high" : v >= 50 ? "mid" : "low"}`} title={`Score moyen ${v}/100`}>{v}</span>;
}

export function useScopeData() {
  const instances = useQuery({ queryKey: ["instances"], queryFn: () => api<Instance[]>("/instances"), staleTime: 300_000 });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<Group[]>("/groups"), staleTime: 60_000 });
  return { instances: instances.data ?? [], groups: groups.data ?? [] };
}

export default function GroupNav({ instance, namespace }: { instance?: string; namespace?: string }) {
  const { instances, groups } = useScopeData();
  const [open, setOpen] = useState<Set<string>>(new Set());
  // The current group's ancestors open by themselves, so a shared link lands on a visible entry.
  useEffect(() => {
    if (!instance) return;
    const segs = namespace?.split("/") ?? [];
    setOpen((o) => new Set([...o, instance, ...segs.map((_, i) => `${instance}:${segs.slice(0, i + 1).join("/")}`)]));
  }, [instance, namespace]);
  const toggle = (k: string) => setOpen((o) => { const n = new Set(o); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const total = groups.reduce((a, g) => a + g.projects, 0);
  const visible = instances.filter((i) => groups.some((g) => g.instance === i.slug));

  const branch = (inst: string, n: Node, depth: number) => (
    <ul className="nav-tree" role="group">
      {[...n.children.values()].sort((a, b) => a.name.localeCompare(b.name)).map((c) => {
        const k = `${inst}:${c.path}`;
        const current = instance === inst && namespace === c.path;
        return (
          <li key={c.path}>
            <div className={`nav-row${current ? " current" : ""}`} style={{ paddingLeft: 8 + depth * 14 }}>
              {c.children.size > 0 ? (
                <button type="button" className="nav-toggle" aria-expanded={open.has(k)} aria-label={`${open.has(k) ? "Replier" : "Déplier"} ${c.name}`} onClick={() => toggle(k)}>›</button>
              ) : <span className="nav-toggle" aria-hidden="true" />}
              <Link to={scopeUrl(inst, c.path)} aria-current={current ? "page" : undefined} title={c.path}>{c.name}</Link>
              <span className="nav-count" title={`${c.projects} projet${c.projects > 1 ? "s" : ""}`}>{c.projects}</span>
              <ScoreChip n={c} />
            </div>
            {open.has(k) && c.children.size > 0 && branch(inst, c, depth + 1)}
          </li>
        );
      })}
    </ul>
  );

  return (
    <nav className="group-nav" aria-label="Instances et groupes GitLab">
      <Link to="/" className={`nav-all${!instance ? " current" : ""}`} aria-current={!instance ? "page" : undefined}>
        Toutes les instances <span className="nav-count">{total}</span>
      </Link>
      {visible.map((i) => {
        const tree = buildTree(groups, i.slug);
        const current = instance === i.slug && !namespace;
        return (
          <div key={i.slug} className="nav-instance">
            <div className={`nav-row nav-inst-row${current ? " current" : ""}`}>
              <button type="button" className="nav-toggle" aria-expanded={open.has(i.slug)} aria-label={`${open.has(i.slug) ? "Replier" : "Déplier"} ${i.name}`} onClick={() => toggle(i.slug)}>›</button>
              <Link to={scopeUrl(i.slug)} aria-current={current ? "page" : undefined}>
                <span className="nav-inst-name">{i.name}</span>
                <span className="nav-host">{new URL(i.url).host}</span>
              </Link>
              <ScoreChip n={tree} />
            </div>
            {open.has(i.slug) && branch(i.slug, tree, 1)}
          </div>
        );
      })}
    </nav>
  );
}

/** Tableau de bord › instance › group › subgroup, each a link to that scope; the last item is the current page. */
export function ScopeCrumbs({ instance, namespace, instances, tail }: { instance?: string; namespace?: string; instances: Instance[]; tail?: React.ReactNode }) {
  const segs = namespace?.split("/") ?? [];
  const inst = instances.find((i) => i.slug === instance);
  return (
    <nav className="crumbs" aria-label="Fil d'Ariane">
      <Link to="/">Tableau de bord</Link>
      {instance && <> <span aria-hidden="true">›</span> <Link to={scopeUrl(instance)}>{inst?.name ?? instance}</Link></>}
      {segs.map((s, i) => <span key={i}> <span aria-hidden="true">›</span> <Link to={scopeUrl(instance, segs.slice(0, i + 1).join("/"))}>{s}</Link></span>)}
      {tail && <> <span aria-hidden="true">›</span> {tail}</>}
    </nav>
  );
}
