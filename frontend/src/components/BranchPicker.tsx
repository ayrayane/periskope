// Branch picker: the repository's real branches (searchable), reference branch first. Launching on one opens its analysis.
import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { api, Branch } from "../api";

export default function BranchPicker({ url, value, onChange }: { url: string; value: string; onChange: (b: string) => void }) {
  const [q, setQ] = useState("");
  const id = useId();
  const branches = useQuery({
    queryKey: ["branches", url, q],
    queryFn: () => api<Branch[]>(`${url}/branches${q ? `?q=${encodeURIComponent(q)}` : ""}`),
    staleTime: 60_000,
  });
  return (
    <div className="branch-picker">
      <label htmlFor={id} className="small muted">Branche</label>
      <input id={id} list={`${id}-list`} value={q || value} placeholder="Rechercher une branche" autoComplete="off"
        onChange={(e) => { setQ(e.target.value); if (branches.data?.some((b) => b.name === e.target.value)) onChange(e.target.value); }}
        onBlur={() => setQ("")} />
      <datalist id={`${id}-list`}>
        {branches.data?.map((b) => <option key={b.name} value={b.name}>{b.default ? "branche de référence" : b.protected ? "protégée" : ""}</option>)}
      </datalist>
      {branches.isError && <span className="error small">{(branches.error as Error).message}</span>}
    </div>
  );
}
