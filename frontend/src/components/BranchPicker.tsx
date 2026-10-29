// Branch picker: the repository's real branches, read once when the field is first used, filtered locally.
// An unknown branch is said at once and blocks the launch: never a silent run on the reference branch.
import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { api, Branch } from "../api";

export default function BranchPicker({ url, value, onChange }: { url: string; value: string; onChange: (branch: string | null, invalid: boolean) => void }) {
  const [text, setText] = useState(value);
  const [used, setUsed] = useState(false);
  const id = useId();
  const branches = useQuery({ queryKey: ["branches", url], queryFn: () => api<Branch[]>(`${url}/branches`), enabled: used, staleTime: 60_000 });
  const names = new Set(branches.data?.map((b) => b.name));
  const invalid = !!branches.data && text !== "" && !names.has(text);

  const update = (next: string) => {
    setText(next);
    const known = names.has(next) || next === value;
    onChange(known ? next : null, !!branches.data && next !== "" && !known);
  };
  return (
    <div className="branch-picker">
      <label htmlFor={id} className="small muted">Branche</label>
      <input id={id} list={`${id}-list`} value={text} autoComplete="off" spellCheck={false}
        onFocus={() => setUsed(true)} onChange={(e) => update(e.target.value)}
        aria-invalid={invalid} aria-describedby={invalid || branches.isError ? `${id}-msg` : undefined} />
      <datalist id={`${id}-list`}>
        {branches.data?.map((b) => <option key={b.name} value={b.name}>{b.default ? "branche de référence" : b.protected ? "protégée" : ""}</option>)}
      </datalist>
      {invalid && <span id={`${id}-msg`} className="error small">Branche inconnue dans GitLab</span>}
      {branches.isError && <span id={`${id}-msg`} className="error small">{(branches.error as Error).message}</span>}
    </div>
  );
}
