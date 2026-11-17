// GitLab rights are read by a collector, which can take a few seconds at sign-in: the pages wait for them.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ReactNode, useEffect, useState } from "react";
import { meQuery } from "./api";

// How long the pages wait before showing what is already known, with a notice.
const PATIENCE_MS = 15_000;

export function RequireRights({ children }: { children: ReactNode }) {
  const queries = useQueryClient();
  // Once shown, the pages stay: rights read again later bring a notice, never a blank page over unsaved input.
  const [open, setOpen] = useState(false);
  const me = useQuery({
    ...meQuery,
    refetchOnWindowFocus: true,
    // Often while the rights are being read; otherwise just enough for the server to renew them before they expire.
    refetchInterval: (q) => (!q.state.data?.pending?.length ? 240_000 : open ? 5000 : 1000),
  });
  const reading = !!me.data?.pending?.length;
  useEffect(() => {
    if (!reading) return;
    const timer = setTimeout(() => setOpen(true), PATIENCE_MS);
    return () => {
      clearTimeout(timer);
      // The rights are there: whatever was loaded without them is loaded again.
      void queries.invalidateQueries({ predicate: (q) => q.queryKey[0] !== "me" });
    };
  }, [reading, queries]);
  // Someone who reads everything is not held back: only what they may launch is still unknown.
  const held = me.isPending || (reading && !me.data?.reads_all);
  if (!open && !held) setOpen(true);
  if (!open && held) return <p className="page-status" role="status">{me.isPending ? "Connexion…" : "Lecture de vos droits GitLab, quelques secondes…"}</p>;
  return <>{children}</>;
}
