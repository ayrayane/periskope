// How to fix a check: numbered steps, a snippet to copy into the named file, and the official docs. Closed by default.
import { useState } from "react";
import type { Fix } from "../api";

export default function FixGuide({ fix, open = false }: { fix: Fix | null | undefined; open?: boolean }) {
  const [copied, setCopied] = useState(false);
  if (!fix) return null;
  const copy = () => navigator.clipboard?.writeText(fix.snippet!.code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); });
  return (
    <details className="fix" open={open}>
      <summary>Comment corriger</summary>
      {fix.tier && <p className="fix-tier">Nécessite GitLab {fix.tier}</p>}
      <ol className="fix-steps">{fix.steps.map((s) => <li key={s}>{s}</li>)}</ol>
      {fix.snippet && (
        <div className="snippet">
          <div className="snippet-head">
            <span className="mono">{fix.snippet.file}</span>
            {navigator.clipboard && <button type="button" className="secondary" onClick={copy}>{copied ? "Copié" : "Copier"}</button>}
          </div>
          <pre><code>{fix.snippet.code}</code></pre>
        </div>
      )}
      <ul className="fix-docs">
        {fix.docs.map((d) => <li key={d.url}><a href={d.url} target="_blank" rel="noreferrer">{d.title}<span className="sr-only"> (nouvel onglet)</span> ↗</a></li>)}
      </ul>
    </details>
  );
}
