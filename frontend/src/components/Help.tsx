// Plain-language definitions next to the words people stumble on. One glossary, so a term always means the same thing.
import { useEffect, useId, useRef, useState } from "react";

export const GLOSSARY = {
  score: "Part des pratiques DevSecOps (référentiel DSOMM) en place jusqu'au niveau cible du projet. 100 = niveau cible atteint. Une pratique partielle compte pour moitié ; ce qui n'a pas pu être mesuré ne fait pas baisser le score.",
  couverture: "Part des pratiques que Periskope a réussi à mesurer. Une couverture basse veut dire que le score repose sur peu d'éléments : il manque une source (SonarQube, rapports CI…).",
  cible: "Niveau DSOMM (1 à 5) que le projet doit atteindre. Seules les pratiques jusqu'à ce niveau comptent dans le score.",
  activite: "Une pratique DevSecOps du référentiel OWASP DSOMM, par exemple « branche protégée » ou « scan de secrets ». Chacune a un niveau de 1 (base) à 5 (avancé).",
  preuve: "Un contrôle automatique que Periskope fait dans GitLab, le dépôt ou SonarQube. Les preuves décident si une pratique est en place.",
  statuts: "En place : toutes les preuves sont réunies. Partielle : une partie seulement. Absente : aucune. Indéterminée : impossible à vérifier (source muette). Sans objet : ne concerne pas ce projet. Écartée : retirée du périmètre par un administrateur.",
  chiffres: "Le score (sur 100) dit quelle part des pratiques attendues jusqu'au niveau cible est en place : 100 = niveau cible atteint. La couverture dit quelle part Periskope a pu vérifier : basse, le score repose sur peu d'éléments.",
} as const;

export function Help({ term, label }: { term: keyof typeof GLOSSARY; label?: string }) {
  const [open, setOpen] = useState(false);
  const [at, setAt] = useState({ top: 0, left: 0 });
  const id = useId();
  const box = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !box.current?.contains(e.target as Node)) setOpen(false);
    };
    const hide = () => setOpen(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    window.addEventListener("scroll", hide, true);
    return () => { document.removeEventListener("mousedown", close); document.removeEventListener("keydown", close); window.removeEventListener("scroll", hide, true); };
  }, [open]);
  return (
    <span className="help" ref={box}>
      <button type="button" className="help-btn" aria-expanded={open} aria-controls={id} onClick={(e) => {
        // Fixed and kept inside the viewport: never clipped by a card, never widening the page.
        const r = e.currentTarget.getBoundingClientRect(), w = Math.min(320, window.innerWidth * 0.8);
        setAt({ top: r.bottom + 8, left: Math.max(8, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 8)) });
        setOpen(!open);
      }}>
        <span aria-hidden="true">?</span><span className="sr-only">Qu'est-ce que {label ?? term} ?</span>
      </button>
      {open && <span id={id} role="note" className="help-pop" style={at}>{GLOSSARY[term]}</span>}
    </span>
  );
}
