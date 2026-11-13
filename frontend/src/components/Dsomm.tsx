// The five DSOMM families (dimensions): one outline icon and one colour each, the same on the profile and on the absent practices.
// Colours are the validated categorical palette (fixed order, CVD-checked, light and dark); the family's name is always written beside.
import { dimension } from "../labels";

const PATHS: Record<string, string[]> = {
  // A package: what is built and shipped.
  "Build and Deployment": ["M12 3 3.5 7.5v9L12 21l8.5-4.5v-9L12 3Z", "M3.5 7.5 12 12l8.5-4.5", "M12 12v9"],
  // People: teams, roles, training.
  "Culture and Organization": ["M9 11.2a3.2 3.2 0 1 0 0-6.4 3.2 3.2 0 0 0 0 6.4Z", "M3 19.5c.8-3.2 3.2-5 6-5s5.2 1.8 6 5", "M15.6 5a3.2 3.2 0 0 1 0 6", "M17.4 14.6c1.8.6 3 2.2 3.6 4.9"],
  // Code: how the software is written.
  "Implementation": ["m8.5 7-5 5 5 5", "m15.5 7 5 5-5 5", "m13.5 4.5-3 15"],
  // A magnifier: knowing what is there (inventory, metrics, threats).
  "Information Gathering": ["M10.5 16.5a6 6 0 1 0 0-12 6 6 0 0 0 0 12Z", "m15 15 5.5 5.5"],
  // A shield with a check: testing and verifying.
  "Test and Verification": ["M12 3 4.5 6v5.5c0 4.6 3.1 8.3 7.5 9.5 4.4-1.2 7.5-4.9 7.5-9.5V6L12 3Z", "m8.8 12.2 2.3 2.3 4.3-4.6"],
};
export const FAMILIES = Object.keys(PATHS);

/** The family's slot (1–5) in the categorical palette: alphabetical, as the profile's axes. */
export const familySlot = (dim: string) => FAMILIES.indexOf(dim) + 1 || 6;

/** The family icon in its tinted tile; decorative, the family name is written next to it. */
export function FamilyIcon({ dim, size = 36 }: { dim: string; size?: number }) {
  return (
    <span className={`fam-tile fam-${familySlot(dim)}`} style={{ width: size, height: size }} aria-hidden="true" title={dimension(dim)}>
      <svg viewBox="0 0 24 24" width={Math.round(size * 0.56)} height={Math.round(size * 0.56)} fill="none" stroke="currentColor"
        strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
        {(PATHS[dim] ?? ["M12 8v5", "M12 16.5h.01", "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z"]).map((d) => <path key={d} d={d} />)}
      </svg>
    </span>
  );
}
