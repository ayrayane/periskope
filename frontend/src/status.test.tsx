import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { projectUrl } from "./api";
import { ActivityBadge, CheckBadge, Score } from "./components/status";

test("unknown is never displayed as a failure", () => {
  render(<><CheckBadge status="unknown" /><ActivityBadge status="unknown" /></>);
  for (const el of screen.getAllByText(/Indéterminée/)) {
    expect(el.className).toContain("tone-unknown");
    expect(el.className).not.toContain("tone-fail");
  }
});

test("score always shows its coverage", () => {
  render(<Score score={40} coverage={50} />);
  expect(screen.getByText(/couverture 50 %/)).toBeTruthy();
});

test("project paths keep their slashes, segments are encoded", () => {
  expect(projectUrl("gl-prod", "team/a b/api")).toBe("/projects/gl-prod/team/a%20b/api");
});
