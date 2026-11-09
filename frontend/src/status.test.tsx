import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { projectUrl } from "./api";
import { safeReturn } from "./auth";
import { ActivityBadge, CheckBadge, PracticeCounts, Score } from "./components/status";

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

test("score chart needs two analyses and labels its range", async () => {
  const { MemoryRouter } = await import("react-router-dom");
  const { default: ScoreChart } = await import("./components/ScoreChart");
  const run = (id: number, score: number, day: number) => ({ id, branch: "main", commit_sha: "a", trigger: "nightly", requested_by: null,
    status: "succeeded" as const, created_at: `2026-10-${10 + day}T01:00:00Z`, finished_at: null, error: null, score, coverage: 80 });
  const { container } = render(<MemoryRouter><ScoreChart runs={[run(1, 40, 0), run(2, 55, 1), run(3, 61, 2)]} /></MemoryRouter>);
  expect(container.querySelector("svg")?.getAttribute("aria-label")).toBe("Score de 40 à 61 sur 3 analyses");
  expect(container.querySelectorAll("circle").length).toBe(3);
});

test("a score shows how many practices are absent, of how many expected", () => {
  render(<PracticeCounts p={{ done: 1, partial: 2, missing: 19, unknown: 1, counted: 23 }} />);
  expect(screen.getByText(/pratiques absentes sur 23 attendues/)).toBeTruthy();
  expect(screen.getByText(/1 en place/)).toBeTruthy();
  expect(screen.getByText(/2 partielles/)).toBeTruthy();
  expect(screen.getByText(/1 non vérifiée$/)).toBeTruthy();
});

test("sign-in only returns to a page of this site", () => {
  expect(safeReturn("/p/gl/team/app?vue=preuves")).toBe("/p/gl/team/app?vue=preuves");
  for (const evil of ["//evil.example", "/\\evil.example", "/x\\..\\evil", "https://evil.example", "evil", null, 42]) expect(safeReturn(evil)).toBe("/");
});
