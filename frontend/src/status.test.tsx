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

test("absent practices carry their DSOMM family and filter by it", async () => {
  const { fireEvent } = await import("@testing-library/react");
  const { Gaps } = await import("./pages/Portfolio");
  const gap = (activity: string, dimension: string, missing: number) => ({ activity, dimension, level: 1, missing, measured: 10 });
  const { container } = render(<Gaps gaps={[gap("Defined build process", "Build and Deployment", 6), gap("A patch policy is defined", "Culture and Organization", 3),
    gap("Each team has a security champion", "Culture and Organization", 2)]} />);
  const rows = () => [...container.querySelectorAll(".fam-gaps li")];
  expect(rows().map((li) => li.className)).toEqual(["fam-1", "fam-2", "fam-2"]);
  // Icons are decorative: the family name is written in each row.
  expect(container.querySelectorAll(".fam-gaps .fam-tile[aria-hidden='true']").length).toBe(3);
  fireEvent.click(screen.getByRole("button", { name: /Culture et organisation/ }));
  expect(rows().length).toBe(2);
  expect(screen.getByRole("button", { name: /Culture et organisation/ }).getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(screen.getByRole("button", { name: /Toutes/ }));
  expect(rows().length).toBe(3);
});
