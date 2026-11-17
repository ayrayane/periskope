import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import { api } from "./api";
import { RequireRights } from "./rights";

vi.mock("./auth", () => ({ userManager: async () => ({ getUser: async () => ({ access_token: "t" }) }) }));

// What the API answers, path by path: each list is served in order and its last entry is repeated.
function serve(answers: Record<string, unknown[]>) {
  vi.stubGlobal("fetch", async (url: string) => {
    const list = answers[url.replace("/api/v1", "")];
    return { ok: true, status: 200, json: async () => (list.length > 1 ? list.shift() : list[0]) };
  });
}

function Projects() {
  const projects = useQuery({ queryKey: ["projects"], queryFn: () => api<{ total: number }>("/projects") });
  return <p>{projects.data ? `projets : ${projects.data.total}` : "Chargement…"}</p>;
}

function page() {
  const client = new QueryClient();
  render(<QueryClientProvider client={client}><RequireRights><Projects /></RequireRights></QueryClientProvider>);
  return client;
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

test("the pages wait until the GitLab rights are read", async () => {
  serve({ "/me": [{ pending: ["gl"] }, { pending: [] }], "/projects": [{ total: 2 }] });
  page();
  expect(await screen.findByText(/Lecture de vos droits GitLab/)).toBeTruthy();
  // Nothing is asked without the rights: a first sign-in never shows an empty estate.
  expect(screen.queryByText(/projets/)).toBeNull();
  expect(await screen.findByText("projets : 2", {}, { timeout: 3000 })).toBeTruthy();
});

test("pages already shown stay, and load again once the rights are read", async () => {
  serve({ "/me": [{ pending: [] }, { pending: ["gl"] }, { pending: [] }], "/projects": [{ total: 1 }, { total: 2 }] });
  const client = page();
  // The pause lets the page draw each answer before the next one comes.
  const again = () => act(async () => {
    await client.refetchQueries({ queryKey: ["me"] });
    await new Promise((done) => setTimeout(done, 20));
  });
  expect(await screen.findByText("projets : 1")).toBeTruthy();
  // The rights expired and are read again: no blank page over what someone is doing.
  await again();
  expect(screen.getByText("projets : 1")).toBeTruthy();
  expect(screen.queryByText(/Lecture de vos droits GitLab/)).toBeNull();
  await again();
  expect(await screen.findByText("projets : 2")).toBeTruthy();
});

test("someone who reads everything is not held back", async () => {
  serve({ "/me": [{ reads_all: true, pending: ["gl"] }], "/projects": [{ total: 2 }] });
  page();
  expect(await screen.findByText("projets : 2")).toBeTruthy();
});

test("after fifteen seconds the pages open with what is known", async () => {
  vi.useFakeTimers();
  serve({ "/me": [{ pending: ["gl"] }], "/projects": [{ total: 0 }] });
  page();
  // React draws at the end of each step: the first one shows the wait, from which the fifteen seconds run.
  const pass = (ms: number) => act(() => vi.advanceTimersByTimeAsync(ms));
  await pass(100);
  await pass(14_000);
  expect(screen.getByText(/Lecture de vos droits GitLab/)).toBeTruthy();
  await pass(1500);
  await pass(100);
  expect(screen.getByText("projets : 0")).toBeTruthy();
});
