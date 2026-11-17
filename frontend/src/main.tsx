import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { lazy, StrictMode, Suspense, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/plus-jakarta-sans";
import { BrowserRouter, Link, MemoryRouter, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { ApiError, meQuery } from "./api";
import { Callback, RequireAuth, useUser, userManager } from "./auth";
import Portfolio from "./pages/Portfolio";
import Project from "./pages/Project";
import Run from "./pages/Run";
import ScopePage from "./pages/Scope";
import { RequireRights } from "./rights";

// The admin screen is for a few people: loaded only when opened.
const Admin = lazy(() => import("./pages/Admin"));
const Report = lazy(() => import("./pages/Report"));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities"));
const CveSheet = lazy(() => import("./pages/CveSheet"));
import "./styles.css";

const queries = new QueryClient({
  defaultOptions: { queries: { retry: (n, e) => n < 2 && !(e instanceof ApiError && e.status < 500), refetchOnWindowFocus: false } },
});

function Shell() {
  const user = useUser();
  const me = useQuery(meQuery);
  const { pathname } = useLocation();
  // After a navigation, focus and the tab title follow the new page's heading, for keyboard and screen-reader users.
  const firstPage = useRef(true);
  const titled = useRef<{ h1: Element | null; text: string | null }>({ h1: null, text: null });
  useEffect(() => {
    let tries = 0;
    const id = setInterval(() => {
      const h1 = document.querySelector<HTMLElement>("main h1");
      // A page still loading shows no heading, or the previous page's: wait for the new one, three seconds at most.
      if ((!h1 || (h1 === titled.current.h1 && h1.textContent === titled.current.text)) && ++tries < 30) return;
      clearInterval(id);
      titled.current = { h1, text: h1?.textContent ?? null };
      document.title = h1?.textContent ? `${h1.textContent} · Periskope` : "Periskope";
      // Not on the first page: keyboard users start from the skip link, the menu and the GitLab panel.
      if (!firstPage.current && h1 && document.activeElement !== h1 && !document.activeElement?.closest("main")) h1.focus();
      firstPage.current = false;
    }, 100);
    return () => clearInterval(id);
  }, [pathname]);
  return (
    <>
      <a className="skip" href="#main">Aller au contenu</a>
      <header className="top">
        <Link to="/" className="brand"><img src="/favicon.svg" alt="" width="24" height="24" /> Periskope</Link>
        <nav aria-label="Navigation principale" className="pill-nav">
          <Link to="/" aria-current={pathname === "/" || pathname === "/rapport" || pathname.startsWith("/p/") || pathname.startsWith("/r/") ? "page" : undefined}>Tableau de bord</Link>
          <NavLink to="/vulnerabilites">Vulnérabilités</NavLink>
          {me.data?.admin && <><NavLink to="/cadrage">Cadrage</NavLink><NavLink to="/admin">Administration</NavLink></>}
        </nav>
        <div className="user">
          <span className="small">{user?.profile.preferred_username}</span>
          {import.meta.env.VITE_DEMO === "1" ? <span className="small muted">données fictives</span>
            : <button type="button" className="link" onClick={() => userManager().then((m) => m.signoutRedirect())}>Se déconnecter</button>}
        </div>
      </header>
      <main id="main">
        {/* The pages are open although GitLab rights are still being read: see RequireRights. */}
        {!!me.data?.pending?.length && !me.data.reads_all && (
          <p className="banner" role="status">Vos droits GitLab ne sont pas encore lus sur {me.data.pending.join(", ")} : des projets peuvent manquer. Cette page se mettra à jour toute seule.</p>
        )}
        <Suspense fallback={<p className="page-status" role="status">Chargement…</p>}>
        <Routes>
          <Route path="/" element={<Portfolio />} />
          <Route path="/p/:instance/*" element={<Project />} />
          <Route path="/r/:id" element={<Run />} />
          <Route path="/cadrage" element={<ScopePage />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/rapport" element={<Report />} />
          <Route path="/vulnerabilites" element={<Vulnerabilities />} />
          <Route path="/vulnerabilites/cve/:key" element={<CveSheet />} />
          <Route path="*" element={<p className="empty">Page introuvable.</p>} />
        </Routes>
        </Suspense>
      </main>
    </>
  );
}

// The demo is published on a page that cannot change its own address: navigation stays in memory there.
const Router = import.meta.env.VITE_DEMO === "1" ? MemoryRouter : BrowserRouter;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queries}>
      <Router>
        <Routes>
          <Route path="/callback" element={<Callback />} />
          <Route path="*" element={<RequireAuth><RequireRights><Shell /></RequireRights></RequireAuth>} />
        </Routes>
      </Router>
    </QueryClientProvider>
  </StrictMode>,
);
