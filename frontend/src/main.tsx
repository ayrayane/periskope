import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { lazy, StrictMode, Suspense, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource-variable/plus-jakarta-sans";
import { BrowserRouter, Link, MemoryRouter, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { api, ApiError, Me } from "./api";
import { Callback, RequireAuth, useUser, userManager } from "./auth";
import Portfolio from "./pages/Portfolio";
import Project from "./pages/Project";
import Run from "./pages/Run";
import ScopePage from "./pages/Scope";


// The admin screen is for a few people: loaded only when opened.
const Admin = lazy(() => import("./pages/Admin"));
const Report = lazy(() => import("./pages/Report"));
import "./styles.css";

const queries = new QueryClient({
  defaultOptions: { queries: { retry: (n, e) => n < 2 && !(e instanceof ApiError && e.status < 500), refetchOnWindowFocus: false } },
});

function Shell() {
  const user = useUser();
  const me = useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/me"), staleTime: 60_000 });
  const { pathname } = useLocation();
  // After a navigation, focus and the tab title follow the new page's heading, for keyboard and screen-reader users.
  const firstPage = useRef(true);
  useEffect(() => {
    const id = setTimeout(() => {
      const h1 = document.querySelector<HTMLElement>("main h1");
      document.title = h1?.textContent ? `${h1.textContent} · Periskope` : "Periskope";
      // Not on the first page: keyboard users start from the skip link, the menu and the GitLab panel.
      if (!firstPage.current && h1 && document.activeElement !== h1 && !document.activeElement?.closest("main")) h1.focus();
      firstPage.current = false;
    }, 300);
    return () => clearTimeout(id);
  }, [pathname]);
  return (
    <>
      <a className="skip" href="#main">Aller au contenu</a>
      <header className="top">
        <Link to="/" className="brand"><img src="/favicon.svg" alt="" width="24" height="24" /> Periskope</Link>
        <nav aria-label="Navigation principale" className="pill-nav">
          <Link to="/" aria-current={pathname === "/" || pathname.startsWith("/p/") || pathname.startsWith("/r/") ? "page" : undefined}>Tableau de bord</Link>
          {me.data?.admin && <><NavLink to="/cadrage">Cadrage</NavLink><NavLink to="/admin">Administration</NavLink></>}
        </nav>
        <div className="user">
          <span className="small">{user?.profile.preferred_username}</span>
          {import.meta.env.VITE_DEMO === "1" ? <span className="small muted">données fictives</span>
            : <button type="button" className="link" onClick={() => userManager().then((m) => m.signoutRedirect())}>Se déconnecter</button>}
        </div>
      </header>
      <main id="main">
        <Suspense fallback={<p className="page-status" role="status">Chargement…</p>}>
        <Routes>
          <Route path="/" element={<Portfolio />} />
          <Route path="/p/:instance/*" element={<Project />} />
          <Route path="/r/:id" element={<Run />} />
          <Route path="/cadrage" element={<ScopePage />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/rapport" element={<Report />} />
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
          <Route path="*" element={<RequireAuth><Shell /></RequireAuth>} />
        </Routes>
      </Router>
    </QueryClientProvider>
  </StrictMode>,
);
