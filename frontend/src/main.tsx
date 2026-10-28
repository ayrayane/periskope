import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, Route, Routes } from "react-router-dom";
import { ApiError } from "./api";
import { Callback, RequireAuth, useUser, userManager } from "./auth";
import Portfolio from "./pages/Portfolio";
import Project from "./pages/Project";
import "./styles.css";

const queries = new QueryClient({
  defaultOptions: { queries: { retry: (n, e) => n < 2 && !(e instanceof ApiError && e.status < 500), refetchOnWindowFocus: false } },
});

function Shell() {
  const user = useUser();
  return (
    <>
      <a className="skip" href="#main">Aller au contenu</a>
      <header className="top">
        <Link to="/" className="brand"><img src="/favicon.svg" alt="" width="24" height="24" /> Periskope</Link>
        <span className="muted small">{user?.profile.preferred_username}</span>
        <button type="button" className="link" onClick={() => userManager().then((m) => m.signoutRedirect())}>Se déconnecter</button>
      </header>
      <main id="main">
        <Routes>
          <Route path="/" element={<Portfolio />} />
          <Route path="/p/:instance/*" element={<Project />} />
          <Route path="*" element={<p className="empty">Page introuvable.</p>} />
        </Routes>
      </main>
    </>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queries}>
      <BrowserRouter>
        <Routes>
          <Route path="/callback" element={<Callback />} />
          <Route path="*" element={<RequireAuth><Shell /></RequireAuth>} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
