// Keycloak sign-in: Authorization Code + PKCE, tokens kept in session storage, renewed silently.
import { User, UserManager, WebStorageStateStore } from "oidc-client-ts";
import { createContext, ReactNode, useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

let manager: Promise<UserManager> | null = null;

export function userManager(): Promise<UserManager> {
  manager ??= fetch("/config.json")
    .then((r) => r.json())
    .then(
      (c: { authority: string; clientId: string }) =>
        new UserManager({
          authority: c.authority,
          client_id: c.clientId,
          redirect_uri: `${location.origin}/callback`,
          post_logout_redirect_uri: location.origin,
          response_type: "code",
          scope: "openid profile email",
          automaticSilentRenew: true,
          userStore: new WebStorageStateStore({ store: sessionStorage }),
        }),
    );
  return manager;
}

const UserContext = createContext<User | null>(null);
export const useUser = () => useContext(UserContext);

const DEMO_USER = { profile: { preferred_username: "démo" }, access_token: "", expired: false } as unknown as User;

export function RequireAuth({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null | undefined>(import.meta.env.VITE_DEMO === "1" ? DEMO_USER : undefined);
  useEffect(() => {
    if (import.meta.env.VITE_DEMO === "1") return;
    userManager().then(async (m) => {
      const u = await m.getUser();
      if (!u || u.expired) await m.signinRedirect({ state: location.pathname + location.search });
      else setUser(u);
    });
  }, []);
  if (!user) return <p className="page-status" role="status">Connexion…</p>;
  return <UserContext.Provider value={user}>{children}</UserContext.Provider>;
}

/** Where to go back after sign-in: a page of this site only. "//host" and "/\\host" are other sites to a browser. */
export function safeReturn(state: unknown): string {
  return typeof state === "string" && /^\/(?![/\\])[^\\]*$/.test(state) ? state : "/";
}

export function Callback() {
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    userManager()
      .then((m) => m.signinRedirectCallback())
      .then((u) => navigate(safeReturn(u.state), { replace: true }))
      .catch((e) => setError(String(e.message ?? e)));
  }, [navigate]);
  return error ? <p className="page-status error" role="alert">Connexion impossible : {error}</p> : <p className="page-status" role="status">Connexion…</p>;
}
