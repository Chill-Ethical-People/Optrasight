import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { apiRequest, queryClient, setAuthToken, setOnUnauthorized, setActiveTenantId } from "./queryClient";

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  tenant: { id: string; name: string; slug: string; plan: string };
}

interface AuthCtx {
  user: AuthUser | null;
  loading: boolean;
  /** Active tenant id (admin only — for analyst this is always their own tenant). */
  activeTenantId: string | null;
  setActiveTenant: (tid: string | null) => void;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setTok] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTid, setActiveTid] = useState<string | null>(null);

  // wire token holder used by queryClient
  useEffect(() => { setAuthToken(token); }, [token]);
  useEffect(() => { setActiveTenantId(activeTid); }, [activeTid]);

  // logout on 401
  useEffect(() => {
    setOnUnauthorized(() => {
      setTok(null);
      setUser(null);
      setActiveTid(null);
      queryClient.clear();
    });
    return () => setOnUnauthorized(null);
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const r = await apiRequest("POST", "/api/v1/auth/login", { email, password });
      const data = await r.json();
      setTok(data.access_token);
      setAuthToken(data.access_token);
      const me = await apiRequest("GET", "/api/v1/me");
      if (me.ok) {
        const u = await me.json();
        setUser(u);
        setActiveTid(u.tenant?.id ?? null);
      }
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    if (token) {
      apiRequest("POST", "/api/v1/auth/logout", {}).catch(() => {});
    }
    setTok(null);
    setUser(null);
    setActiveTid(null);
    queryClient.clear();
  };

  const setActiveTenant = (tid: string | null) => {
    // Update the queryClient header holder SYNCHRONOUSLY before invalidating —
    // otherwise the refetch fires with the previous tenant's X-Tenant-Id and
    // the UI receives stale data.
    setActiveTenantId(tid);
    setActiveTid(tid);
    // Drop any tenant-scoped caches so views refetch with the new header.
    queryClient.invalidateQueries();
  };

  const value = useMemo(
    () => ({ user, loading, activeTenantId: activeTid, setActiveTenant, login, logout }),
    [user, loading, activeTid],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
