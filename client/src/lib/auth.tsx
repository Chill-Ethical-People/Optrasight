import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { apiRequest, queryClient, setAuthToken, setOnUnauthorized, setActiveTenantId } from "./queryClient";

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  tenant: { id: string; name: string; slug: string; plan: string };
  passwordMustChange?: boolean;
  mfaEnabled?: boolean;
  mfaVerifiedAt?: string | null;
  access_mode?: "credentialed" | "guest";
  capabilities?: string[];
}

interface AuthCtx {
  user: AuthUser | null;
  loading: boolean;
  /** Active tenant id (admin only — for analyst this is always their own tenant). */
  activeTenantId: string | null;
  setActiveTenant: (tid: string | null) => void;
  login: (email: string, password: string, mfaCode?: string) => Promise<void>;
  refreshMe: () => Promise<AuthUser | null>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);
const HISTORY_AUTH_KEY = "__optrasightAuth";
let historyAuthPatchInstalled = false;

type HistoryAuthState = {
  [HISTORY_AUTH_KEY]?: {
    token?: string;
  };
};

function readHistoryAuthToken(): string | null {
  if (typeof window === "undefined") return null;
  const token = (window.history.state as HistoryAuthState | null)?.[HISTORY_AUTH_KEY]?.token;
  return typeof token === "string" && token.length > 0 ? token : null;
}

function writeHistoryAuthToken(token: string | null): void {
  if (typeof window === "undefined") return;
  const current = (window.history.state && typeof window.history.state === "object")
    ? { ...window.history.state }
    : {};
  if (token) {
    (current as HistoryAuthState)[HISTORY_AUTH_KEY] = { token };
  } else {
    delete (current as HistoryAuthState)[HISTORY_AUTH_KEY];
  }
  window.history.replaceState(current, "", window.location.href);
}

function patchHistoryAuthState(): void {
  if (typeof window === "undefined" || historyAuthPatchInstalled) return;
  historyAuthPatchInstalled = true;

  const mergeAuthState = (state: unknown): unknown => {
    const existingToken = readHistoryAuthToken();
    if (!existingToken) return state;
    const next = state && typeof state === "object" ? { ...(state as Record<string, unknown>) } : {};
    if (!(HISTORY_AUTH_KEY in next)) {
      (next as HistoryAuthState)[HISTORY_AUTH_KEY] = { token: existingToken };
    }
    return next;
  };

  const originalReplaceState = window.history.replaceState.bind(window.history);
  const originalPushState = window.history.pushState.bind(window.history);

  window.history.replaceState = (state: unknown, unused: string, url?: string | URL | null) => {
    originalReplaceState(mergeAuthState(state), unused, url);
  };
  window.history.pushState = (state: unknown, unused: string, url?: string | URL | null) => {
    originalPushState(mergeAuthState(state), unused, url);
  };
}

export function resolveSessionAccessMode(
  user: Partial<Pick<AuthUser, "access_mode">> | null | undefined,
  session: { accessMode?: "credentialed" | "guest"; access_mode?: "credentialed" | "guest" } | null | undefined,
  fallback: "credentialed" | "guest" = "credentialed",
): "credentialed" | "guest" {
  return user?.access_mode ?? session?.accessMode ?? session?.access_mode ?? fallback;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  patchHistoryAuthState();
  const [token, setTok] = useState<string | null>(() => readHistoryAuthToken());
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(() => !!readHistoryAuthToken());
  const [activeTid, setActiveTid] = useState<string | null>(null);

  // wire token holder used by queryClient
  useEffect(() => { setAuthToken(token); }, [token]);
  useEffect(() => { setActiveTenantId(activeTid); }, [activeTid]);

  // Rehydrate a still-valid server session after refresh or duplicated tab.
  // This deliberately avoids localStorage/sessionStorage/IndexedDB/cookies.
  useEffect(() => {
    const bootToken = readHistoryAuthToken();
    if (!bootToken) return;
    let cancelled = false;
    setAuthToken(bootToken);
    setLoading(true);
    apiRequest("GET", "/api/v1/me")
      .then((r) => r.json())
      .then((u: AuthUser) => {
        if (cancelled) return;
        setTok(bootToken);
        setUser(u);
        setActiveTid(u.tenant?.id ?? null);
      })
      .catch(() => {
        if (cancelled) return;
        writeHistoryAuthToken(null);
        setTok(null);
        setUser(null);
        setActiveTid(null);
        queryClient.clear();
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  // logout on 401
  useEffect(() => {
    setOnUnauthorized(() => {
      writeHistoryAuthToken(null);
      setTok(null);
      setUser(null);
      setActiveTid(null);
      queryClient.clear();
    });
    return () => setOnUnauthorized(null);
  }, []);

  const login = async (email: string, password: string, mfaCode?: string) => {
    setLoading(true);
    try {
      const r = await apiRequest("POST", "/api/v1/auth/login", { email, password, mfaCode });
      const data = await r.json();
      setTok(data.access_token);
      setAuthToken(data.access_token);
      writeHistoryAuthToken(data.access_token);
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

  const refreshMe = async () => {
    const me = await apiRequest("GET", "/api/v1/me");
    if (me.ok) {
      const u = await me.json();
      setUser(u);
      setActiveTid(u.tenant?.id ?? null);
      return u as AuthUser;
    }
    return null;
  };

  const logout = () => {
    if (token) {
      apiRequest("POST", "/api/v1/auth/logout", {}).catch(() => {});
    }
    writeHistoryAuthToken(null);
    setTok(null);
    setUser(null);
    setActiveTid(null);
    queryClient.clear();
  };

  const setActiveTenant = (tid: string | null) => {
    // BatchOne keeps this API shape for older components, but the query
    // client no longer sends tenant override headers.
    setActiveTenantId(tid);
    setActiveTid(tid);
    // Drop any tenant-scoped caches so views refetch with the new header.
    queryClient.invalidateQueries();
  };

  const value = useMemo(
    () => ({ user, loading, activeTenantId: activeTid, setActiveTenant, login, refreshMe, logout }),
    [user, loading, activeTid],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
