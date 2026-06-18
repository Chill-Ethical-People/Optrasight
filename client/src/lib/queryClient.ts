import { QueryClient, QueryFunction } from "@tanstack/react-query";
import { STATIC_DEMO_MODE, staticDemoRequest } from "./staticDemoApi";

const API_BASE = "__PORT_5000__".startsWith("__") ? "" : "__PORT_5000__";

/** Resolve a server-rooted asset URL (e.g. "/portraits/<id>.png") to a URL
 *  that works both locally (relative) and after deployment (proxied through
 *  the port-5000 prefix that `deploy_website` injects via __PORT_5000__).
 *  Returns null/undefined unchanged so callers can pass through optional fields. */
export function resolveAssetUrl(path: string | null | undefined): string | null | undefined {
  if (!path) return path;
  // Don't double-prefix absolute URLs.
  if (/^https?:\/\//i.test(path)) return path;
  // Don't double-prefix paths that already contain the deploy proxy prefix.
  if (API_BASE && path.startsWith(API_BASE)) return path;
  return `${API_BASE}${path.startsWith("/") ? "" : "/"}${path}`;
}

// Token holder kept outside React tree so apiRequest/getQueryFn can read it.
// Auth context updates it via setAuthToken / setOnUnauthorized.
let authToken: string | null = null;
let onUnauthorized: (() => void) | null = null;
export function setAuthToken(t: string | null) {
  authToken = t;
}
export function setOnUnauthorized(cb: (() => void) | null) {
  onUnauthorized = cb;
}
export function setActiveTenantId(_tid: string | null) {
  // BatchOne is a single-workspace release. Keep this no-op export so older
  // auth/UI code can call it without sending tenant override headers.
}

function authHeaders(extra: HeadersInit = {}): HeadersInit {
  const h: Record<string, string> = { ...(extra as Record<string, string>) };
  if (authToken) h.Authorization = `Bearer ${authToken}`;
  return h;
}

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    if (res.status === 401 && onUnauthorized) onUnauthorized();
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

export async function apiRequest(method: string, url: string, data?: unknown | undefined): Promise<Response> {
  if (STATIC_DEMO_MODE) {
    const demo = staticDemoRequest(method, url, data);
    if (demo) {
      await throwIfResNotOk(demo.clone());
      return demo;
    }
  }

  const res = await fetch(`${API_BASE}${url}`, {
    method,
    headers: authHeaders(data ? { "Content-Type": "application/json" } : {}),
    body: data ? JSON.stringify(data) : undefined,
  });

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: { on401: UnauthorizedBehavior }) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey }) => {
    const path = queryKey.filter((s) => s !== undefined && s !== null && s !== "").join("/");
    if (STATIC_DEMO_MODE) {
      const demo = staticDemoRequest("GET", path);
      if (demo) {
        if (unauthorizedBehavior === "returnNull" && demo.status === 401) return null;
        await throwIfResNotOk(demo.clone());
        return await demo.json();
      }
    }
    const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders() });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) return null;
    if (res.status === 401 && onUnauthorized) onUnauthorized();
    await throwIfResNotOk(res);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      retry: false,
    },
    mutations: { retry: false },
  },
});
