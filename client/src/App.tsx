import { Switch, Route, Router } from "wouter";
import { useHashLocation } from "wouter/use-hash-location";
import { QueryClientProvider } from "@tanstack/react-query";
import { useEffect } from "react";
import { queryClient } from "@/lib/queryClient";
import { warmExistingIntelCache, type WarmExistingIntelScope } from "@/lib/warmCache";
import { BATCH_ONE_RELEASE, BATCH_ONE_ALLOWED_PATHS } from "@/lib/release";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/lib/auth";
import { UiStateProvider } from "@/lib/uiState";
import { AiJobsProvider } from "@/lib/aiJobs";
import Login from "@/pages/Login";
import AccountSecuritySetup from "@/pages/AccountSecuritySetup";
import AISetup from "@/pages/AISetup";
import OsintMonitoring from "@/pages/OsintMonitoring";
import ThreatActors from "@/pages/ThreatActors";
import OperationsAudit from "@/pages/OperationsAudit";
import PlatformUsers from "@/pages/PlatformUsers";
import NotFound from "@/pages/not-found";

function stripHashQuery(path: string) {
  const qix = path.indexOf("?");
  return qix >= 0 ? path.slice(0, qix) || "/" : path || "/";
}

function useHashLocationWithoutQuery() {
  const [location, navigate] = useHashLocation();
  return [stripHashQuery(location), navigate] as const;
}

function ProtectedRoutes() {
  const { user } = useAuth();
  if (!user) return <Login />;
  if (user.passwordMustChange || !(user.mfaEnabled && user.mfaVerifiedAt)) return <AccountSecuritySetup />;
  const reviewOnly = user.access_mode === "guest" || user.role === "reviewer";
  if (BATCH_ONE_RELEASE && typeof window !== "undefined") {
    const hash = window.location.hash || "#/";
    const rawPath = hash.startsWith("#") ? hash.slice(1) : hash;
    const hashPath = stripHashQuery(rawPath);
    if (reviewOnly && !["/", "/osint", "/intel", "/threat-actors"].includes(hashPath)) {
      window.location.hash = "#/osint";
      return <OsintMonitoring />;
    }
    if (!BATCH_ONE_ALLOWED_PATHS.has(hashPath)) {
      window.location.hash = "#/osint";
      return <OsintMonitoring />;
    }
  }
  // Keep BatchOne hash-query deep links route-safe. Wouter's hash hook behavior
  // can vary across dev/prod builds, so known release routes with query params
  // are rendered directly before the catch-all NotFound route can see them.
  if (typeof window !== "undefined") {
    const hash = window.location.hash || "";
    const rawPath = hash.startsWith("#") ? hash.slice(1) : hash;
    const hashPath = stripHashQuery(rawPath);
    if (hash.includes("?")) {
      switch (hashPath) {
        case "/intel":
        case "/osint":
          return <OsintMonitoring />;
        case "/threat-actors":
          return <ThreatActors />;
        case "/ai-setup":
          return reviewOnly ? <OsintMonitoring /> : <AISetup />;
        case "/operations-audit":
          return reviewOnly ? <OsintMonitoring /> : <OperationsAudit />;
        case "/platform-users":
          return user.role === "admin" ? <PlatformUsers /> : <OsintMonitoring />;
      }
    }
  }
  return (
    <Switch>
      <Route path="/" component={OsintMonitoring} />
      <Route path="/osint" component={OsintMonitoring} />
      <Route path="/threat-actors" component={ThreatActors} />
      <Route path="/ai-setup">{reviewOnly ? <OsintMonitoring /> : <AISetup />}</Route>
      <Route path="/operations-audit">{reviewOnly ? <OsintMonitoring /> : <OperationsAudit />}</Route>
      <Route path="/platform-users">{user.role === "admin" ? <PlatformUsers /> : <OsintMonitoring />}</Route>
      <Route component={NotFound} />
    </Switch>
  );
}

function WarmDataCache() {
  const { user, activeTenantId } = useAuth();

  useEffect(() => {
    if (!user) return;
    const timers: number[] = [];
    const idleCallbacks: number[] = [];
    let cancelled = false;
    const win = window as Window & typeof globalThis & {
      requestIdleCallback?: (
        callback: IdleRequestCallback,
        options?: IdleRequestOptions,
      ) => number;
      cancelIdleCallback?: (handle: number) => void;
    };
    const hash = window.location.hash || "";
    const currentScope: WarmExistingIntelScope = hash.startsWith("#/osint") || hash.startsWith("#/intel")
      ? "osint"
      : hash.startsWith("#/threat-actors")
        ? "tap"
        : "startup";
    const warm = (scope: WarmExistingIntelScope) => {
      if (cancelled) return;
      warmExistingIntelCache(scope).catch(() => { /* page-level queries surface errors when opened */ });
    };
    const scheduleWarm = (scope: WarmExistingIntelScope, delayMs: number, idleTimeoutMs: number) => {
      const timer = window.setTimeout(() => {
        if (cancelled) return;
        if (win.requestIdleCallback) {
          const handle = win.requestIdleCallback(() => warm(scope), { timeout: idleTimeoutMs });
          idleCallbacks.push(handle);
          return;
        }
        warm(scope);
      }, delayMs);
      timers.push(timer);
    };

    scheduleWarm(currentScope, currentScope === "startup" ? 1_200 : 250, 2_000);
    if (currentScope !== "startup") scheduleWarm("startup", 1_800, 2_500);
    if (currentScope !== "osint") scheduleWarm("osint", 9_000, 4_000);

    return () => {
      cancelled = true;
      timers.forEach((timer) => window.clearTimeout(timer));
      idleCallbacks.forEach((handle) => win.cancelIdleCallback?.(handle));
    };
  }, [user?.id, activeTenantId]);

  return null;
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <UiStateProvider>
        <TooltipProvider delayDuration={150}>
          <AuthProvider>
            <AiJobsProvider>
              <WarmDataCache />
              <Router hook={useHashLocationWithoutQuery}>
                <ProtectedRoutes />
              </Router>
              <Toaster />
            </AiJobsProvider>
          </AuthProvider>
        </TooltipProvider>
      </UiStateProvider>
    </QueryClientProvider>
  );
}
