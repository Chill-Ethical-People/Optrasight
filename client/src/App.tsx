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
import { ActiveScansProvider } from "@/lib/activeScans";
import Login from "@/pages/Login";
import Overview from "@/pages/Overview";
import Findings from "@/pages/Findings";
import Lookalikes from "@/pages/Lookalikes";
import Assets from "@/pages/Assets";
import Scans from "@/pages/Scans";
import Evidence from "@/pages/Evidence";
import Integrations from "@/pages/Integrations";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";
import AISetup from "@/pages/AISetup";
import MaliciousSiteScanner from "@/pages/MaliciousSiteScanner";
import OsintMonitoring from "@/pages/OsintMonitoring";
import SourcesAnalytics from "@/pages/SourcesAnalytics";
import ThreatLandscape from "@/pages/ThreatLandscape";
import Investigations from "@/pages/Investigations";
import ThreatActors from "@/pages/ThreatActors";
import CoverageRadar from "@/pages/CoverageRadar";
import DetectionRules from "@/pages/DetectionRules";
import Exercises from "@/pages/Exercises";
import ExercisePortal from "@/pages/ExercisePortal";
import OperationsAudit from "@/pages/OperationsAudit";
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
  // Participant portal is public (magic-link token authenticates) and bypasses
  // the login wall + AppShell entirely.
  if (typeof window !== "undefined") {
    const hash = window.location.hash || "";
    if (hash.startsWith("#/exercise/")) return <ExercisePortal />;
  }
  if (!user) return <Login />;
  if (BATCH_ONE_RELEASE && typeof window !== "undefined") {
    const hash = window.location.hash || "#/";
    const rawPath = hash.startsWith("#") ? hash.slice(1) : hash;
    const hashPath = stripHashQuery(rawPath);
    if (!BATCH_ONE_ALLOWED_PATHS.has(hashPath)) {
      window.location.hash = "#/osint";
      return <OsintMonitoring />;
    }
  }
  // Keep hash-query deep links route-safe. Wouter's hash hook behavior can vary
  // across dev/prod builds, so known app routes with query params are rendered
  // directly before the catch-all NotFound route can see them.
  if (typeof window !== "undefined") {
    const hash = window.location.hash || "";
    const rawPath = hash.startsWith("#") ? hash.slice(1) : hash;
    const hashPath = stripHashQuery(rawPath);
    if (hash.includes("?")) {
      switch (hashPath) {
        case "/intel":
        case "/osint":
          return <OsintMonitoring />;
        case "/findings":
          return <Findings />;
        case "/malicious-site-scanner":
        case "/young-domains":
          return <MaliciousSiteScanner />;
        case "/detection-rules":
          return <DetectionRules />;
        case "/investigations":
          return <Investigations />;
        case "/coverage-radar":
          return <CoverageRadar />;
        case "/threat-actors":
          return <ThreatActors />;
        case "/exercises":
          return <Exercises />;
        case "/operations-audit":
          return <OperationsAudit />;
      }
    }
    if (hashPath.startsWith("/investigations/")) return <Investigations />;
    if (hashPath.startsWith("/detection-rules/")) return <DetectionRules />;
  }
  return (
    <Switch>
      <Route path="/" component={BATCH_ONE_RELEASE ? OsintMonitoring : Overview} />
      <Route path="/osint" component={OsintMonitoring} />
      <Route path="/threat-actors" component={ThreatActors} />
      <Route path="/ai-setup" component={AISetup} />
      <Route path="/operations-audit" component={OperationsAudit} />
      {!BATCH_ONE_RELEASE && <Route path="/findings" component={Findings} />}
      {!BATCH_ONE_RELEASE && <Route path="/lookalikes" component={Lookalikes} />}
      {!BATCH_ONE_RELEASE && <Route path="/assets" component={Assets} />}
      {!BATCH_ONE_RELEASE && <Route path="/scans" component={Scans} />}
      {!BATCH_ONE_RELEASE && <Route path="/evidence" component={Evidence} />}
      {!BATCH_ONE_RELEASE && <Route path="/integrations" component={Integrations} />}
      {!BATCH_ONE_RELEASE && <Route path="/reports" component={Reports} />}
      {!BATCH_ONE_RELEASE && <Route path="/malicious-site-scanner" component={MaliciousSiteScanner} />}
      {!BATCH_ONE_RELEASE && <Route path="/young-domains" component={MaliciousSiteScanner} />}
      {!BATCH_ONE_RELEASE && <Route path="/detection-rules/:technique" component={DetectionRules} />}
      {!BATCH_ONE_RELEASE && <Route path="/detection-rules" component={DetectionRules} />}
      {!BATCH_ONE_RELEASE && <Route path="/sources-analytics" component={SourcesAnalytics} />}
      {!BATCH_ONE_RELEASE && <Route path="/threat-landscape" component={ThreatLandscape} />}
      {!BATCH_ONE_RELEASE && <Route path="/investigations/:caseId" component={Investigations} />}
      {!BATCH_ONE_RELEASE && <Route path="/investigations" component={Investigations} />}
      {!BATCH_ONE_RELEASE && <Route path="/coverage-radar" component={CoverageRadar} />}
      {!BATCH_ONE_RELEASE && <Route path="/exercises" component={Exercises} />}
      {!BATCH_ONE_RELEASE && <Route path="/exercise/:token" component={ExercisePortal} />}
      {!BATCH_ONE_RELEASE && <Route path="/settings" component={Settings} />}
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
              <ActiveScansProvider>
                <WarmDataCache />
                <Router hook={useHashLocationWithoutQuery}>
                  <ProtectedRoutes />
                </Router>
                <Toaster />
              </ActiveScansProvider>
            </AiJobsProvider>
          </AuthProvider>
        </TooltipProvider>
      </UiStateProvider>
    </QueryClientProvider>
  );
}
