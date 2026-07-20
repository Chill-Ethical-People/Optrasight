import { useEffect, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Building2, Check, Loader2, ShieldCheck, UserRound } from "lucide-react";
import { AppShell, CreatorBrand } from "@/components/AppShell";
import { Logo } from "@/components/Logo";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/lib/auth";
import { apiRequest, queryClient } from "@/lib/queryClient";

type OperatingMode = "mss" | "individual";
const MIN_MODE_TRANSITION_MS = 700;

const MODES: Array<{
  id: OperatingMode;
  title: string;
  description: string;
  icon: typeof Building2;
  features: string[];
}> = [
  {
    id: "mss",
    title: "MSS mode",
    description: "For service providers managing threat intelligence and detection coverage across multiple clients.",
    icon: Building2,
    features: [
      "Client Profiles and semantic scope",
      "Client tagging across intelligence and rules",
      "Client Briefs and email delivery",
    ],
  },
  {
    id: "individual",
    title: "Individual mode",
    description: "For one internal security team operating a single workspace without client-management workflows.",
    icon: UserRound,
    features: ["Intel Inbox and analyst assessment", "Threat actor analysis", "Workspace-scoped detection engineering"],
  },
];

function ModeTransitionScreen({ mode }: { mode: OperatingMode }) {
  const destination = mode === "mss" ? "MSS mode" : "Individual mode";
  return (
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-background/95 px-6 backdrop-blur-sm"
      role="status"
      aria-live="polite"
      aria-label={`Switching workspace to ${destination}`}
      data-testid="workspace-mode-transition"
    >
      <div className="w-full max-w-sm text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-md border border-border bg-background">
          <Logo size={36} />
        </div>
        <div className="mt-6 flex items-center justify-center gap-2 text-sm font-semibold text-foreground">
          <Loader2 size={16} className="animate-spin text-primary" />
          Applying {destination}
        </div>
        <p className="mt-2 text-xs leading-5 text-muted-foreground">
          Updating workspace access, navigation, and detection scope.
        </p>
        <div className="mt-6 h-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
          <div className="h-full w-2/3 animate-pulse rounded-full bg-primary" />
        </div>
        <p className="mt-3 font-mono text-[10px] text-muted-foreground">Keep this window open</p>
      </div>
    </div>
  );
}

export default function WorkspaceSetup({ required = false }: { required?: boolean }) {
  const { user, refreshMe } = useAuth();
  const { toast } = useToast();
  const [mode, setMode] = useState<OperatingMode | "">(user?.tenant.operatingMode ?? "");
  const [isApplying, setIsApplying] = useState(false);

  useEffect(() => setMode(user?.tenant.operatingMode ?? ""), [user?.tenant.operatingMode]);

  const save = useMutation({
    onMutate: () => {
      setIsApplying(true);
      return { startedAt: Date.now() };
    },
    mutationFn: async () => {
      if (!mode) throw new Error("Select an operating mode");
      const response = await apiRequest("PATCH", "/api/v1/workspace/operating-mode", { operatingMode: mode });
      return response.json();
    },
    onSuccess: async (_data, _variables, context) => {
      try {
        queryClient.clear();
        await refreshMe();
        const elapsed = Date.now() - (context?.startedAt ?? Date.now());
        if (elapsed < MIN_MODE_TRANSITION_MS) {
          await new Promise((resolve) => window.setTimeout(resolve, MIN_MODE_TRANSITION_MS - elapsed));
        }
        toast({
          title: "Workspace mode updated",
          description: mode === "mss" ? "Client workflows are enabled." : "Client workflows are hidden.",
        });
        if (required) window.location.hash = "/osint";
      } finally {
        setIsApplying(false);
      }
    },
    onError: (error: Error) => {
      setIsApplying(false);
      toast({ title: "Could not update workspace", description: error.message, variant: "destructive" });
    },
  });

  const content = (
    <main className="mx-auto w-full max-w-5xl px-5 py-8 sm:px-8 lg:py-12" aria-busy={isApplying}>
      {isApplying && mode ? <ModeTransitionScreen mode={mode} /> : null}
      {required ? (
        <div className="mb-10 flex items-center gap-3 border-b border-border pb-6">
          <Logo size={34} />
          <div>
            <div className="text-lg font-semibold">OptraSight</div>
            <div className="text-xs text-muted-foreground">Workspace setup</div>
          </div>
          <div className="ml-auto border-l border-border pl-3">
            <CreatorBrand side="bottom" />
          </div>
        </div>
      ) : (
        <PageHeader
          title="Workspace Setup"
          eyebrow="Operating model"
          description="Choose whether this workspace manages multiple clients or supports one internal security team."
        />
      )}

      {required ? (
        <div className="mb-8 max-w-2xl">
          <div className="text-xs font-semibold uppercase text-primary">Operating model</div>
          <h1 className="mt-2 text-3xl font-semibold">How will this workspace be used?</h1>
          <p className="mt-3 text-sm leading-6 text-muted-foreground">
            This choice controls which client-management features appear throughout the platform.
          </p>
        </div>
      ) : null}

      <div className="grid gap-5 md:grid-cols-2">
        {MODES.map((item) => {
          const selected = mode === item.id;
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setMode(item.id)}
              disabled={isApplying}
              className={`cursor-pointer rounded-md border p-6 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${selected ? "border-primary bg-primary/5" : "border-border bg-background hover:border-primary/35 hover:bg-muted/20"}`}
              aria-pressed={selected}
              data-testid={`button-mode-${item.id}`}
            >
              <div className="flex items-start justify-between gap-4">
                <span
                  className={`flex h-10 w-10 items-center justify-center rounded-md border ${selected ? "border-primary/30 bg-primary/10 text-primary" : "border-border text-muted-foreground"}`}
                >
                  <Icon size={19} />
                </span>
                <span
                  className={`flex h-6 w-6 items-center justify-center rounded-full border ${selected ? "border-primary bg-primary text-primary-foreground" : "border-border"}`}
                >
                  {selected ? <Check size={14} /> : null}
                </span>
              </div>
              <h2 className="mt-5 text-lg font-semibold">{item.title}</h2>
              <p className="mt-2 min-h-12 text-sm leading-6 text-muted-foreground">{item.description}</p>
              <div className="mt-5 space-y-2 border-t border-border pt-4">
                {item.features.map((feature) => (
                  <div key={feature} className="flex items-center gap-2 text-xs">
                    <ShieldCheck size={13} className="shrink-0 text-primary" />
                    {feature}
                  </div>
                ))}
              </div>
            </button>
          );
        })}
      </div>

      <div className="mt-7 flex flex-col gap-3 border-t border-border pt-6 sm:flex-row sm:items-center sm:justify-between">
        <p className="max-w-2xl text-xs leading-5 text-muted-foreground">
          Changing modes does not delete existing client records. Individual mode hides and blocks client workflows
          until MSS mode is restored.
        </p>
        <Button
          onClick={() => save.mutate()}
          disabled={!mode || isApplying || save.isPending || (!required && mode === user?.tenant.operatingMode)}
          className="shrink-0"
        >
          {required ? "Continue" : "Save mode"}
        </Button>
      </div>
    </main>
  );

  return required ? (
    <div className="min-h-screen bg-background text-foreground">{content}</div>
  ) : (
    <AppShell>{content}</AppShell>
  );
}
