import { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Command, CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandShortcut } from "@/components/ui/command";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Search, ExternalLink, BriefcaseBusiness, Copy, ShieldCheck } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

type SearchResult = {
  id: string;
  type: string;
  title: string;
  subtitle: string;
  href: string;
  severity?: string | null;
  status?: string | null;
  tenantName?: string | null;
  action?: string;
  copyValue?: string | null;
};

function sourceTypeFor(r: SearchResult): string | null {
  if (r.type === "Exposure finding") return "finding";
  if (r.type === "Intel finding") return "osint_finding";
  if (r.type === "Threat actor") return "threat_actor";
  if (r.type === "Domain candidate") return "domain_candidate";
  if (r.type === "Detection rule") return "detection_rule";
  if (r.type === "Tabletop exercise") return "exercise";
  return null;
}

export function GlobalCommandPalette() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const { toast } = useToast();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key.toLowerCase() === "k" || e.code === "KeyK")) {
        e.preventDefault();
        e.stopPropagation();
        setOpen((v) => !v);
      }
    };
    document.addEventListener("keydown", onKey, { capture: true });
    window.addEventListener("keydown", onKey, { capture: true });
    return () => {
      document.removeEventListener("keydown", onKey, { capture: true });
      window.removeEventListener("keydown", onKey, { capture: true });
    };
  }, []);

  const query = useQuery<{ results: SearchResult[] }>({
    queryKey: ["/api/v1/search", `?q=${encodeURIComponent(q)}`],
    enabled: open && q.trim().length >= 2,
    queryFn: async () => {
      const r = await apiRequest("GET", `/api/v1/search?q=${encodeURIComponent(q.trim())}`);
      return r.json();
    },
  });

  const results = query.data?.results ?? [];
  const actionTarget = useMemo(() => results[0], [results]);
  const actionTargetType = actionTarget ? sourceTypeFor(actionTarget) : null;

  const startInvestigation = useMutation({
    mutationFn: async (r: SearchResult) => {
      const sourceType = sourceTypeFor(r);
      if (!sourceType) return null;
      const res = await apiRequest("POST", "/api/v1/investigations", {
        title: `Investigate ${r.title}`.slice(0, 170),
        severity: (r.severity || "medium").toLowerCase(),
        summary: `${r.type}: ${r.subtitle}`,
        sourceType,
        sourceId: r.id,
      });
      return res.json();
    },
    onSuccess: (inv: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/investigations"] });
      if (inv?.id) window.location.hash = `#/investigations/${encodeURIComponent(inv.id)}`;
      setOpen(false);
      toast({ title: "Investigation started", description: inv?.title ?? "Case workspace opened." });
    },
    onError: (e: any) => toast({ variant: "destructive", title: "Could not start investigation", description: e.message }),
  });

  const openResult = (r: SearchResult) => {
    window.location.hash = r.href.startsWith("#") ? r.href : `#${r.href}`;
    setOpen(false);
  };

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="h-9 min-w-9 gap-2 px-2.5 sm:px-3"
        onClick={() => setOpen(true)}
        data-testid="button-command-palette"
      >
        <Search size={15} className="shrink-0" />
        <span className="hidden lg:inline text-xs text-muted-foreground">Search</span>
        <kbd className="hidden 2xl:inline-flex rounded border bg-muted px-1.5 py-0.5 text-[10px] leading-none text-muted-foreground">Ctrl/⌘K</kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen}>
        <CommandInput value={q} onValueChange={setQ} placeholder="Search actors, findings, IOCs, domains, rules…" />
        <CommandList className="max-h-[520px]">
          <CommandEmpty>{q.trim().length < 2 ? "Type at least two characters." : "No matching signal found."}</CommandEmpty>
          {results.length > 0 && (
            <CommandGroup heading="Open">
              {results.map((r) => (
                <CommandItem key={`${r.type}-${r.id}`} value={`${r.type} ${r.title} ${r.subtitle}`} onSelect={() => openResult(r)}>
                  <ExternalLink size={15} className="text-muted-foreground" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm">{r.title}</div>
                    <div className="truncate text-xs text-muted-foreground">
                      {r.type} · {r.subtitle}{r.tenantName ? ` · ${r.tenantName}` : ""}
                    </div>
                  </div>
                  {r.severity && <Badge variant="outline" className="text-[10px]">{r.severity}</Badge>}
                  {r.status && <CommandShortcut>{r.status}</CommandShortcut>}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
          {actionTarget && (actionTargetType || actionTarget.type === "Intel finding" || actionTarget.copyValue) && (
            <CommandGroup heading="Quick actions for top result">
              <div className="px-2 pb-1 text-[11px] text-muted-foreground">
                Actions apply to <span className="font-medium text-foreground">{actionTarget.title}</span>.
              </div>
              {actionTargetType && (
                <CommandItem value={`start investigation ${actionTarget.title}`} onSelect={() => startInvestigation.mutate(actionTarget)}>
                  <BriefcaseBusiness size={15} className="text-[hsl(var(--brand))]" />
                  <span className="truncate">Start investigation</span>
                </CommandItem>
              )}
              {actionTarget.type === "Intel finding" && (
                <CommandItem value={`generate detection ${actionTarget.title}`} onSelect={() => {
                  window.location.hash = `#/detection-rules?findingIds=${encodeURIComponent(actionTarget.id)}`;
                  setOpen(false);
                }}>
                  <ShieldCheck size={15} className="text-[hsl(var(--brand))]" />
                  <span className="truncate">Generate detection from this intel</span>
                </CommandItem>
              )}
              {actionTarget.copyValue && (
                <CommandItem value={`copy ${actionTarget.copyValue}`} onSelect={() => {
                  navigator.clipboard?.writeText(actionTarget.copyValue || "");
                  toast({ title: "Copied", description: actionTarget.copyValue });
                  setOpen(false);
                }}>
                  <Copy size={15} className="text-[hsl(var(--brand))]" />
                  <span className="truncate">Copy {actionTarget.copyValue}</span>
                </CommandItem>
              )}
            </CommandGroup>
          )}
        </CommandList>
      </CommandDialog>
    </>
  );
}
