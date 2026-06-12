import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandShortcut } from "@/components/ui/command";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { apiRequest } from "@/lib/queryClient";
import { Search, ExternalLink, Copy } from "lucide-react";
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
          {actionTarget?.copyValue && (
            <CommandGroup heading="Quick actions for top result">
              <div className="px-2 pb-1 text-[11px] text-muted-foreground">
                Actions apply to <span className="font-medium text-foreground">{actionTarget.title}</span>.
              </div>
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
