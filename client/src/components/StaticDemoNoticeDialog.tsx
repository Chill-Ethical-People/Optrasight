import { useEffect, useMemo, useState } from "react";
import { Eye, LockKeyhole, Route } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { STATIC_DEMO_MODE } from "@/lib/staticDemoApi";
import {
  STATIC_DEMO_NOTICE_EVENT,
  type StaticDemoNoticeDetail,
  type StaticDemoNoticeKind,
} from "@/lib/staticDemoNotice";

const KIND_COPY: Record<StaticDemoNoticeKind, { label: string; message: string }> = {
  ai: {
    label: "Live AI restricted",
    message:
      "Live AI actions are restricted in this static preview. In the local app, configured provider keys run triage, deep-dive review, actor enrichment, and hunt-query drafting through tracked background jobs.",
  },
  write: {
    label: "Write action restricted",
    message:
      "Write actions are restricted in this static preview. Run OptraSight locally to create records, update settings, manage users, and persist changes.",
  },
  export: {
    label: "Export restricted",
    message:
      "Exports are restricted in this static preview because there is no live server session to assemble or persist generated artifacts.",
  },
  source: {
    label: "Source operation restricted",
    message:
      "Source refresh and ingestion controls are shown for workflow review. The static preview does not fetch live feeds or write parsed findings.",
  },
  selection: {
    label: "Selection locked",
    message:
      "Selection controls are shown to demonstrate the workflow, but this static preview keeps the review dataset fixed so completed examples stay reproducible.",
  },
  default: {
    label: "Capability restricted",
    message:
      "Interactive controls are shown to demonstrate the Batch One operating model, but actions that require a live server, database writes, provider keys, or background jobs are restricted in this static preview.",
  },
};

export function StaticDemoNoticeDialog() {
  const [open, setOpen] = useState(false);
  const [detail, setDetail] = useState<StaticDemoNoticeDetail>({});

  useEffect(() => {
    if (!STATIC_DEMO_MODE) return;
    const handler = (event: Event) => {
      setDetail((event as CustomEvent<StaticDemoNoticeDetail>).detail ?? {});
      setOpen(true);
    };
    window.addEventListener(STATIC_DEMO_NOTICE_EVENT, handler);
    return () => window.removeEventListener(STATIC_DEMO_NOTICE_EVENT, handler);
  }, []);

  const copy = useMemo(() => KIND_COPY[detail.kind ?? "default"] ?? KIND_COPY.default, [detail.kind]);

  if (!STATIC_DEMO_MODE) return null;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <div className="mb-2 flex items-center gap-2">
            <Badge variant="outline" className="gap-1 border-primary/30 bg-primary/10 text-primary">
              <Eye size={12} /> Public preview
            </Badge>
            <Badge variant="secondary" className="gap-1">
              <LockKeyhole size={12} /> Read-only
            </Badge>
          </div>
          <DialogTitle>Static review workspace</DialogTitle>
          <DialogDescription>
            This public workspace is read-only. Interactive controls are shown to demonstrate the Batch One operating model, but actions that require a live server, database writes, provider keys, or background jobs are restricted in this static preview.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 text-sm">
          <div className="rounded-md border border-primary/20 bg-primary/5 p-3">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-primary">{detail.action ?? copy.label}</div>
            <p className="leading-6 text-muted-foreground">{copy.message}</p>
          </div>
          <div className="rounded-md border bg-muted/25 p-3">
            <div className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-foreground">
              <Route size={13} className="text-primary" /> Suggested review path
            </div>
            <p className="leading-6 text-muted-foreground">
              Start in Intel Inbox, inspect OSINT findings, open completed CIRT triage and deep-dive job examples, review generated hunt queries, browse Actor Observatory, then check AI Setup and Platform Users as read-only administration surfaces.
            </p>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={() => setOpen(false)}>Continue review</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
