import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { BookOpen, Download } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import guideMarkdown from "../../../docs/WEEKLY_THREAT_INTELLIGENCE_DIGEST_GUIDE.md?raw";

const renderedGuide = guideMarkdown.replace(/^# Weekly Threat Intelligence Digest Drafting Guide\s*/u, "");

function downloadGuide() {
  const url = URL.createObjectURL(new Blob([guideMarkdown], { type: "text/markdown;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "OptraSight_Client_Brief_Guide.md";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function ClientBriefGuideDialog() {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button type="button" variant="outline">
          <BookOpen size={15} className="mr-2" />
          Client Brief guide
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[92vh] sm:max-w-5xl">
        <DialogHeader className="pr-8">
          <DialogTitle>Client Brief drafting guide</DialogTitle>
          <DialogDescription>
            Audience positioning, evidence guardrails, DOCX placeholders, drafting vocabulary, and reusable client
            communication patterns.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-black bg-white px-4 py-3 text-black">
          <p className="text-xs leading-5">
            Required DOCX contract: <code>{"{{client_name}}"}</code> in the subject;{" "}
            <code>{"{{executive_summary}}"}</code> and <code>{"{{sources}}"}</code> in the body.
          </p>
          <Button type="button" variant="outline" size="sm" className="border-black text-black" onClick={downloadGuide}>
            <Download size={14} className="mr-2" />
            Download guide
          </Button>
        </div>

        <article className="prose prose-sm max-w-none rounded-md border bg-white px-5 py-4 text-black prose-headings:text-black prose-a:text-black prose-a:underline prose-table:text-xs prose-th:text-left prose-td:align-top sm:px-7 sm:py-6">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{renderedGuide}</ReactMarkdown>
        </article>
      </DialogContent>
    </Dialog>
  );
}
