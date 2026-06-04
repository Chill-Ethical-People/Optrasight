// v2.17 — Floating AI chatbot, repurposed as a free-form chat with the
// integrated AI provider. The CIRT Triage + Deep Dive workflows that used to
// live here have moved to OsintTriagePanel.tsx (inline on the OSINT page).
//
// The floating button is the bottom-right entry point. Clicking it opens a
// right-side Sheet with a chat conversation backed by
// `/api/v1/osint/chat/converse`. The conversation is automatically
// context-aware of the currently visible findings — the analyst can ask
// open-ended questions like "summarize the ransomware leaks this week" or
// "which findings affect Atlassian Confluence".
import { useEffect, useRef, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Bot, Loader2, MessageSquare, Send, Sparkles, Trash2 } from "lucide-react";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription,
} from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { useAiAvailability } from "@/lib/aiAvailability";
import type { OsintFindingDTO } from "@shared/schema";

/** Day-range key kept for backward compatibility with the page. */
export type RangeKey = "1d" | "7d" | "1m" | "1q" | "1y" | "all";

interface Props {
  range: RangeKey;
  findings: OsintFindingDTO[];
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  providerLabel?: string;
  contextSize?: number;
}

function parseApiError(e: any): { isAiFailure: boolean; message: string } {
  const raw = String(e?.message || e || "");
  const m = raw.match(/^(\d{3}):\s*(.*)$/s);
  if (!m) return { isAiFailure: false, message: raw };
  const status = Number(m[1]);
  const body = m[2];
  try {
    const parsed = JSON.parse(body);
    if (status === 502 && parsed?.aiDiagnostic) {
      const diag = parsed.aiDiagnostic;
      const provider = parsed.providerLabel ? `"${parsed.providerLabel}" ` : "";
      return {
        isAiFailure: true,
        message: `${provider}returned ${diag.httpStatus ? `HTTP ${diag.httpStatus}` : "no response"} after ${diag.latencyMs}ms — ${diag.reason}.`,
      };
    }
    return { isAiFailure: false, message: parsed.detail || body };
  } catch {
    return { isAiFailure: false, message: body || raw };
  }
}

const SUGGESTIONS = [
  "Summarize the most critical findings I have right now.",
  "Which findings would you escalate to a client today and why?",
  "Are there any CVEs being actively exploited that I should hunt for?",
  "Group the findings by threat actor and tell me which actor is most active.",
];

export default function OsintChatbot({ findings }: Props) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to the bottom as new messages arrive.
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading]);

  // Cap the context we send: top-20 findings by recency (already sorted server-side).
  const contextFindingIds = (findings || []).slice(0, 20).map((f) => f.id);

  async function send(text: string) {
    const trimmed = text.trim();
    if (!trimmed) return;
    if (aiDisabled) {
      toast({ variant: "destructive", title: "AI unavailable", description: aiAvailability.disabledReason });
      return;
    }
    const nextHistory: ChatMessage[] = [...messages, { role: "user", content: trimmed }];
    setMessages(nextHistory);
    setInput("");
    setLoading(true);
    try {
      const r = await apiRequest("POST", "/api/v1/osint/chat/converse", {
        messages: nextHistory.map((m) => ({ role: m.role, content: m.content })),
        contextFindingIds,
      });
      const json = await r.json();
      setMessages((m) => [...m, {
        role: "assistant",
        content: typeof json.reply === "string" && json.reply.length ? json.reply : "(empty reply)",
        providerLabel: json.providerLabel,
        contextSize: json.contextSize,
      }]);
    } catch (e: any) {
      const parsed = parseApiError(e);
      toast({ variant: "destructive", title: parsed.isAiFailure ? "AI provider failed" : "Chat failed", description: parsed.message });
      setMessages((m) => [...m, { role: "assistant", content: `_⚠️ ${parsed.message}_` }]);
    } finally {
      setLoading(false);
    }
  }

  function clearChat() {
    setMessages([]);
    setInput("");
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        disabled={aiDisabled}
        className={`fixed bottom-6 right-6 z-40 h-14 w-14 rounded-full shadow-xl transition-all flex items-center justify-center group ${aiDisabled ? "bg-muted text-muted-foreground cursor-not-allowed opacity-60" : "bg-primary text-primary-foreground hover:shadow-2xl hover:scale-105 active:scale-95"}`}
        data-testid="button-osint-chatbot-fab"
        aria-label="Open OSINT AI chat"
        title={aiAvailability.disabledReason ?? "OSINT AI chat"}
      >
        <MessageSquare size={22} className="group-hover:rotate-3 transition-transform" />
        {/* Pulse ring — signals "AI online" without a misleading unread-count dot. */}
        {!aiDisabled && <span className="absolute -top-0.5 -right-0.5 h-2.5 w-2.5 bg-emerald-500 rounded-full ring-2 ring-background animate-pulse" title="AI assistant online" />}
      </button>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent
          side="right"
          className="w-full sm:max-w-[600px] md:max-w-[720px] flex flex-col"
          data-testid="sheet-osint-chatbox"
        >
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Bot size={18} className="text-primary" />
              OSINT AI Chat
            </SheetTitle>
            <SheetDescription className="text-xs">
              Ask anything about the {findings?.length ?? 0} currently visible findings. The assistant uses your configured AI provider (DeepSeek / OpenAI / Anthropic / Gemini).
            </SheetDescription>
          </SheetHeader>

          {/* Scrollable conversation area. */}
          <div
            ref={scrollRef}
            className="flex-1 mt-3 overflow-y-auto pr-1 space-y-3"
            data-testid="chatbox-messages"
          >
            {messages.length === 0 ? (
              <Card className="p-4 bg-muted/30 border-dashed">
                <div className="text-xs text-muted-foreground mb-3">
                  <Sparkles size={12} className="inline mr-1.5 text-primary" />
                  Try one of these to get started:
                </div>
                <div className="grid grid-cols-1 gap-1.5">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => send(s)}
                      disabled={aiDisabled}
                      className="text-left text-xs px-2.5 py-2 rounded border bg-background hover:bg-primary/5 hover:border-primary/40 transition-colors"
                      data-testid="button-chat-suggestion"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </Card>
            ) : (
              messages.map((m, i) => (
                <div
                  key={i}
                  className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
                  data-testid={`chat-message-${m.role}-${i}`}
                >
                  <div
                    className={`max-w-[88%] rounded-lg px-3 py-2 ${
                      m.role === "user"
                        ? "bg-primary text-primary-foreground"
                        : "bg-card border"
                    }`}
                  >
                    {m.role === "user" ? (
                      <div className="text-sm whitespace-pre-wrap leading-relaxed">{m.content}</div>
                    ) : (
                      <div className="prose prose-sm dark:prose-invert max-w-none text-sm leading-relaxed">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{m.content}</ReactMarkdown>
                      </div>
                    )}
                    {m.role === "assistant" && (m.providerLabel || typeof m.contextSize === "number") && (
                      <div className="text-[10px] text-muted-foreground mt-1.5 flex items-center gap-2 flex-wrap border-t pt-1.5">
                        {m.providerLabel && <Badge variant="outline" className="text-[9px]">{m.providerLabel}</Badge>}
                        {typeof m.contextSize === "number" && <span>{m.contextSize} findings in context</span>}
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
            {loading && (
              <div className="flex justify-start">
                <div className="bg-card border rounded-lg px-3 py-2 flex items-center gap-2 text-xs text-muted-foreground">
                  <Loader2 size={12} className="animate-spin" /> thinking…
                </div>
              </div>
            )}
          </div>

          {/* Composer */}
          <div className="mt-3 border-t pt-3 space-y-2">
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  if (!loading) send(input);
                }
              }}
              placeholder="Ask about these findings… (Enter to send, Shift+Enter for newline)"
              className="text-sm resize-none min-h-[64px]"
              data-testid="textarea-chat-input"
              disabled={loading || aiDisabled}
            />
            <div className="flex items-center gap-2">
              <Button
                size="sm" variant="ghost"
                onClick={clearChat}
                disabled={loading || messages.length === 0}
                data-testid="button-chat-clear"
              >
                <Trash2 size={12} className="mr-1" /> Clear
              </Button>
              <div className="flex-1" />
              <span className="text-[10px] text-muted-foreground">
                {findings?.length ?? 0} findings · up to 20 in context
              </span>
              <Button
                size="sm"
                onClick={() => send(input)}
                disabled={loading || aiDisabled || !input.trim()}
                data-testid="button-chat-send"
              >
                {loading
                  ? <><Loader2 size={12} className="mr-1.5 animate-spin" />Sending</>
                  : <><Send size={12} className="mr-1.5" />Send</>}
              </Button>
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}
