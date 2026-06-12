// Floating analyst chat backed by the configured AI provider. The CIRT Triage
// + Deep Dive workflows live in OsintTriagePanel.tsx on the Intel Inbox page.
//
// The floating button is the bottom-right entry point. Clicking it opens a
// right-side Sheet with a chat conversation backed by
// `/api/v1/osint/chat/converse`. The conversation is automatically
// context-aware when findings are supplied, while still supporting general
// analyst questions and pasted source URLs from any protected workspace page.
import { useEffect, useRef, useState, type PointerEvent } from "react";
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
  range?: RangeKey;
  findings?: OsintFindingDTO[];
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
  "Summarize the most important threat signals in the current workspace.",
  "Review this URL and extract security-relevant findings.",
  "Draft a concise hunt hypothesis for a ransomware actor.",
  "Explain which CVEs or TTPs should be prioritized and why.",
];

const CHAT_FAB_SIZE = 56;
const CHAT_FAB_MARGIN = 24;

function clampFabOffset(value: number, viewportSize: number): number {
  const max = Math.max(CHAT_FAB_MARGIN, viewportSize - CHAT_FAB_SIZE - CHAT_FAB_MARGIN);
  return Math.min(Math.max(value, CHAT_FAB_MARGIN), max);
}

export default function OsintChatbot({ findings = [] }: Props) {
  const { toast } = useToast();
  const aiAvailability = useAiAvailability();
  const aiDisabled = !aiAvailability.hasUsableProvider;
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [fabOffset, setFabOffset] = useState({ right: CHAT_FAB_MARGIN, bottom: CHAT_FAB_MARGIN });
  const scrollRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    startRight: number;
    startBottom: number;
    moved: boolean;
  } | null>(null);
  const suppressFabClickRef = useRef(false);

  // Auto-scroll to the bottom as new messages arrive.
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading]);

  // Cap the context we send: top-20 findings by recency (already sorted server-side).
  const contextFindingIds = findings.slice(0, 20).map((f) => f.id);
  const hasFindingContext = contextFindingIds.length > 0;

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

  function onFabPointerDown(e: PointerEvent<HTMLButtonElement>) {
    if (aiDisabled || e.button !== 0) return;
    suppressFabClickRef.current = false;
    dragRef.current = {
      pointerId: e.pointerId,
      startX: e.clientX,
      startY: e.clientY,
      startRight: fabOffset.right,
      startBottom: fabOffset.bottom,
      moved: false,
    };
    e.currentTarget.setPointerCapture(e.pointerId);
  }

  function onFabPointerMove(e: PointerEvent<HTMLButtonElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;
    const dx = e.clientX - drag.startX;
    const dy = e.clientY - drag.startY;
    if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true;
    setFabOffset({
      right: clampFabOffset(drag.startRight - dx, window.innerWidth),
      bottom: clampFabOffset(drag.startBottom - dy, window.innerHeight),
    });
  }

  function finishFabDrag(e: PointerEvent<HTMLButtonElement>) {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;
    e.currentTarget.releasePointerCapture(e.pointerId);
    suppressFabClickRef.current = drag.moved;
    dragRef.current = null;
  }

  return (
    <>
      <button
        type="button"
        onClick={(e) => {
          if (suppressFabClickRef.current) {
            e.preventDefault();
            suppressFabClickRef.current = false;
            return;
          }
          setOpen(true);
        }}
        onPointerDown={onFabPointerDown}
        onPointerMove={onFabPointerMove}
        onPointerUp={finishFabDrag}
        onPointerCancel={finishFabDrag}
        disabled={aiDisabled}
        style={{ right: fabOffset.right, bottom: fabOffset.bottom, touchAction: "none" }}
        className={`fixed z-40 h-14 w-14 rounded-full shadow-xl transition-shadow flex items-center justify-center group ${aiDisabled ? "bg-muted text-muted-foreground cursor-not-allowed opacity-60" : "bg-primary text-primary-foreground cursor-grab hover:shadow-2xl active:cursor-grabbing active:scale-95"}`}
        data-testid="button-osint-chatbot-fab"
        aria-label="Open analyst chat"
        title={aiAvailability.disabledReason ?? "Drag to move. Click to open analyst chat."}
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
              Analyst chat
            </SheetTitle>
            <SheetDescription className="text-xs">
              {hasFindingContext
                ? `Ask about the ${findings.length} visible findings, a pasted source URL, or any threat-intel question.`
                : "Ask any threat-intel, TAP, hunt-query, or source URL question."} The assistant uses your configured AI provider and does not perform platform code-development work.
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
                        {typeof m.contextSize === "number" && (
                          <span>{m.contextSize} context item{m.contextSize === 1 ? "" : "s"}</span>
                        )}
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
              placeholder="Ask a question or paste a source URL... (Enter to send, Shift+Enter for newline)"
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
                {hasFindingContext ? `${findings.length} findings - up to 20 in context` : "General workspace context"}
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
