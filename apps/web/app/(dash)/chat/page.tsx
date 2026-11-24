"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport, getToolName, isToolUIPart, type UIMessage } from "ai";
import type { ActionRecord, Finding, HostSummary } from "@prohori/shared";
import { Bot, CheckCircle2, ChevronDown, ChevronRight, CircleAlert, Loader2, MessageSquare, Pin, Plus, Send, Square, User, Wrench } from "lucide-react";
import { ActionCard, LiveActionCard } from "@/components/action-card";
import { JudgmentCard } from "@/components/judgment-card";
import { ThreadList } from "@/components/thread-list";
import { Markdown } from "@/components/markdown";
import { Badge, Button, Card, PageHeader, Skeleton } from "@/components/ui";
import { api, usePoll } from "@/lib/api";
import { extractAction } from "@/lib/actions";
import { extractJudgmentRef } from "@/lib/judgments";
import { cn } from "@/lib/utils";

const SUGGESTIONS = [
  "Assess our exposure to PHP2Shell",
  "Why is bank-web-02 not affected?",
  "Inventory bank-batch-01",
  "Recommend remediation for bank-web-01",
];
const REVIEW_SUGGESTIONS = [
  "Assess the risk of this change",
  "Can we avoid downtime?",
  "Revise: block file uploads only",
  "Impact of no action",
];

const THREAD_KEY = "prohori.chat.thread";
const msgKey = (t: string) => `prohori.chat.msgs.${t}`;
const actionThreadKey = (a: string) => `prohori.chat.action.${a}`;

function newThreadId() {
  return `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function json(v: unknown): string {
  if (v === undefined) return "";
  try {
    return typeof v === "string" ? v : JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

type AnyToolPart = Extract<UIMessage["parts"][number], { toolCallId: string }>;

function ToolCard({ part }: { part: AnyToolPart }) {
  const [open, setOpen] = useState(false);
  const name = getToolName(part);
  const state = part.state;
  const running = state === "input-streaming" || state === "input-available";
  const failed = state === "output-error" || state === "output-denied";
  const done = state === "output-available";
  const inputStr = json(part.input);
  const outStr = done ? json(part.output) : failed && "errorText" in part ? String(part.errorText ?? "") : "";
  return (
    <div className="my-2 overflow-hidden rounded-lg border border-line bg-bg/70 text-xs">
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-panel-2/60">
        <Wrench className="size-3.5 text-violet-400" />
        <span className="font-mono font-semibold text-violet-200">{name}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-dim">{inputStr.replace(/\s+/g, " ")}</span>
        {running && <Badge tone="blue"><Loader2 className="size-3 animate-spin" /> Running</Badge>}
        {done && <Badge tone="green"><CheckCircle2 className="size-3" /> Complete</Badge>}
        {failed && <Badge tone="red"><CircleAlert className="size-3" /> {state === "output-denied" ? "Denied" : "Error"}</Badge>}
        {!running && !done && !failed && <Badge tone="gray">{state}</Badge>}
        {open ? <ChevronDown className="size-3.5 text-dim" /> : <ChevronRight className="size-3.5 text-dim" />}
      </button>
      {open && (
        <div className="space-y-2 border-t border-line px-3 py-2">
          <div>
            <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-dim">Input</div>
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-fg">{inputStr || "{}"}</pre>
          </div>
          {(done || failed) && (
            <div>
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-dim">{failed ? "Error" : "Output"}</div>
              <pre className={cn("max-h-72 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px]", failed ? "text-red-300" : "text-fg")}>{outStr}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Message({ m, hostName, threadId }: { m: UIMessage; hostName: (id: string) => string; threadId: string }) {
  const isUser = m.role === "user";
  return (
    <div className={cn("flex gap-3", isUser && "flex-row-reverse")}>
      <div className={cn("flex size-8 shrink-0 items-center justify-center rounded-full", isUser ? "bg-blue-600" : "bg-panel-2 ring-1 ring-line-2")}>
        {isUser ? <User className="size-4 text-white" /> : <Bot className="size-4 text-blue-300" />}
      </div>
      <div className={cn("min-w-0 max-w-[85%]", isUser ? "rounded-2xl rounded-tr-sm bg-blue-600/90 px-4 py-2.5 text-white" : "flex-1")}>
        {m.parts.map((p, i) => {
          if (p.type === "text") return isUser ? <div key={i} className="whitespace-pre-wrap text-sm">{p.text}</div> : <Markdown key={i}>{p.text}</Markdown>;
          if (p.type === "reasoning") return <div key={i} className="my-1 border-l-2 border-line-2 pl-3 text-xs italic text-dim">{p.text}</div>;
          if (isToolUIPart(p)) {
            // proposeFix / reviseProposal / getAction (or any tool returning an ActionRecord) render as an action card.
            // judgeAdvisory / getJudgment (any tool returning { id: "jdg_…" }) render as a live judgment card.
            const judgment = p.state === "output-available" ? extractJudgmentRef(p.output) : null;
            const action = p.state === "output-available" && !judgment ? extractAction(p.output) : null;
            return (
              <div key={p.toolCallId}>
                <ToolCard part={p} />
                {action && <div className="my-2"><LiveActionCard initial={action} hostName={hostName(action.hostId)} threadId={threadId} /></div>}
                {judgment && <div className="my-2"><JudgmentCard initial={judgment} /></div>}
              </div>
            );
          }
          return null;
        })}
      </div>
    </div>
  );
}

/** Follows supersededBy from the starting action to the newest revision, polling every 3 s. */
function useActionChain(startId: string | null) {
  const [currentId, setCurrentId] = useState(startId);
  useEffect(() => setCurrentId(startId), [startId]);
  const poll = usePoll<ActionRecord>(currentId ? `/actions/${encodeURIComponent(currentId)}` : null, 3000);
  const a = poll.data && poll.data.id === currentId ? poll.data : undefined;
  useEffect(() => {
    if (a?.state === "superseded" && a.supersededBy) setCurrentId(a.supersededBy);
  }, [a?.state, a?.supersededBy]);
  return { action: a, error: poll.error, refresh: poll.refresh, setCurrentId, currentId };
}

type Chain = ReturnType<typeof useActionChain>;

function ReviewBanner({ chain, hostName, threadId }: { chain: Chain; hostName: (id: string) => string; threadId: string }) {
  const a = chain.action;
  const finding = usePoll<Finding>(a?.findingId ? `/findings/${encodeURIComponent(a.findingId)}` : null, 5000);
  return (
    <div className="min-h-0 xl:order-last xl:overflow-y-auto xl:pr-1">
      <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-amber-300">
        <Pin className="size-3.5" /> Reviewing Proposed Action{chain.currentId && <span className="font-mono normal-case text-dim">· {chain.currentId}</span>}
      </div>
      {a ? (
        <ActionCard a={a} hostName={hostName(a.hostId)} mode="decide" finding={finding.data ?? null} threadId={threadId} onChange={() => void chain.refresh()} compact />
      ) : chain.error ? (
        <div className="rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-sm text-red-200">Unable to load action: {chain.error}</div>
      ) : (
        <Skeleton className="h-32" />
      )}
    </div>
  );
}

function ChatThread({ threadId, initial, actionId, onNewThread }: { threadId: string; initial: UIMessage[]; actionId: string | null; onNewThread: () => void }) {
  const hosts = usePoll<HostSummary[]>("/hosts", 15000);
  const hostName = (id: string) => hosts.data?.find((h) => h.id === id)?.name ?? id;
  const chain = useActionChain(actionId);
  const currentActionRef = useRef<string | null>(actionId);
  currentActionRef.current = chain.currentId;
  const { setCurrentId, currentId } = chain;

  const transport = useMemo(
    () =>
      new DefaultChatTransport<UIMessage>({
        api: "/api/chat",
        body: () => (currentActionRef.current ? { threadId, actionId: currentActionRef.current } : { threadId }),
      }),
    [threadId],
  );
  const { messages, sendMessage, status, error, stop, clearError } = useChat({ id: threadId, transport, messages: initial });
  const [input, setInput] = useState("");
  const endRef = useRef<HTMLDivElement>(null);
  const busy = status === "submitted" || status === "streaming";

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, status]);

  useEffect(() => {
    if (status === "ready" || status === "error") {
      try {
        sessionStorage.setItem(msgKey(threadId), JSON.stringify(messages));
      } catch {
        /* quota */
      }
    }
  }, [messages, status, threadId]);

  // A revision returned by a tool immediately becomes the pinned action (polling would also catch it via supersededBy).
  useEffect(() => {
    if (!actionId) return;
    for (const m of messages) {
      for (const p of m.parts) {
        if (!isToolUIPart(p) || p.state !== "output-available") continue;
        const a = extractAction(p.output);
        if (a && a.supersedes && a.supersedes === currentId && a.state === "pending") setCurrentId(a.id);
      }
    }
  }, [messages, actionId, currentId, setCurrentId]);

  function send(text: string) {
    const t = text.trim();
    if (!t || busy) return;
    clearError();
    void sendMessage({ text: t });
    setInput("");
  }

  const chips = actionId ? REVIEW_SUGGESTIONS : SUGGESTIONS;

  return (
    <div
      className={cn(
        actionId
          ? "grid gap-4 xl:h-[calc(100vh-9.5rem)] xl:grid-cols-[minmax(0,1fr)_minmax(22rem,28rem)]"
          : "flex h-[calc(100vh-9.5rem)] flex-col",
      )}
    >
      {actionId && <ReviewBanner chain={chain} hostName={hostName} threadId={threadId} />}
      <Card className={cn("flex min-h-0 flex-col overflow-hidden", actionId ? "h-[calc(100vh-9.5rem)] xl:h-auto" : "flex-1")}>
        <div className="flex items-center gap-2 border-b border-line px-4 py-2.5 text-xs text-muted">
          <span className="font-mono">Thread {threadId}</span>
          <span className="ml-auto">{busy ? <span className="inline-flex items-center gap-1 text-blue-300"><Loader2 className="size-3 animate-spin" /> Analyzing…</span> : "Ready"}</span>
          <Button size="sm" variant="ghost" onClick={onNewThread} disabled={busy}><Plus className="size-3.5" /> New Conversation</Button>
        </div>
        <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-5 py-5">
          {messages.length === 0 && (
            <div className="mx-auto mt-6 max-w-xl text-center">
              <Bot className="mx-auto size-10 text-blue-400" />
              <h2 className="mt-3 text-lg font-semibold text-white">{actionId ? "Review This Proposal with Sentinel" : "Ask Sentinel About Your Assets"}</h2>
              <p className="mt-1 text-sm text-muted">
                {actionId
                  ? "Ask about risk, alternatives or side effects. Sentinel can revise the proposal; approval remains with you."
                  : "Sentinel answers from live data, querying assets, findings and advisories directly. It can propose remediation but never applies changes."}
              </p>
            </div>
          )}
          {messages.map((m) => <Message key={m.id} m={m} hostName={hostName} threadId={threadId} />)}
          {status === "submitted" && (
            <div className="flex items-center gap-2 pl-11 text-sm text-muted"><Loader2 className="size-4 animate-spin" /> Sentinel is analyzing live data…</div>
          )}
          {error && (
            <div className="flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-950/40 px-3 py-2 text-sm text-red-200">
              <CircleAlert className="mt-0.5 size-4" /> {error.message || "Request failed"}
            </div>
          )}
          <div ref={endRef} />
        </div>
        <div className="border-t border-line p-3">
          <div className="mb-2 flex flex-wrap gap-2">
            {chips.map((s) => (
              <button key={s} onClick={() => send(s)} disabled={busy} className="rounded-full border border-line-2 bg-panel-2 px-3 py-1 text-xs text-fg hover:border-blue-500/60 hover:bg-blue-500/10 disabled:opacity-50">
                {s}
              </button>
            ))}
          </div>
          <form onSubmit={(e) => { e.preventDefault(); send(input); }} className="flex gap-2">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={actionId ? "Ask about this change or request a revision…" : "Ask about exposure, assets, CVEs or remediation…"}
              className="h-11 flex-1 rounded-lg border border-line-2 bg-bg px-3 text-sm text-fg placeholder:text-dim focus:border-accent focus:outline-none"
            />
            {busy ? (
              <Button type="button" size="lg" onClick={() => void stop()}><Square className="size-4" /> Stop</Button>
            ) : (
              <Button type="submit" size="lg" variant="primary" disabled={!input.trim()}><Send className="size-4" /> Send</Button>
            )}
          </form>
        </div>
      </Card>
    </div>
  );
}

function readStored(threadId: string): UIMessage[] {
  try {
    return JSON.parse(sessionStorage.getItem(msgKey(threadId)) ?? "[]") as UIMessage[];
  } catch {
    return [];
  }
}

async function loadThread(threadId: string, fromServer: boolean): Promise<UIMessage[]> {
  if (fromServer) {
    try {
      const msgs = await api<UIMessage[]>(`/chat/threads/${encodeURIComponent(threadId)}/messages`);
      if (Array.isArray(msgs) && msgs.length) return msgs;
    } catch {
      /* fall back to the local copy */
    }
  }
  return readStored(threadId);
}

function ChatRouter() {
  const params = useSearchParams();
  const router = useRouter();
  const threadParam = params.get("thread");
  const actionId = params.get("actionId");
  const [state, setState] = useState<{ threadId: string; initial: UIMessage[]; key: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setState(null);
    setErr(null);
    void (async () => {
      let threadId: string;
      let fromServer = false;
      if (threadParam) {
        threadId = threadParam;
        fromServer = true;
      } else if (actionId) {
        let a: ActionRecord | null = null;
        try {
          a = await api<ActionRecord>(`/actions/${encodeURIComponent(actionId)}`);
        } catch (e) {
          setErr(e instanceof Error ? e.message : String(e));
        }
        if (a?.threadId) {
          threadId = a.threadId;
          fromServer = true;
        } else {
          threadId = sessionStorage.getItem(actionThreadKey(actionId)) ?? newThreadId();
          sessionStorage.setItem(actionThreadKey(actionId), threadId);
        }
      } else {
        threadId = sessionStorage.getItem(THREAD_KEY) ?? newThreadId();
        sessionStorage.setItem(THREAD_KEY, threadId);
      }
      const initial = await loadThread(threadId, fromServer);
      if (!cancelled) setState({ threadId, initial, key: `${threadId}:${actionId ?? ""}` });
    })();
    return () => {
      cancelled = true;
    };
  }, [threadParam, actionId]);

  function newThread() {
    const t = newThreadId();
    sessionStorage.setItem(THREAD_KEY, t);
    if (threadParam || actionId) router.push("/chat");
    else setState({ threadId: t, initial: [], key: t });
  }

  return (
    <>
      <PageHeader
        title={actionId ? "Review with Sentinel" : "Sentinel"}
        icon={<MessageSquare className="size-6 text-blue-400" />}
        sub={actionId ? "Discuss the proposed change, then approve or reject it" : "AI security analyst — every answer is grounded in live data from your assets"}
      />
      {err && <div className="mb-3 text-sm text-red-300">{err}</div>}
      <div className="grid gap-4 lg:grid-cols-[17rem_minmax(0,1fr)]">
        <aside className="hidden lg:block">
          <ThreadList currentThreadId={state?.threadId ?? null} onNewThread={newThread} />
        </aside>
        <div className="min-w-0">
          {state ? <ChatThread key={state.key} threadId={state.threadId} initial={state.initial} actionId={actionId} onNewThread={newThread} /> : <Skeleton className="h-[60vh]" />}
        </div>
      </div>
    </>
  );
}

export default function ChatPage() {
  return (
    <Suspense fallback={<Skeleton className="h-[60vh]" />}>
      <ChatRouter />
    </Suspense>
  );
}
