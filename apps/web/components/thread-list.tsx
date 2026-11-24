"use client";

import Link from "next/link";
import type { ChatThreadSummary } from "@prohori/shared";
import { CheckSquare, MessageSquare, Plus } from "lucide-react";
import { usePoll } from "@/lib/api";
import { cn, relTime } from "@/lib/utils";
import { Button, Card } from "@/components/ui";

/** Left column of the Sentinel page: past conversations (general chats and "Review with Sentinel" threads). */
export function ThreadList({ currentThreadId, onNewThread }: { currentThreadId: string | null; onNewThread: () => void }) {
  const threads = usePoll<ChatThreadSummary[]>("/chat/threads?limit=60", 5000);
  const now = Date.now();
  const list = threads.data ?? [];
  return (
    <Card className="flex max-h-[calc(100vh-11rem)] flex-col overflow-hidden">
      <div className="flex items-center justify-between gap-2 border-b border-line px-3 py-2.5">
        <span className="text-xs font-semibold uppercase tracking-wider text-muted">Conversations</span>
        <Button size="sm" variant="ghost" onClick={onNewThread} title="Start a new conversation">
          <Plus className="size-3.5" /> New
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-1.5">
        {threads.loading && !threads.data && <div className="p-3 text-xs text-dim">Loading…</div>}
        {threads.error && <div className="p-3 text-xs text-red-300">{threads.error}</div>}
        {!threads.loading && list.length === 0 && <div className="p-3 text-xs text-dim">No conversations yet.</div>}
        {list.map((t) => {
          const active = t.id === currentThreadId;
          const href = t.actionId
            ? `/chat?thread=${encodeURIComponent(t.id)}&actionId=${encodeURIComponent(t.actionId)}`
            : `/chat?thread=${encodeURIComponent(t.id)}`;
          return (
            <Link
              key={t.id}
              href={href}
              className={cn(
                "mb-0.5 block rounded-lg px-2.5 py-2 transition-colors",
                active ? "bg-accent/15 ring-1 ring-accent/40" : "hover:bg-white/5",
              )}
            >
              <div className="flex items-start gap-2">
                {t.actionId
                  ? <CheckSquare className="mt-0.5 size-3.5 shrink-0 text-amber-300" />
                  : <MessageSquare className="mt-0.5 size-3.5 shrink-0 text-blue-300" />}
                <div className="min-w-0 flex-1">
                  <div className={cn("line-clamp-2 text-[13px] leading-snug", active ? "text-white" : "text-fg")}>{t.title}</div>
                  <div className="mt-0.5 text-[11px] text-dim">
                    {t.startedBy ? `${t.startedBy} · ` : ""}{relTime(t.updatedAt, now)}
                    {t.messageCount > 0 ? ` · ${t.messageCount} msg` : ""}
                  </div>
                </div>
              </div>
            </Link>
          );
        })}
      </div>
    </Card>
  );
}
