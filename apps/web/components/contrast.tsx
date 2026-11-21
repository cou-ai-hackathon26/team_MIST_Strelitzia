import Link from "next/link";
import type { Finding, HostSummary } from "@prohori/shared";
import { ShieldCheck } from "lucide-react";
import { FlashOnChange } from "@/components/flash";
import { KevBadge, StatusPill } from "@/components/ui";
import { type CveGroup, shortVerdictReason, versionBanner } from "@/lib/format";
import { cn } from "@/lib/utils";
import { HostFixProgress } from "@/components/fix-progress";


/** Recent Detections: Asset | Reported version | Assessment | Rationale, per CVE. */
export function ContrastTable({ group, hosts, compact }: { group: CveGroup; hosts: HostSummary[] | undefined; compact?: boolean }) {
  const name = (id: string) => hosts?.find((h) => h.id === id)?.name ?? id;
  const critical = group.findings.filter((f) => f.status === "exposed").length;
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-panel">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line bg-panel-2/60 px-4 py-2.5">
        <span className="font-mono text-sm font-semibold text-white">{group.cveIds.join(" + ")}</span>
        {group.inKev && <KevBadge />}
        <span className="truncate text-sm text-muted">{group.title}</span>
        <span className="ml-auto flex items-center gap-2 text-xs">
          <span className={cn("inline-flex items-center gap-1 font-semibold", critical ? "text-red-400" : "text-emerald-300")}>
            <ShieldCheck className="size-3.5" /> {critical} critical
          </span>
        </span>
      </div>
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-[11px] uppercase tracking-wider text-dim">
            <th className="px-4 py-2 font-semibold">Asset</th>
            <th className="px-4 py-2 font-semibold">Reported version</th>
            <th className="px-4 py-2 font-semibold">Assessment</th>
            {!compact && <th className="px-4 py-2 font-semibold">Rationale</th>}
          </tr>
        </thead>
        <tbody>
          {group.findings.map((f) => (
            <tr key={f.id} className={cn("border-t border-line/70 align-top", f.status === "exposed" && "bg-red-500/[0.06]")}>
              <td className="px-4 py-2.5">
                <Link href={`/findings/${f.id}`} className="whitespace-nowrap font-semibold text-white hover:underline">{name(f.hostId)}</Link>
                <div className="font-mono text-[11px] text-dim">{f.hostId}</div>
              </td>
              <td className="px-4 py-2.5">
                <div className="font-medium">{versionBanner(f.package)}</div>
                {f.package && <div className="font-mono text-[11px] text-dim">{f.package.installedVersion}</div>}
              </td>
              <td className="px-4 py-2.5">
                <FlashOnChange value={f.status}><StatusPill status={f.status} /></FlashOnChange>
                {f.needsConfirmation && <div className="mt-1 text-[11px] text-amber-300">Pending confirmation</div>}
                <HostFixProgress hostId={f.hostId} hostName={name(f.hostId)} compact className="mt-1.5" />
              </td>
              {!compact && <td className="max-w-md px-4 py-2.5 text-xs leading-relaxed text-muted">{shortVerdictReason(f)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
