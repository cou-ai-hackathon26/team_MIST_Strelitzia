import { cn } from "@/lib/utils";

export function ShieldMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={cn("size-8", className)} aria-hidden>
      <defs>
        <linearGradient id="pg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#60a5fa" />
          <stop offset="1" stopColor="#2563eb" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V7L16 2.5Z" fill="url(#pg)" />
      <path d="M16 6.2 8 9.4v5.9c0 5 3.3 8.9 8 10.5V6.2Z" fill="#fff" fillOpacity=".18" />
      <path d="m11.2 15.8 3.4 3.4 6.4-6.6" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <ShieldMark />
      <div className="leading-tight">
        <div className="font-display text-[18px] text-white">Prohori</div>
      </div>
    </div>
  );
}
