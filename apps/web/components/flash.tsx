"use client";

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

/** Briefly highlights its children when `value` changes after the first render (e.g. a verdict transition). */
export function FlashOnChange({ value, children, className }: { value: string; children: React.ReactNode; className?: string }) {
  const prev = useRef(value);
  const [flash, setFlash] = useState(false);
  useEffect(() => {
    if (prev.current === value) return;
    prev.current = value;
    setFlash(true);
    const t = setTimeout(() => setFlash(false), 4000);
    return () => clearTimeout(t);
  }, [value]);
  return (
    <span className={cn("inline-block rounded-md transition-shadow duration-700", flash && "animate-flash ring-2 ring-blue-400/80 ring-offset-2 ring-offset-panel", className)}>
      {children}
    </span>
  );
}
