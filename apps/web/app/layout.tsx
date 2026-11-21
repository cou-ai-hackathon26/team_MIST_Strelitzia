import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Prohori · AI security sentinel",
  description: "Prohori (প্রহরী) — live inventory, real exposure analysis and human-approved fixes for servers.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen font-sans">{children}</body>
    </html>
  );
}
