import type { Metadata } from "next";
import { Audiowide } from "next/font/google";
import "./globals.css";

const display = Audiowide({ weight: "400", subsets: ["latin"], display: "swap", variable: "--font-audiowide" });

export const metadata: Metadata = {
  title: "Prohori · AI security sentinel",
  description: "Prohori (প্রহরী) — live inventory, real exposure analysis and human-approved fixes for servers.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`dark ${display.variable}`}>
      <body className="min-h-screen font-sans">{children}</body>
    </html>
  );
}
