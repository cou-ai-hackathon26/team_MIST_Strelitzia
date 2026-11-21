import nodemailer from "nodemailer";
import { marked } from "marked";
import { env } from "./env";

const transport = nodemailer.createTransport({
  host: env.smtpHost,
  port: env.smtpPort,
  secure: false,
  ignoreTLS: true,
  connectionTimeout: 10_000,
});

export function markdownToHtml(md: string): string {
  const body = marked.parse(md, { async: false }) as string;
  return `<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:860px;margin:auto;line-height:1.5;color:#111">
<style>table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left}code{background:#f4f4f4;padding:1px 4px}</style>
${body}
<hr><p style="color:#666;font-size:12px">Sent by Sentinel, Prohori's AI agent. Fixes are only applied after human approval in the dashboard.</p></body></html>`;
}

export async function sendReportEmail(to: string[], subject: string, markdown: string) {
  if (!to.length) throw new Error("no recipients configured");
  await transport.sendMail({ from: env.reportFrom, to: to.join(", "), subject, text: markdown, html: markdownToHtml(markdown) });
}
