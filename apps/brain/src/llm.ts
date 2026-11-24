import { createAnthropic } from "@ai-sdk/anthropic";
import { env } from "./env";

/** Anthropic-format model via OpenCode Go; `sessionId` becomes the x-opencode-session header. */
export function modelFor(sessionId: string) {
  const anthropic = createAnthropic({
    baseURL: env.llm.baseURL,
    apiKey: env.llm.apiKey,
    headers: { "x-opencode-session": sessionId, "User-Agent": env.llm.userAgent },
  });
  // @ai-sdk/anthropic v4 types lag Mastra's MastraLanguageModelV4 typing; runtime is compatible (verified).
  return anthropic(env.llm.model) as any;
}
