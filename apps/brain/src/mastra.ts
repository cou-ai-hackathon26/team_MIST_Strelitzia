import { Mastra } from "@mastra/core/mastra";
import { LibSQLStore } from "@mastra/libsql";
import { env } from "./env";
import { prohoriAgent } from "./agent/prohori";
import { scanWorkflow } from "./scan/workflow";

export const mastra = new Mastra({
  agents: { prohori: prohoriAgent },
  workflows: { scanWorkflow },
  storage: new LibSQLStore({ id: "prohori-mastra", url: `file:${env.mastraDbPath}` }),
});
