
import "dotenv/config";
import { Mastra } from "@mastra/core";
import { threatFlowAgent } from "./agents/threatflow.js";

export const mastra = new Mastra({
  agents: {
    threatFlowAgent,
  },
});