import { createTool } from "@mastra/core/tools";
import { z } from "zod";

export const virusTotalLookup = createTool({
  id: "virustotal-lookup",
  description:
    "Look up an IP address, file hash (MD5/SHA1/SHA256), or domain in VirusTotal to check for malicious activity reports from security vendors.",
  inputSchema: z.object({
    indicator: z
      .string()
      .describe("The indicator to look up: an IP address, file hash, or domain"),
    type: z
      .enum(["ip", "hash", "domain"])
      .describe("The type of indicator being looked up"),
  }),
execute: async ({ indicator, type }) => {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    console.log("=== VT TOOL CALLED ===");
    console.log("API Key present:", !!apiKey);
    console.log("Indicator:", indicator, "Type:", type);
    if (!apiKey) {
      return { error: "VIRUSTOTAL_API_KEY not configured in .env" };
    }

    const endpoints: Record<string, string> = {
      ip: `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`,
      hash: `https://www.virustotal.com/api/v3/files/${indicator}`,
      domain: `https://www.virustotal.com/api/v3/domains/${indicator}`,
    };

    try {
      const response = await fetch(endpoints[type], {
        headers: { "x-apikey": apiKey },
      });

      if (!response.ok) {
        return {
          error: `VirusTotal API returned ${response.status}`,
          indicator,
          type,
        };
      }

      const data = await response.json();
      const stats = data.data?.attributes?.last_analysis_stats;
      const reputation = data.data?.attributes?.reputation;
      const country = data.data?.attributes?.country;
      const asOwner = data.data?.attributes?.as_owner;

      return {
        indicator,
        type,
        malicious: stats?.malicious ?? 0,
        suspicious: stats?.suspicious ?? 0,
        harmless: stats?.harmless ?? 0,
        undetected: stats?.undetected ?? 0,
        totalEngines:
          (stats?.malicious ?? 0) +
          (stats?.suspicious ?? 0) +
          (stats?.harmless ?? 0) +
          (stats?.undetected ?? 0),
        reputation: reputation ?? "N/A",
        country: country ?? "Unknown",
        networkOwner: asOwner ?? "Unknown",
      };
    } catch (error) {
      return {
        error: `Failed to query VirusTotal: ${error instanceof Error ? error.message : "Unknown error"}`,
        indicator,
        type,
      };
    }
  },
});
