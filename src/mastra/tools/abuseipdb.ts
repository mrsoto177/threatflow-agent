import { createTool } from "@mastra/core/tools";
import { z } from "zod";

export const abuseIPDBLookup = createTool({
  id: "abuseipdb-lookup",
  description:
    "Check an IP address against the AbuseIPDB database to get its abuse confidence score, number of reports, ISP information, and usage type. Higher confidence scores indicate stronger evidence of malicious activity.",
  inputSchema: z.object({
    ipAddress: z
      .string()
      .describe("The IP address to check (IPv4 or IPv6)"),
  }),
  execute: async ({ ipAddress }) => {
    const apiKey = process.env.ABUSEIPDB_API_KEY;
    console.log("=== ABUSEIPDB TOOL CALLED ===");
    console.log("API Key present:", !!apiKey);
    console.log("IP:", ipAddress);

    if (!apiKey) {
      return { error: "ABUSEIPDB_API_KEY not configured in .env" };
    }

    try {
      const url = new URL("https://api.abuseipdb.com/api/v2/check");
      url.searchParams.set("ipAddress", ipAddress);
      url.searchParams.set("maxAgeInDays", "90");
      url.searchParams.set("verbose", "true");

      const response = await fetch(url.toString(), {
        headers: {
          Key: apiKey,
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        return {
          error: `AbuseIPDB API returned ${response.status}`,
          ipAddress,
        };
      }

      const data = await response.json();
      const result = data.data;

      return {
        ipAddress,
        abuseConfidenceScore: result.abuseConfidenceScore,
        totalReports: result.totalReports,
        lastReportedAt: result.lastReportedAt ?? "Never reported",
        isp: result.isp ?? "Unknown",
        domain: result.domain ?? "Unknown",
        usageType: result.usageType ?? "Unknown",
        countryCode: result.countryCode ?? "Unknown",
        isWhitelisted: result.isWhitelisted ?? false,
        isTor: result.isTor ?? false,
        recentCategories: (result.reports ?? [])
          .slice(0, 5)
          .map((r: { categories: number[] }) => r.categories)
          .flat()
          .filter((v: number, i: number, a: number[]) => a.indexOf(v) === i),
      };
    } catch (error) {
      return {
        error: `Failed to query AbuseIPDB: ${error instanceof Error ? error.message : "Unknown error"}`,
        ipAddress,
      };
    }
  },
});
