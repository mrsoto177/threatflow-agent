# 🛡️ ThreatFlow

**AI-powered security incident triage agent.** Give it an indicator of compromise (IP address, file hash or domain) and it enriches it with threat intelligence, assigns a severity level and returns a structured triage report with recommended actions — the first pass a SOC analyst would otherwise do by hand.

Built with [Mastra](https://mastra.ai) (TypeScript agent framework) and Anthropic Claude.

---

## Why

Triage of a single IoC usually means opening VirusTotal, opening AbuseIPDB, comparing the numbers, deciding a severity and writing it up in the ticket. It's repetitive, and it's easy to be inconsistent between analysts or shifts. ThreatFlow automates that loop with a fixed severity matrix and a consistent report format, so the analyst only has to review and act.

## How it works

```
 Analyst input            ThreatFlow agent (Claude)                 Output
 ─────────────            ─────────────────────────                 ──────
 "Check 185.x.x.x"  ──►   1. Identify IoC type (IP / hash / domain)
                          2. Call tools ──► virusTotalLookup  ──► VirusTotal API v3
                                        └─► abuseIPDBLookup   ──► AbuseIPDB API v2 (IPs only)
                          3. Cross-reference results
                          4. Classify with severity matrix
                          5. Write report                    ──►   Triage report
```

| Indicator | Sources queried |
|-----------|-----------------|
| IP address | VirusTotal **and** AbuseIPDB (cross-referenced) |
| File hash (MD5 / SHA1 / SHA256) | VirusTotal |
| Domain | VirusTotal |

### Severity matrix

| Severity | Rule | Recommended action |
|----------|------|--------------------|
| **CRITICAL** | VT malicious ≥ 10 **or** AbuseIPDB score ≥ 80 | Isolate immediately, block at firewall, escalate to SOC lead |
| **HIGH** | VT malicious ≥ 5 **or** AbuseIPDB score ≥ 50 | Block at perimeter, investigate affected systems, watch for lateral movement |
| **MEDIUM** | VT malicious ≥ 2 **or** AbuseIPDB score ≥ 20 | Add to watchlist, increase logging, review next triage cycle |
| **LOW** | Minimal detections, some suspicious signals | Log for baseline |
| **CLEAN** | No significant detections | Close ticket |

When in doubt the agent is instructed to classify **one level higher**, and if a source fails it reports the failure and continues with the data it has.

### Report format

Every response includes: **Indicator** (and type) · **Severity** · **Summary** (2–3 sentences) · **Intelligence sources** (raw numbers from each tool) · **Recommended actions**.

## Project structure

```
src/mastra/
├── index.ts               # Mastra instance, registers the agent
├── agents/
│   └── threatflow.ts      # Agent definition: instructions, severity matrix, model, tools
└── tools/
    ├── virustotal.ts      # VirusTotal v3 lookup (IP / hash / domain), Zod-validated input
    └── abuseipdb.ts       # AbuseIPDB v2 check (confidence score, reports, ISP, Tor, categories)
```

Each tool validates its input with **Zod**, normalizes the API response into a small, predictable object, and returns an `error` field instead of throwing — so the agent can degrade gracefully when one source is down or rate-limited.

## Getting started

### Requirements

- Node.js 20+
- API keys (all have free tiers):
  - [Anthropic](https://console.anthropic.com)
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey)
  - [AbuseIPDB](https://www.abuseipdb.com/account/api)

### Setup

```bash
git clone https://github.com/mrsoto177/threatflow-agent.git
cd threatflow-agent
npm install
cp .env.example .env    # then fill in your keys
npm run dev
```

`npm run dev` starts the Mastra dev playground (by default at `http://localhost:4111`). Open it, select the **ThreatFlow** agent and send an indicator, for example:

```
Triage this IP: 8.8.8.8
Check this hash: 44d88612fea8a8f36de82e1278abb02f
Is evil-example.com malicious?
```

> The hash above is the standard EICAR test file — safe to use for testing detections.

## Tech stack

TypeScript · Mastra · Anthropic Claude (Haiku 4.5) · Zod · VirusTotal API v3 · AbuseIPDB API v2

## Built with AI assistance

I used Claude as a pair programmer throughout: to scaffold the Mastra project, iterate on the agent instructions and severity matrix, and debug the tool integrations. Design decisions — which sources to trust for which IoC type, the thresholds, the fail-soft tool behavior — and testing against real indicators were mine.

## Roadmap

- [ ] Batch mode: triage a list of IoCs from a CSV and export results
- [ ] Additional sources (URLhaus, AlienVault OTX, Shodan)
- [ ] Structured JSON output for ticketing integrations (e.g. creating incidents in ServiceNow)
- [ ] Cache lookups to stay within free-tier rate limits
