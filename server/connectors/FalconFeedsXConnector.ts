import { ThreatIntelConnector } from "./ThreatIntelConnector";
import type { ConnectorIntelItem, ConnectorParsingServices, ConnectorRunOptions } from "./types";

interface FalconFeedsXConfig {
  bearerToken: string;
}

export class FalconFeedsXConnector extends ThreatIntelConnector<FalconFeedsXConfig> {
  readonly metadata = {
    id: "deep-falconfeeds-x",
    sourceId: "osrc-1050",
    sourceName: "FalconFeeds.io — X ransomware alerts",
    sourceCategory: "RANSOMWARE_LEAK",
    sourceUrl: "https://x.com/FalconFeedsio",
  } as const;

  constructor(config: FalconFeedsXConfig, parsing: ConnectorParsingServices) {
    super(config, parsing);
  }

  async fetch({ sinceIso, maxItems }: ConnectorRunOptions): Promise<ConnectorIntelItem[]> {
    const token = this.config.bearerToken.trim();
    if (!token) throw new Error("not configured: add an X bearer token for FalconFeeds.io");
    const headers = { authorization: `Bearer ${token}` };
    const user = await this.fetchJson("https://api.x.com/2/users/by/username/FalconFeedsio", { headers });
    const userId = String(user?.data?.id || "");
    if (!userId) throw new Error("X API account lookup returned no FalconFeeds.io account id");

    const timelineUrl = new URL(`https://api.x.com/2/users/${encodeURIComponent(userId)}/tweets`);
    timelineUrl.searchParams.set("max_results", "100");
    timelineUrl.searchParams.set("exclude", "retweets,replies");
    timelineUrl.searchParams.set("tweet.fields", "created_at,entities");
    const timeline = await this.fetchJson(timelineUrl.toString(), { headers });
    const posts = Array.isArray(timeline?.data) ? timeline.data : [];
    const signal = /\b(ransomware|extortion|leak\s+site|data\s+leak|victim(?:s)?\s+(?:listed|claimed|announced))\b/i;
    const out: ConnectorIntelItem[] = [];

    for (const post of posts) {
      if (out.length >= maxItems) break;
      const text = this.parsing.stripHtml(String(post?.text || ""));
      if (!post?.id || !text || !signal.test(text)) continue;
      const publishedAt = this.parsing.safeDateIso(post?.created_at);
      if (publishedAt < sinceIso) continue;
      const displayText = text
        .replace(/https:\/\/t\.co\/\S+/gi, "")
        .replace(/^[^\p{L}\p{N}]+/u, "")
        .replace(/\s+/g, " ")
        .trim();
      const title = displayText.length > 220 ? `${displayText.slice(0, 217).trimEnd()}...` : displayText;
      const postUrl = `https://x.com/FalconFeedsio/status/${post.id}`;
      out.push({
        sourceId: this.metadata.sourceId,
        sourceName: this.metadata.sourceName,
        sourceCategory: this.metadata.sourceCategory,
        sourceUrl: this.metadata.sourceUrl,
        title: title || "FalconFeeds.io ransomware alert",
        url: postUrl,
        publishedAt,
        severity: this.parsing.severityFromText(text) === "critical" ? "critical" : "high",
        cveIds: this.parsing.extractCves(text),
        affectedTech: this.parsing.detectTech(text),
        threatActors: this.parsing.detectActors(text),
        summary: `Social early warning from FalconFeeds.io on X. Analyst verification required. ${displayText}`.slice(
          0,
          320,
        ),
        rawSnippet:
          `[FalconFeeds.io on X — social early warning; not independently verified]\nOriginal post: ${postUrl}\nPublished: ${publishedAt}\n\n${text}`.slice(
            0,
            2000,
          ),
      });
    }
    return out;
  }
}
