import assert from "node:assert/strict";
import { it } from "vitest";
import { OSINT_SOURCES, REMOVED_OSINT_SOURCE_IDS } from "../server/osintSeed";

it("keeps the OSINT source catalog well formed", () => {
  const byId = new Map(OSINT_SOURCES.map((source) => [source.id, source]));

  assert.equal(byId.size, OSINT_SOURCES.length, "OSINT source ids must be unique");

  for (const source of OSINT_SOURCES) {
    assert.match(source.id, /^osrc-[0-9a-z]+$/i, `${source.name} has an invalid source id`);
    assert.ok(source.name.trim(), `${source.id} is missing a source name`);
    assert.ok(source.url.startsWith("http://") || source.url.startsWith("https://"), `${source.name} has a non-HTTP URL`);
    assert.match(source.reliability, /^[ABCD]$/, `${source.name} has an invalid reliability rating`);
  }

  for (const id of REMOVED_OSINT_SOURCE_IDS) {
    assert.equal(byId.has(id), false, `${id} is a known zero-parse or non-public source and must stay pruned`);
  }

  const expectedFeeds = new Map([
    ["osrc-0261", "http://feeds.feedburner.com/OfficeOfInadequateSecurity"],
    ["osrc-0282", "https://feeds.feedburner.com/eset/blog"],
    ["osrc-0334", "https://grahamcluley.com/feed/"],
    ["osrc-0348", "https://labs.infoguard.ch/rss.xml"],
  ]);

  for (const [id, url] of expectedFeeds) {
    assert.equal(byId.get(id)?.url, url, `${id} should use the reviewed canonical feed URL`);
  }
});
