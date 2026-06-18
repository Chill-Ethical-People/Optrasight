import { BATCH_ONE_AI_TASKS, type AiProviderKind } from "@shared/schema";
import { STATIC_OSINT_SOURCES } from "./staticOsintSources";

export const STATIC_DEMO_MODE = import.meta.env.VITE_OPTRASIGHT_STATIC_DEMO === "1";

const now = new Date("2026-06-17T08:30:00.000Z");
const iso = (offsetHours = 0) => new Date(now.getTime() + offsetHours * 3_600_000).toISOString();
const assetPath = (path: string) => `${import.meta.env.BASE_URL}${path.replace(/^\/+/, "")}`;

export const STATIC_DEMO_USER = {
  id: "demo-admin",
  email: "admin@cep.com",
  role: "admin",
  tenant: { id: "batchone", name: "BatchOne", slug: "batchone", plan: "public-demo" },
  passwordMustChange: false,
  mfaEnabled: true,
  mfaVerifiedAt: iso(-24),
  access_mode: "credentialed" as const,
  capabilities: ["manage_users", "manage_ai", "manage_osint", "manage_tap", "view_jobs"],
};

type FindingSeed = [
  id: string,
  sourceId: string,
  sourceName: string,
  sourceCategory: string,
  title: string,
  severity: string,
  intelCategory: string,
  score: number,
  techniques: string[],
  actors: string[],
  affectedTech: string[],
];

const normalizeKey = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_|_$/g, "");

const sourceKind = (url: string) =>
  /(json|api|github|osv\.dev|cve\.circl|ransomware\.live)/i.test(url) ? "web" : "rss";

const sources = STATIC_OSINT_SOURCES.map((source, index) => ({
  ...source,
  englishName: source.name,
  language: "en",
  kind: sourceKind(source.url),
  lastFetchedAt: iso(-index - 1),
  enabled: true,
}));
const sourceById = new Map(sources.map((source) => [source.id, source]));

const findings = (
  [
    [
      "f-001",
      "osrc-0348",
      "InfoGuard Labs",
      "Vendor Threat Research",
      "New ransomware playbook chains stolen VPN credentials with cloud backup deletion",
      "high",
      "threat_intel",
      86,
      ["T1078", "T1486"],
      ["RansomHub"],
      ["VPN", "Cloud backup"],
    ],
    [
      "f-002",
      "osrc-0279",
      "Microsoft Threat Intelligence",
      "Vendor Threat Research",
      "Threat cluster pivots through unmanaged edge devices before identity abuse",
      "high",
      "threat_intel",
      82,
      ["T1190", "T1021"],
      ["APT41"],
      ["VPN", "Active Directory"],
    ],
    [
      "f-003",
      "osrc-0304",
      "Malwarebytes Labs",
      "Vendor Threat Research",
      "Hands-on-keyboard intrusion uses remote support tooling and data staging",
      "medium",
      "threat_intel",
      74,
      ["T1219", "T1074"],
      ["Scattered Spider"],
      ["Remote support", "File shares"],
    ],
    [
      "f-004",
      "osrc-0058",
      "Fortinet - PSIRT RSS",
      "Vendor Threat Research",
      "Loader campaign shifts delivery infrastructure and rotates command nodes",
      "medium",
      "regular_report",
      68,
      ["T1105", "T1027"],
      ["TA505"],
      ["Windows endpoint"],
    ],
    [
      "f-005",
      "osrc-0001",
      "NVD CVE API - recent",
      "CVE & Vulnerability DBs",
      "Critical appliance vulnerability added to public exploitation watchlist",
      "critical",
      "threat_intel",
      91,
      ["T1190"],
      ["Cl0p"],
      ["Edge appliance"],
    ],
    [
      "f-006",
      "osrc-0282",
      "ESET WeLiveSecurity",
      "Vendor Threat Research",
      "Espionage group refreshes spearphishing lure themes against public sector",
      "medium",
      "threat_intel",
      77,
      ["T1566"],
      ["APT31"],
      ["Email gateway"],
    ],
    [
      "f-007",
      "osrc-0034",
      "GitHub Advisory DB (GHSA mirror)",
      "CVE & Vulnerability DBs",
      "Dependency advisory affects exposed admin console packages",
      "low",
      "regular_report",
      51,
      ["T1190"],
      [],
      ["Node.js", "Admin UI"],
    ],
    [
      "f-008",
      "osrc-0266",
      "Dark Reading",
      "Security News & Press",
      "Name That Toon Contest",
      "info",
      "advertisement",
      5,
      [],
      [],
      [],
    ],
    [
      "f-009",
      "osrc-0263",
      "KrebsOnSecurity",
      "Security News & Press",
      "Credential-stuffing lessons from breach corpus reuse",
      "medium",
      "regular_report",
      62,
      ["T1110"],
      ["8Base"],
      ["Identity"],
    ],
    [
      "f-012",
      "osrc-0265",
      "The Hacker News",
      "Security News & Press",
      "Supply-chain alert: malicious npm packages target Solana private keys",
      "critical",
      "threat_intel",
      92,
      ["T1195", "T1552", "T1041"],
      [],
      ["npm", "Solana wallets", "Developer workstations"],
    ],
    [
      "f-013",
      "osrc-0264",
      "BleepingComputer",
      "Security News & Press",
      "DragonForce ransomware abuses Microsoft Teams for social-engineering relay",
      "high",
      "threat_intel",
      84,
      ["T1566", "T1204", "T1219"],
      ["DragonForce"],
      ["Microsoft Teams", "Remote support", "Identity"],
    ],
    [
      "f-014",
      "osrc-0265",
      "The Hacker News",
      "Security News & Press",
      "ClickFix-style campaigns deliver DeerStealer and Odyssey infostealers",
      "high",
      "threat_intel",
      81,
      ["T1204", "T1059", "T1555"],
      [],
      ["Browser credentials", "Windows endpoint", "macOS endpoint"],
    ],
    [
      "f-015",
      "osrc-0264",
      "BleepingComputer",
      "Security News & Press",
      "Fortinet FortiSandbox command injection exploited after public PoC",
      "high",
      "threat_intel",
      79,
      ["T1190", "T1059"],
      [],
      ["FortiSandbox", "Edge appliance"],
    ],
    [
      "f-016",
      "osrc-0265",
      "The Hacker News",
      "Security News & Press",
      "Critical Sitecore Experience Platform flaw allows unauthenticated remote code execution",
      "critical",
      "threat_intel",
      90,
      ["T1190", "T1059"],
      [],
      ["Sitecore XP", "Internet-facing CMS"],
    ],
    [
      "f-011",
      "osrc-0289",
      "The DFIR Report",
      "Vendor Threat Research",
      "DFIR flash alert: EtherRAT and TukTuk C2 lead to The Gentlemen ransomware",
      "high",
      "threat_intel",
      89,
      ["T1219", "T1074", "T1041", "T1486", "T1558", "T1003"],
      ["The Gentlemen"],
      ["Windows endpoint", "Remote support", "Active Directory", "Wasabi storage"],
    ],
    [
      "f-010",
      "osrc-0334",
      "Graham Cluley",
      "Security News & Press",
      "Phishing kit operators adopt inbox rule persistence",
      "medium",
      "threat_intel",
      71,
      ["T1114", "T1098"],
      ["Black Basta"],
      ["Microsoft 365"],
    ],
  ] as FindingSeed[]
).map(
  (
    [id, sourceId, sourceName, sourceCategory, title, severity, intelCategory, score, techs, actors, affected],
    index,
  ) => ({
    id,
    tenantId: "batchone",
    sourceId,
    sourceName,
    sourceCategory,
    title,
    url: `https://example.com/optrasight-demo/${id}`,
    publishedAt: iso(-72 - index * 7),
    severity,
    cveIds: index === 4 ? ["CVE-2026-1024"] : [],
    affectedTech: affected,
    threatActors: actors,
    iocs: index === 0 ? { domain: ["vpn-update.example"], ipv4: ["203.0.113.24"] } : {},
    summary: `${title}. The public demo preserves source, publish date, ingestion date, and evidence context without calling live providers.`,
    aiSummary:
      intelCategory === "advertisement"
        ? "This item is non-actionable media and should remain hidden when advertisement filtering is enabled."
        : `OptraSight assesses this item as ${severity} priority because it includes actionable tradecraft and source context for analyst review.`,
    aiRelevanceScore: score,
    aiRecommendation:
      intelCategory === "advertisement"
        ? "Suppress similar non-intel items during review."
        : "Review source context, map durable TTPs, and draft a hunt query where telemetry is available.",
    aiAnalyzedAt: iso(-3 - index),
    aiProviderLabel: "Static demo AI",
    draftEmail: null,
    draftEmailAt: null,
    status: index < 3 ? "triaged" : "new",
    createdAt: iso(-48 - index),
    rawSnippet: `${title}. Demo snippet with source-linked context for the public static build.`,
    analystTags: actors.length ? ["actor-linked", "hunt-candidate"] : ["review"],
    analystEditedAt: null,
    analystEditedBy: null,
    intelCategory,
    attackTechniques: (techs as string[]).map((id) => ({ id, name: attackName(id), tactic: "enterprise" })),
    sectors: ["Technology", "Financial Services"],
    regions: ["Global"],
    clusterId: `cluster-${Math.floor(index / 2) + 1}`,
  }),
);

function attackName(id: string) {
  const names: Record<string, string> = {
    T1078: "Valid Accounts",
    T1486: "Data Encrypted for Impact",
    T1041: "Exfiltration Over C2 Channel",
    T1195: "Supply Chain Compromise",
    T1552: "Unsecured Credentials",
    T1190: "Exploit Public-Facing Application",
    T1021: "Remote Services",
    T1219: "Remote Access Software",
    T1074: "Data Staged",
    T1105: "Ingress Tool Transfer",
    T1027: "Obfuscated Files or Information",
    T1566: "Phishing",
    T1204: "User Execution",
    T1059: "Command and Scripting Interpreter",
    T1555: "Credentials from Password Stores",
    T1558: "Steal or Forge Kerberos Tickets",
    T1003: "OS Credential Dumping",
    T1110: "Brute Force",
    T1114: "Email Collection",
    T1098: "Account Manipulation",
  };
  return names[id] ?? id;
}

const providers = [
  provider("provider-deepseek", "deepseek", "DeepSeek", "deepseek-chat", true),
  provider("provider-gemini", "gemini", "Google Gemini", "gemini-flash-latest", false),
  provider("provider-openai", "openai", "OpenAI", "gpt-4.1-mini", false),
];

function provider(id: string, kind: AiProviderKind, label: string, model: string, enabled: boolean) {
  return {
    id,
    provider: kind,
    label,
    model,
    baseUrl: null,
    enabled,
    isDefault: enabled,
    hasKey: false,
    apiKeyMask: null,
    lastTestedAt: enabled ? iso(-6) : null,
    lastTestOk: enabled ? true : null,
    lastTestMessage: enabled ? `${label} is available in static demo mode.` : null,
    updatedAt: iso(-6),
  };
}

const assignments = Object.fromEntries(BATCH_ONE_AI_TASKS.map((task) => [task, "provider-deepseek"]));

const actors = [
  actor(
    "tap-clop",
    "TAP-003",
    "Cl0p",
    "Ransomware-as-a-Service",
    ["TA505 sub-cluster", "Lace Tempest"],
    assetPath("demo/portraits/Cl0p.png"),
    "HIGH",
    ["Financial Services", "Technology"],
    ["Global", "North America"],
    ["T1190", "T1041", "T1486"],
  ),
  actor(
    "tap-ransomhub",
    "TAP-008",
    "RansomHub",
    "Ransomware-as-a-Service",
    ["Cyclops rebrand", "Knight rebrand"],
    assetPath("demo/portraits/RansomHub.png"),
    "HIGH",
    ["Healthcare", "Manufacturing"],
    ["Global", "North America"],
    ["T1078", "T1486", "T1041"],
  ),
  actor(
    "tap-black-basta",
    "TAP-010",
    "Black Basta",
    "Ransomware-as-a-Service",
    ["Storm-1811", "Cardinal cybercrime group"],
    assetPath("demo/portraits/Black_Basta.png"),
    "HIGH",
    ["Manufacturing", "Healthcare"],
    ["North America", "Europe"],
    ["T1566", "T1219", "T1486"],
  ),
  actor(
    "tap-ta505",
    "TAP-013",
    "TA505",
    "Organized Cybercrime",
    ["GOLD TAHOE", "Hive0065", "SectorJ04"],
    assetPath("demo/portraits/TA505.png"),
    "MODERATE",
    ["Financial Services", "Retail"],
    ["Global"],
    ["T1105", "T1027", "T1059"],
  ),
  actor(
    "tap-8base",
    "TAP-089",
    "8Base",
    "Ransomware-as-a-Service",
    [],
    assetPath("demo/portraits/8Base.png"),
    "HIGH",
    ["Manufacturing", "Healthcare"],
    ["North America", "Europe"],
    ["T1078", "T1110", "T1486"],
  ),
  actor(
    "tap-the-gentlemen",
    "TAP-117",
    "The Gentlemen",
    "Ransomware-as-a-Service",
    ["Gentlemen ransomware"],
    assetPath("demo/portraits/The_Gentlemen.png"),
    "HIGH",
    ["Technology", "Professional Services"],
    ["Global"],
    ["T1219", "T1074", "T1041", "T1486", "T1558", "T1003"],
  ),
];

function actor(
  id: string,
  profileId: string,
  primaryName: string,
  actorType: string,
  aliases: string[],
  portraitUrl: string,
  threatLevel: string,
  sectors: string[],
  regions: string[],
  techniques: string[],
) {
  const createdAt = iso(-240 + Number(profileId.slice(-3)));
  const ttps = techniques.map((techniqueId, index) => ({
    id: `${id}-ttp-${index}`,
    actorId: id,
    tactic: techniqueId === "T1486" ? "Impact" : techniqueId === "T1566" ? "Initial Access" : "Execution",
    techniqueId,
    subTechniqueId: null,
    techniqueName: attackName(techniqueId),
    evidence: `${primaryName} reporting references ${attackName(techniqueId)} in recent public analysis.`,
    status: "observed",
    detectionPriority: index === 0 ? "high" : "medium",
    createdAt,
  }));
  return {
    id,
    tenantId: "batchone",
    profileId,
    primaryName,
    mitreGroupId: aliases.find((a) => /^APT|^TA|^FIN|^UNC|^GOLD|^Storm/i.test(a)) ?? null,
    aliases,
    vendorNames: aliases.length ? { "Public reporting": aliases } : {},
    actorType,
    sponsorship: "Independent",
    assessedOrigin: "Unknown",
    originConfidence: "Likely",
    sponsoringEntity: "Independent",
    motivation: actorType.includes("Ransomware") ? ["Financial", "Extortion"] : ["Financial"],
    activeSince: 2019,
    sophistication: threatLevel === "HIGH" ? "Advanced" : "Intermediate",
    tlp: "AMBER",
    admiraltySource: "B",
    admiraltyInfo: "2",
    wepConfidence: "Likely",
    targetSectors: sectors,
    targetRegions: regions,
    targetTechStack: ["Microsoft 365", "VPN", "Active Directory"],
    orgSizePreference: "Enterprise",
    intentProximity: "Near-term",
    relevanceRating: "Priority",
    execWhat: `${primaryName} is tracked for repeatable intrusion behavior and operationally relevant tradecraft.`,
    execSoWhat: `${primaryName} matters because its tradecraft can produce material tenant impact through data theft, extortion, or operational disruption.`,
    execWhatNow:
      "Review the mapped ATT&CK techniques, compare detection coverage, and queue hunt queries against available telemetry.",
    threatLevel,
    threatLevelRationale: "Recent reporting, reusable TTPs, and observable impact justify continued monitoring.",
    sectorActivelyTargeted: true,
    diamondAdversary: { summary: `${primaryName} operator cluster`, confidence: "Likely" },
    diamondCapability: {
      malware: aliases.slice(0, 2),
      tooling: ["Remote access", "Credential access"],
      confidence: "Likely",
    },
    diamondInfrastructure: { patterns: ["Rotating VPS", "Compromised accounts"], confidence: "Possible" },
    diamondVictim: { sectors, regions, confidence: "Likely" },
    diamondMeta: { confidence: "Likely", rank: "Priority", cutoff: iso(-48), sourceCount: 3 },
    businessImpact: {
      confidentiality: "High",
      integrity: "Moderate",
      availability: "High",
      regulatory: "Potential breach notification and third-party risk exposure",
    },
    capabilityProfile: {
      tier: threatLevel === "HIGH" ? "Advanced" : "Intermediate",
      tooling: ["Rclone", "Mimikatz", "PowerShell"],
      coordination: "Independent",
      evidence: "Public reports describe repeatable tradecraft and operational maturity.",
    },
    infrastructureProfile: {
      hosting: "Rotating infrastructure",
      c2: "Short-lived command nodes",
      delivery: "Phishing and exposed services",
    },
    irActions: {
      immediate: "Validate exposure, preserve logs, and isolate impacted identities.",
      shortTerm: "Hunt for mapped TTPs and review EDR telemetry.",
      mediumTerm: "Tune controls and refresh detection coverage.",
    },
    countermeasures: { identity: "MFA and conditional access", endpoint: "EDR coverage", network: "Egress review" },
    forecast: "Activity is expected to remain opportunistic and source-driven. Confidence is moderate.",
    extortionTactics: { pressure: "Data leak and business disruption threats" },
    bodyMd: null,
    status: "approved",
    version: Number(profileId.slice(-1)) || 3,
    cutoffDate: iso(-48),
    preparedBy: "OptraSight static demo",
    aiProviderLabel: "Static demo AI",
    portraitUrl,
    portraitGeneratedAt: iso(-72),
    portraitStatus: "ready",
    createdAt,
    updatedAt: iso(-24),
    createdBy: "demo-admin",
    ttps,
    tools: [
      {
        id: `${id}-tool-1`,
        actorId: id,
        name: "Rclone",
        category: "Exfiltration",
        purpose: "Data transfer",
        variants: [],
        hashOrRule: null,
        confidence: "Likely",
        createdAt,
      },
      {
        id: `${id}-tool-2`,
        actorId: id,
        name: "PowerShell",
        category: "Living-off-the-land",
        purpose: "Execution and discovery",
        variants: [],
        hashOrRule: null,
        confidence: "Likely",
        createdAt,
      },
    ],
    campaigns: [
      {
        id: `${id}-campaign-1`,
        actorId: id,
        name: `${primaryName} public reporting wave`,
        period: "2025-2026",
        targetSector: sectors[0] ?? null,
        targetGeography: regions[0] ?? null,
        initialAccess: "Valid accounts",
        outcome: "Data theft and extortion pressure",
        sourceUrl: "https://example.com/optrasight-demo/campaign",
        findingIds: ["f-001"],
        ruleIds: [],
        createdAt,
      },
    ],
    iocs: [
      {
        id: `${id}-ioc-1`,
        actorId: id,
        iocType: "domain",
        value: `${primaryName.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-cdn.example`,
        firstSeen: iso(-220),
        lastConfirmed: iso(-24),
        confidence: "Possible",
        tlp: "AMBER",
        source: "Static demo source",
        mitreTtps: techniques.slice(0, 2),
        recommendedAction: "Use for scoping only; prioritize TTP-based hunting.",
        createdAt,
      },
    ],
    references: [
      {
        id: `${id}-ref-1`,
        actorId: id,
        refNum: 1,
        sourceType: "Vendor research",
        title: `${primaryName} public profile notes`,
        date: iso(-96),
        url: "https://example.com/optrasight-demo/reference",
        archiveUrl: null,
        createdAt,
      },
    ],
    ruleLinks: [
      {
        id: `${id}-rule-1`,
        actorId: id,
        ruleId: "rule-001",
        priority: "high",
        notes: "Demo mapped coverage for core tradecraft.",
        ruleTitle: "Suspicious Remote Access Tool Execution",
        ruleStatus: "validated",
        ruleMitreTechniques: ttps
          .slice(0, 1)
          .map((t) => ({ id: t.techniqueId, name: t.techniqueName, tactic: t.tactic })),
        createdAt,
      },
    ],
    relevantTenants: [],
  };
}

let huntQueries = [
  hunt(
    "hq-001",
    "Ransomware credential-to-encryption hunt",
    ["f-001", "f-005"],
    "splunk",
    "index=edr (process_name=rclone OR process_name=vssadmin) user=* | stats count by host,user,process_name",
  ),
  hunt(
    "hq-002",
    "Edge appliance exploitation review",
    ["f-002", "f-005"],
    "kql",
    "DeviceNetworkEvents | where RemoteUrl has_any ('vpn','gateway') | summarize count() by DeviceName, RemoteUrl",
  ),
  hunt(
    "hq-003",
    "Remote support tooling abuse",
    ["f-003"],
    "sigma",
    "title: Remote Support Tool Abuse\nlogsource:\n  product: windows\ncondition: selection",
  ),
  hunt(
    "hq-004",
    "Mailbox rule persistence",
    ["f-010"],
    "kql",
    "CloudAppEvents | where ActionType has 'New-InboxRule' | project Timestamp, AccountDisplayName, RawEventData",
  ),
  hunt(
    "hq-005",
    "Loader infrastructure rotation",
    ["f-004"],
    "splunk",
    "index=proxy uri_domain=* | stats dc(uri_domain) as domains by src_ip | where domains > 20",
  ),
  hunt("hq-006", "DFIR EtherRAT to The Gentlemen ransomware hunt pack", ["f-011"], {
    splunk:
      'index=edr ("RAMMap" OR "EtherRAT" OR "TukTuk" OR "1rpc.io" OR "trycloudflare.com" OR "GoTo Resolve" OR "NetExec" OR "mimikatz" OR "ntds.dit" OR "rclone" OR "Wasabi" OR "vssadmin delete shadows" OR "wevtutil cl") | stats earliest(_time) as first latest(_time) as last values(process_name) as tools values(CommandLine) as commands by host,user',
    kql: 'DeviceProcessEvents | where ProcessCommandLine has_any ("RAMMap","EtherRAT","TukTuk","1rpc.io","trycloudflare.com","GoTo Resolve","NetExec","mimikatz","ntds.dit","rclone","Wasabi","vssadmin delete shadows","wevtutil cl") or FileName in~ ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe") | summarize Tools=make_set(FileName), Commands=make_set(ProcessCommandLine) by DeviceName, AccountName',
    sigma:
      "title: EtherRAT TukTuk Rclone Ransomware Staging\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection_cmd:\n    CommandLine|contains:\n      - 'RAMMap'\n      - 'EtherRAT'\n      - 'TukTuk'\n      - '1rpc.io'\n      - 'trycloudflare.com'\n      - 'GoTo Resolve'\n      - 'Wasabi'\n      - 'ntds.dit'\n      - 'vssadmin delete shadows'\n      - 'wevtutil cl'\n  selection_tools:\n    Image|endswith:\n      - '\\\\rclone.exe'\n      - '\\\\netexec.exe'\n      - '\\\\nxc.exe'\n      - '\\\\mimikatz.exe'\n      - '\\\\vssadmin.exe'\n      - '\\\\wevtutil.exe'\n  condition: selection_cmd or selection_tools",
    chronicle:
      'metadata.event_type = "PROCESS_LAUNCH" and (principal.process.command_line = /(?i)(RAMMap|EtherRAT|TukTuk|1rpc\\.io|trycloudflare|GoTo Resolve|NetExec|mimikatz|ntds\\.dit|Wasabi|rclone|vssadmin delete shadows|wevtutil cl)/ or principal.process.file.full_path = /(?i)(rclone|netexec|nxc|mimikatz|vssadmin|wevtutil)\\.exe/)',
    cortex_xdr:
      'dataset = xdr_data | filter action_process_image_command_line contains "EtherRAT" or action_process_image_command_line contains "TukTuk" or action_process_image_command_line contains "trycloudflare.com" or action_process_image_command_line contains "Wasabi" or action_process_image_name in ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe")',
    crowdstrike:
      '#event_simpleName=ProcessRollup2 (CommandLine="*EtherRAT*" OR CommandLine="*TukTuk*" OR CommandLine="*trycloudflare*" OR CommandLine="*Wasabi*" OR CommandLine="*ntds.dit*" OR FileName="rclone.exe" OR FileName="netexec.exe" OR FileName="nxc.exe" OR FileName="mimikatz.exe" OR FileName="vssadmin.exe" OR FileName="wevtutil.exe")',
    sentinelone:
      'EventType = "Process Creation" AND (CmdLine Contains AnyCase ("EtherRAT","TukTuk","1rpc.io","trycloudflare.com","Wasabi","ntds.dit","vssadmin delete shadows","wevtutil cl") OR TgtProcName In Contains AnyCase ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe"))',
    defender:
      'DeviceProcessEvents | where ProcessCommandLine has_any ("RAMMap","EtherRAT","TukTuk","1rpc.io","trycloudflare.com","GoTo Resolve","NetExec","mimikatz","ntds.dit","rclone","Wasabi","vssadmin delete shadows","wevtutil cl") or FileName in~ ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe") | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine',
  }),
];

function hunt(
  id: string,
  title: string,
  sourceFindingIds: string[],
  langOrQueries: string | Record<string, string>,
  query = "",
) {
  return {
    id,
    tenantId: "batchone",
    title,
    description: "Static demo hunt query generated from selected OSINT findings.",
    sourceFindingIds,
    affectedTech: ["Endpoint", "Identity"],
    queries: typeof langOrQueries === "string" ? { [langOrQueries]: query } : langOrQueries,
    aiProviderLabel: "Static demo AI",
    createdAt: iso(-8),
    createdBy: "demo-admin",
  };
}

const aiJobs = [
  job(
    "job-tap-002",
    "threat_actor_enrichment",
    "completed",
    100,
    "TAP analysis - The Gentlemen",
    "#/threat-actors?focus=tap-the-gentlemen",
    -1.5,
  ),
  job(
    "job-tap-001",
    "threat_actor_enrichment",
    "completed",
    100,
    "TAP analysis - RansomHub",
    "#/threat-actors?focus=tap-ransomhub",
    -2,
  ),
  job(
    "job-hunt-001",
    "hunt_query_generation",
    "completed",
    100,
    "Hunt query - DFIR EtherRAT to The Gentlemen ransomware",
    "#/osint?tab=hunt&hunt=hq-006",
    -3,
  ),
  job(
    "job-osint-001",
    "osint_analysis",
    "completed",
    100,
    "OSINT AI analysis - 3 selected",
    "#/osint?finding=f-001",
    -4,
  ),
  job("job-cirt-001", "chat_triage", "completed", 100, "CIRT triage - 7d", "#/osint?ai=triage&job=job-cirt-001", -5),
  job(
    "job-deep-001",
    "chat_deep_dive",
    "completed",
    100,
    "CIRT deep-dive - selected findings",
    "#/osint?ai=deep-dive&job=job-deep-001",
    -6,
  ),
];

function job(
  id: string,
  kind: string,
  status: string,
  progressPct: number,
  targetLabel: string,
  targetUrl: string,
  offset: number,
) {
  return {
    id,
    kind,
    status,
    progressPct,
    providerLabel: "Static demo AI",
    createdBy: "demo-admin",
    createdAt: iso(offset - 0.2),
    startedAt: iso(offset - 0.15),
    completedAt: status === "running" ? null : iso(offset),
    targetLabel,
    targetUrl,
    heartbeatAt: status === "running" ? iso(0) : iso(offset),
    errorMessage: null,
    resultBytes: 4096,
  };
}

const platformUsers = [
  {
    id: "demo-admin",
    email: "admin@cep.com",
    role: "admin",
    tenantId: "batchone",
    displayName: "Platform admin",
    status: "active",
    passwordMustChange: false,
    mfaEnabled: true,
    mfaVerifiedAt: iso(-24),
    lastLoginAt: iso(-1),
  },
  {
    id: "demo-reviewer",
    email: "reviewer@cep.com",
    role: "reviewer",
    tenantId: "batchone",
    displayName: "Read-only reviewer",
    status: "active",
    passwordMustChange: false,
    mfaEnabled: true,
    mfaVerifiedAt: iso(-30),
    lastLoginAt: iso(-4),
  },
  {
    id: "demo-analyst",
    email: "analyst@cep.com",
    role: "threat_intel_expert",
    tenantId: "batchone",
    displayName: "Threat analyst",
    status: "active",
    passwordMustChange: false,
    mfaEnabled: true,
    mfaVerifiedAt: iso(-36),
    lastLoginAt: iso(-6),
  },
];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function text(body: string, status = 200): Response {
  return new Response(body, { status, headers: { "Content-Type": "text/plain" } });
}

function sourceSummary() {
  const counts = new Map<string, { category: string; label: string; count: number }>();
  for (const source of sources) {
    const key = source.category;
    const existing = counts.get(key) ?? { category: key, label: source.categoryLabel, count: 0 };
    existing.count += 1;
    counts.set(key, existing);
  }
  return Array.from(counts.values());
}

function filteredFindings(search: URLSearchParams) {
  let rows = [...findings];
  const severity = search.get("severity");
  const status = search.get("status");
  const sourceId = search.get("sourceId");
  const category = search.get("category");
  const tech = search.get("tech");
  if (severity) rows = rows.filter((f) => f.severity === severity);
  if (status) rows = rows.filter((f) => f.status === status);
  if (sourceId) rows = rows.filter((f) => f.sourceId === sourceId);
  if (category)
    rows = rows.filter(
      (f) =>
        sourceById.get(f.sourceId)?.category === category ||
        normalizeKey(f.sourceCategory) === normalizeKey(category) ||
        normalizeKey(sourceById.get(f.sourceId)?.categoryLabel ?? "") === normalizeKey(category),
    );
  if (tech) rows = rows.filter((f) => f.attackTechniques?.some((t) => t.id.toUpperCase() === tech.toUpperCase()));
  return rows;
}

function fullJob(id: string) {
  const base =
    aiJobs.find((j) => j.id === id) ?? job(id, "osint_analysis", "completed", 100, "Static demo AI job", "#/osint", -1);
  const dfirFinding = findings.find((f) => f.id === "f-011") ?? findings[0];
  const triageReport = [
    "As a top-tier CIRT and SOC analyst, I reviewed the supplied Batch One OSINT findings for operational urgency, exploitability, and defensive actionability. The current landscape is dominated by three themes: ransomware intrusion chains with credential access and exfiltration, high-leverage exposed-application vulnerabilities, and user-execution tradecraft that can seed hands-on-keyboard activity. Advertisement and low-signal media items should be filtered out of the active triage queue so analyst attention stays on source-backed findings.",
    "",
    "## \uD83D\uDEA8 TIER 1: CRITICAL RISK (Immediate Triage & Action Required)",
    "*Active exploitation or high-blast-radius intrusion paths that should trigger immediate validation, ownership assignment, and hunt coverage.*",
    "",
    "### 1. Ransomware intrusion chain with C2, credential access, exfiltration, and impact",
    "- **Intel:** *DFIR flash alert: EtherRAT and TukTuk C2 lead to The Gentlemen ransomware*",
    "- **Source:** The DFIR Report; source URL: `https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/`",
    "- **Mapped TTPs:** T1219 Remote Access Software; T1074 Data Staged; T1041 Exfiltration Over C2 Channel; T1558 Steal or Forge Kerberos Tickets; T1003 OS Credential Dumping; T1486 Data Encrypted for Impact.",
    "- **Why it's Critical:** The finding describes an end-to-end intrusion path from C2 tooling through credential theft, rclone-to-Wasabi exfiltration, and ransomware impact preparation, which gives defenders enough sequence-level evidence to hunt immediately.",
    "- **Action:** Open the DFIR finding for deep dive, search endpoint and identity telemetry for EtherRAT, TukTuk, TryCloudflare, `1rpc.io`, GoTo Resolve, NetExec/NXC, Mimikatz, `ntds.dit`, rclone, Wasabi, `vssadmin delete shadows`, and `wevtutil cl`, then preserve matching host timelines.",
    "",
    "### 2. Supply-chain package compromise targeting developer credentials",
    "- **Intel:** *Supply-chain alert: malicious npm packages target Solana private keys*",
    "- **Source:** The Hacker News.",
    "- **Mapped TTPs:** T1195 Supply Chain Compromise; T1552 Unsecured Credentials; T1041 Exfiltration Over C2 Channel.",
    "- **Why it's Critical:** Developer workstations and CI environments can convert package compromise into credential theft and downstream deployment risk.",
    "- **Action:** Ask engineering owners to validate package-lock changes, inspect recent npm install events, and hunt for unexpected package post-install execution on developer endpoints.",
    "",
    "### 3. Public-facing application and appliance exploitation watch",
    "- **Intel:** *Critical Sitecore Experience Platform flaw allows unauthenticated remote code execution*",
    "- **Intel:** *Fortinet FortiSandbox command injection exploited after public PoC*",
    "- **Intel:** *Critical appliance vulnerability added to public exploitation watchlist*",
    "- **Sources:** The Hacker News; BleepingComputer; NVD CVE API - recent.",
    "- **Why it's Critical:** Unauthenticated RCE and appliance command injection are common initial-access paths for ransomware and extortion operators once public PoC details exist.",
    "- **Action:** Engage AppSec and infrastructure owners to confirm internet exposure, patch state, compensating controls, and log retention for Sitecore XP, FortiSandbox, and relevant edge appliances.",
    "",
    "## \uD83D\uDD34 TIER 2: HIGH RISK (Prioritize for Patching & Threat Hunting)",
    "*High-confidence tradecraft and intrusion-enablement signals that should be converted into prioritized hunts and detections within the current work cycle.*",
    "",
    "### 1. Social engineering through collaboration and remote-support tooling",
    "- **Intel:** *DragonForce ransomware abuses Microsoft Teams for social-engineering relay*",
    "- **Source:** BleepingComputer.",
    "- **Mapped TTPs:** T1566 Phishing; T1204 User Execution; T1219 Remote Access Software.",
    "- **Why it's High:** The tradecraft combines trusted collaboration channels with remote-support tooling, which can bypass user suspicion and create fast operator access.",
    "- **Action:** Hunt Teams messages, OAuth grants, remote-support installations, and new external federation patterns around the same user and host windows.",
    "",
    "### 2. Loader and infostealer delivery through user-execution patterns",
    "- **Intel:** *ClickFix-style campaigns deliver DeerStealer and Odyssey infostealers*",
    "- **Intel:** *Loader campaign shifts delivery infrastructure and rotates command nodes*",
    "- **Sources:** The Hacker News; Fortinet - PSIRT RSS.",
    "- **Mapped TTPs:** T1204 User Execution; T1059 Command and Scripting Interpreter; T1555 Credentials from Password Stores; T1105 Ingress Tool Transfer; T1027 Obfuscated Files or Information.",
    "- **Why it's High:** Infostealer and loader campaigns are frequently upstream of credential replay, session theft, and follow-on ransomware access.",
    "- **Action:** Deploy hunts for suspicious clipboard-driven command execution, browser credential access, packed loaders, and new outbound destinations from recently phished users.",
    "",
    "## \uD83D\uDFE0 TIER 3: MEDIUM RISK (Awareness & Detection Engineering)",
    "*Emerging or contextual intelligence that should inform detection engineering, exposure review, and analyst watchlists without interrupting Tier 1 work.*",
    "",
    "### 1. Identity abuse and unmanaged edge-device pivoting",
    "- **Intel:** *Threat cluster pivots through unmanaged edge devices before identity abuse*",
    "- **Source:** Microsoft Threat Intelligence.",
    "- **Mapped TTPs:** T1190 Exploit Public-Facing Application; T1021 Remote Services.",
    "- **Why it's Medium:** The finding is operationally relevant, but the static demo lacks environment-specific exposure data to prove immediate impact.",
    "- **Action:** Add unmanaged edge devices, VPN gateways, and high-risk remote services to the weekly exposure review and correlate with identity anomalies.",
    "",
    "### 2. Mailbox persistence and public-sector lure refresh",
    "- **Intel:** *Phishing kit operators adopt inbox rule persistence*",
    "- **Intel:** *Espionage group refreshes spearphishing lure themes against public sector*",
    "- **Sources:** Graham Cluley; ESET WeLiveSecurity.",
    "- **Mapped TTPs:** T1114 Email Collection; T1098 Account Manipulation; T1566 Phishing.",
    "- **Why it's Medium:** These items support detection content and user-awareness updates, but they do not outrank the active ransomware and RCE paths.",
    "- **Action:** Review suspicious inbox rules, forwarding configuration, and spearphishing lure themes against email-security telemetry.",
    "",
    "## \u26AA TIER 4: LOW RISK / INFORMATIONAL (Filter Out)",
    "*Non-actionable media, contest, marketing, or low-confidence items that should not consume CIRT cycles unless they become linked to concrete indicators or exploited technology.*",
    "- **Ignore/Filter out for triage:**",
    "  - *Name That Toon Contest* from Dark Reading is advertisement-class content and should remain hidden when advertisement filtering is enabled.",
    "  - Generic breach commentary or low-context media items should be retained only as background reading, not escalated as findings.",
    "",
    "## Source Aggregation:",
    "- **The DFIR Report:** 1 high-signal incident report; date span current review window; dominant category ransomware intrusion chain; notable actors The Gentlemen; representative source `https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/`.",
    "- **The Hacker News:** 3 items; dominant categories supply-chain compromise, infostealer delivery, and public-facing RCE; notable technology npm, Solana wallets, Sitecore XP; use for exposure validation and user-execution hunts.",
    "- **BleepingComputer:** 2 items; dominant categories ransomware social engineering and appliance exploitation; notable technology Microsoft Teams, remote-support tooling, FortiSandbox; use for endpoint and collaboration telemetry hunts.",
    "- **NVD CVE API / GitHub Advisory DB:** 2 vulnerability entries; dominant category CVE and dependency exposure; use for asset inventory and patch validation.",
    "- **Vendor research feeds:** Microsoft Threat Intelligence, ESET, Malwarebytes Labs, Fortinet PSIRT, and InfoGuard contribute contextual tradecraft for edge-device abuse, phishing, loader activity, and ransomware playbooks.",
    "",
    "## \uD83D\uDCCB Analyst Action Plan Summary:",
    "1. **Drop everything and check for:** EtherRAT, TukTuk, TryCloudflare, `1rpc.io`, GoTo Resolve, NetExec/NXC, Mimikatz, `ntds.dit`, rclone, Wasabi, `vssadmin delete shadows`, `wevtutil cl`, public-facing Sitecore XP, FortiSandbox, and internet-exposed edge appliances.",
    "2. **Engage DevOps / AppSec:** Validate npm dependency changes, package-lock drift, CI package install logs, Sitecore XP patch state, FortiSandbox patch state, and compensating controls for any exposed vulnerable services.",
    "3. **Deploy Threat Hunts:** Generate the DFIR EtherRAT-to-The-Gentlemen hunt pack across Splunk, KQL, Sigma, Chronicle, Cortex XDR, CrowdStrike, SentinelOne, and Defender; add Teams/remote-support abuse and ClickFix/infostealer execution searches.",
    "4. **Standard Op:** Keep advertisement-class items suppressed, preserve source URLs and publish/ingest dates, and convert only evidence-backed findings into TAP updates or hunt-query drafts.",
    "",
    `Recommended deep-dive candidate: select "${dfirFinding.title}" and generate the multi-platform hunt query pack after review.`,
  ].join("\n");
  const deepHtml = [
    "<!doctype html>",
    "<html><head><meta charset=\"utf-8\"><title>OptraSight CIRT deep-dive - EtherRAT/TukTuk to The Gentlemen ransomware</title>",
    "<style>",
    ":root{color-scheme:light;--ink:#101124;--muted:#5f617b;--line:#dfe3f1;--brand:#4f46e5;--signal:#22d3ee;--panel:#fff;--soft:#f6f7fd;--danger:#e11d48;--warn:#f97316;--ok:#059669}",
    "body{margin:0;background:#f8fafc;color:var(--ink);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}",
    ".wrap{max-width:1180px;margin:0 auto;padding:28px}",
    ".hero{border:1px solid var(--line);border-left:5px solid var(--brand);background:var(--panel);border-radius:16px;padding:22px 24px;box-shadow:0 14px 36px rgba(15,23,42,.08)}",
    ".eyebrow{color:var(--brand);font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}",
    "h1{font-size:30px;line-height:1.15;margin:8px 0 10px}h2{font-size:20px;margin:0 0 10px}h3{font-size:15px;margin:0 0 8px}.muted{color:var(--muted)}",
    ".grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}.metric{border:1px solid var(--line);border-radius:12px;background:var(--soft);padding:12px}.metric b{display:block;font-size:18px}.metric span{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}",
    ".section{margin-top:18px;border:1px solid var(--line);border-radius:16px;background:var(--panel);padding:18px 20px}.callout{border:1px solid #c7d2fe;border-left:4px solid var(--signal);border-radius:12px;background:#f7f7ff;padding:12px 14px}",
    "table{width:100%;border-collapse:separate;border-spacing:0;margin-top:10px;border:1px solid var(--line);border-radius:12px;overflow:hidden}th,td{padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{background:#f1f5f9;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}tr:last-child td{border-bottom:0}",
    ".pill{display:inline-block;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:800;border:1px solid transparent}.critical{background:#ffe4e6;color:#9f1239;border-color:#fecdd3}.high{background:#ffedd5;color:#9a3412;border-color:#fed7aa}.amber{background:#fef3c7;color:#92400e;border-color:#fde68a}.info{background:#e0f2fe;color:#075985;border-color:#bae6fd}.ok{background:#dcfce7;color:#166534;border-color:#bbf7d0}",
    "ol,ul{padding-left:20px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono',monospace}.sources li{margin-bottom:6px}",
    "@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.wrap{padding:16px}}",
    "</style></head><body><main class=\"wrap\">",
    "<section class=\"hero\">",
    "<div class=\"eyebrow\">CIRT Deep Dive</div>",
    "<h1>EtherRAT/TukTuk C2 leading to The Gentlemen ransomware</h1>",
    "<p class=\"muted\">Static demo AI result based on the provided DFIR Report source. The report is English-only and mirrors the BatchOne deep-dive structure: source context, evidence chain, ATT&CK mapping, hunt signals, and analyst action.</p>",
    "<div class=\"grid\">",
    "<div class=\"metric\"><span>Priority</span><b>Tier 1</b><small>Active intrusion chain</small></div>",
    "<div class=\"metric\"><span>Severity</span><b>Critical</b><small>C2, credential theft, exfiltration, ransomware</small></div>",
    "<div class=\"metric\"><span>TLP</span><b>Amber</b><small>Defensive use</small></div>",
    "<div class=\"metric\"><span>Source</span><b>The DFIR Report</b><small>May 11, 2026 flash alert</small></div>",
    "</div>",
    "</section>",
    "<section class=\"section\"><h2>Executive assessment</h2>",
    "<div class=\"callout\"><strong>Bottom line:</strong> This finding should be handled as a high-confidence ransomware intrusion chain. The valuable signal is the sequence: initial execution, EtherRAT/TukTuk command and control, remote access, Active Directory credential access, rclone-to-Wasabi exfiltration, and impact preparation.</div>",
    "<p>The DFIR source describes a traceable operator path that gives defenders multiple detection points before encryption. BatchOne should convert this item into a focused hunt pack and use the result to enrich TAP tradecraft for ransomware-as-a-service activity.</p>",
    "</section>",
    "<section class=\"section\"><h2>Observed intrusion chain</h2>",
    "<table><thead><tr><th>Phase</th><th>Observed behavior</th><th>Primary evidence to review</th><th>Priority</th></tr></thead><tbody>",
    "<tr><td>Initial execution</td><td>Installer and user-execution style activity consistent with operator foothold preparation.</td><td>Process creation, MSI execution, parent-child command lines, signed binary abuse, first-seen host artifacts.</td><td><span class=\"pill high\">High</span></td></tr>",
    "<tr><td>C2 relay</td><td>EtherRAT and TukTuk C2 activity with relay or staging infrastructure.</td><td>DNS and proxy logs for TryCloudflare-style relay use, 1rpc.io references, unusual outbound beacon patterns, newly observed domains.</td><td><span class=\"pill critical\">Critical</span></td></tr>",
    "<tr><td>Remote access</td><td>Interactive remote-support tooling appears in the operator workflow.</td><td>GoTo Resolve or comparable remote-access installation, service creation, user logon pairing, process ancestry.</td><td><span class=\"pill high\">High</span></td></tr>",
    "<tr><td>Credential access</td><td>Active Directory and endpoint credential-theft behavior appears before exfiltration and impact.</td><td>NetExec/NXC, Mimikatz, LSASS access, NTDS access, Kerberoasting indicators, unusual LDAP enumeration.</td><td><span class=\"pill critical\">Critical</span></td></tr>",
    "<tr><td>Collection and exfiltration</td><td>Data staging and transfer align with rclone movement to cloud object storage.</td><td>Rclone command lines, Wasabi endpoints, large outbound transfers, archive creation, staging directory growth.</td><td><span class=\"pill critical\">Critical</span></td></tr>",
    "<tr><td>Impact preparation</td><td>Defender tampering, shadow copy deletion, log clearing, and ransomware deployment readiness.</td><td>Security tool disablement, vssadmin/wmic shadow-copy deletion, wevtutil clearing, GPO/script fan-out.</td><td><span class=\"pill critical\">Critical</span></td></tr>",
    "</tbody></table></section>",
    "<section class=\"section\"><h2>ATT&CK mapping and hunt anchors</h2>",
    "<table><thead><tr><th>Technique</th><th>Why it matters</th><th>Example hunt anchor</th></tr></thead><tbody>",
    "<tr><td class=\"mono\">T1059 Command and Scripting Interpreter</td><td>Operators rely on shell execution to stage tooling and run follow-on commands.</td><td>Suspicious PowerShell, cmd, or script hosts spawned by installer, browser, archive, or remote-support parents.</td></tr>",
    "<tr><td class=\"mono\">T1219 Remote Access Software</td><td>Remote-support tooling can create interactive operator access under a legitimate product name.</td><td>First-seen remote-access binaries paired with uncommon users, new services, or outbound management sessions.</td></tr>",
    "<tr><td class=\"mono\">T1003 OS Credential Dumping</td><td>Credential theft expands blast radius and supports lateral movement.</td><td>LSASS handle access, credential-dumping tools, NTDS extraction, and suspicious privilege escalation before encryption.</td></tr>",
    "<tr><td class=\"mono\">T1558 Steal or Forge Kerberos Tickets</td><td>Kerberos abuse can reveal AD compromise and service-account targeting.</td><td>Kerberoasting patterns, high-volume TGS requests, unusual SPN access, and tool strings linked to NetExec/NXC.</td></tr>",
    "<tr><td class=\"mono\">T1074 Data Staged</td><td>Ransomware operators usually collect and compress data before exfiltration.</td><td>New archive creation, large staging folders, sensitive file discovery, and compression utilities run from admin contexts.</td></tr>",
    "<tr><td class=\"mono\">T1041 Exfiltration Over C2 Channel</td><td>Cloud or relay-based exfiltration can blend into normal HTTPS egress.</td><td>Rclone execution, Wasabi destinations, high-byte transfers, and unusual cloud-storage paths from servers.</td></tr>",
    "<tr><td class=\"mono\">T1486 Data Encrypted for Impact</td><td>Impact preparation marks the final window before business disruption.</td><td>Shadow-copy deletion, event-log clearing, security product tampering, and script/GPO fan-out.</td></tr>",
    "</tbody></table></section>",
    "<section class=\"section\"><h2>Indicators and trace terms</h2>",
    "<table><thead><tr><th>Category</th><th>Trace terms</th><th>Use</th></tr></thead><tbody>",
    "<tr><td>C2 and relay</td><td class=\"mono\">EtherRAT, TukTuk, TryCloudflare, 1rpc.io</td><td>Search DNS, proxy, EDR network events, and URL telemetry.</td></tr>",
    "<tr><td>Remote access</td><td class=\"mono\">GoTo Resolve, remote-support install paths, new services</td><td>Pair process and logon telemetry to confirm interactive operator activity.</td></tr>",
    "<tr><td>Credential access</td><td class=\"mono\">NetExec, NXC, Mimikatz, lsass, ntds.dit, Kerberoast</td><td>Review endpoint alerts, command-line logs, and domain-controller security events.</td></tr>",
    "<tr><td>Exfiltration</td><td class=\"mono\">rclone, Wasabi, archive staging, high outbound bytes</td><td>Correlate process execution with proxy/firewall byte counts and cloud-storage domains.</td></tr>",
    "<tr><td>Impact</td><td class=\"mono\">vssadmin delete shadows, wmic shadowcopy delete, wevtutil cl</td><td>Escalate immediately if seen near C2, credential, or exfiltration evidence.</td></tr>",
    "</tbody></table></section>",
    "<section class=\"section\"><h2>Recommended analyst actions</h2>",
    "<ol>",
    "<li><strong>Containment check:</strong> Query the last 14 days for EtherRAT/TukTuk terms, relay infrastructure, remote-support installations, credential tooling, and rclone-to-Wasabi transfer paths.</li>",
    "<li><strong>Identity review:</strong> Inspect domain-controller events for abnormal Kerberos requests, service-account targeting, and privileged logons from hosts with new remote-access tools.</li>",
    "<li><strong>Endpoint review:</strong> Prioritize servers or user workstations showing both command execution and outbound relay/cloud-storage traffic.</li>",
    "<li><strong>Network review:</strong> Correlate DNS, proxy, and firewall telemetry for first-seen destinations, high-byte HTTPS transfers, and suspicious cloud-tunnel patterns.</li>",
    "<li><strong>Detection engineering:</strong> Generate and validate the DFIR EtherRAT-to-The-Gentlemen hunt pack across Splunk, Microsoft KQL, Sigma, Chronicle, Cortex XDR, CrowdStrike, SentinelOne, and Defender.</li>",
    "</ol></section>",
    "<section class=\"section\"><h2>Aggregated source context</h2>",
    "<ul class=\"sources\">",
    "<li><strong>The DFIR Report:</strong> primary incident-chain source for EtherRAT/TukTuk C2 and The Gentlemen ransomware. Reference: <span class=\"mono\">https://thedfirreport.com/2026/05/11/flash-alert-etherrat-and-tuktuk-c2-end-in-the-gentleman-ransomware/</span></li>",
    "<li><strong>BatchOne OSINT queue:</strong> related ransomware, remote-support abuse, supply-chain compromise, infostealer, and public-facing RCE items provide adjacent hunts but do not supersede the DFIR report as the deep-dive anchor.</li>",
    "<li><strong>Advertisement-class items:</strong> remain filtered from the review queue unless linked to concrete indicators, exploited technology, or verified actor tradecraft.</li>",
    "</ul></section>",
    "</main></body></html>",
  ].join("");
  const platformDeepHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OptraSight CIRT Deep Dive Report</title>
<style>
  *,*::before,*::after { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #0f172a; background: #f8fafc; line-height: 1.55; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 48px 32px 80px; }
  .hero { padding: 32px; border-radius: 18px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #312e81 100%); color: #f8fafc; box-shadow: 0 20px 60px -20px rgba(15,23,42,.45); }
  .hero h1 { margin: 0 0 8px; font-size: 32px; font-weight: 700; letter-spacing: -0.01em; }
  .hero .sub { color: #cbd5e1; font-size: 14px; }
  .hero .badges { margin-top: 18px; display: flex; gap: 8px; flex-wrap: wrap; }
  .badge { padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 600; background: rgba(255,255,255,.12); color: #e2e8f0; }
  .profile { margin-top: 14px; padding: 14px 18px; border-radius: 12px; background: rgba(255,255,255,.07); color: #e2e8f0; font-size: 13px; display: grid; gap: 4px; }
  .overview { margin: 28px 0; padding: 24px 28px; border-radius: 14px; background: #eef2ff; border: 1px solid #c7d2fe; }
  .overview h2 { margin: 0 0 8px; font-size: 18px; color: #312e81; }
  .overview p { margin: 0; color: #1e293b; }
  .cards { display: grid; gap: 18px; margin-top: 8px; }
  .card { border-radius: 14px; background: #ffffff; box-shadow: 0 4px 20px -8px rgba(15,23,42,.12); overflow: hidden; border: 1px solid #e2e8f0; }
  .card-head { display: flex; justify-content: space-between; align-items: center; padding: 12px 20px; font-size: 13px; font-weight: 600; background: #b91c1c; color: #fff; }
  .sev-pill { font-size: 14px; letter-spacing: 0.04em; }
  .rel { opacity: 0.92; }
  .card-body { padding: 22px 26px 26px; }
  .card-title { margin: 0 0 6px; font-size: 19px; color: #0f172a; line-height: 1.35; }
  .meta { font-size: 12px; color: #475569; margin-bottom: 14px; }
  .src-link { color: #2563eb; text-decoration: none; margin-left: 10px; }
  .src-link:hover { text-decoration: underline; }
  .exec { font-size: 15px; color: #1f2937; margin: 0 0 18px; padding: 12px 16px; border-left: 4px solid #6366f1; background: #f5f3ff; border-radius: 0 8px 8px 0; }
  .block { margin-top: 14px; }
  .block-label { font-size: 12px; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px; }
  .analysis { margin: 0; font-size: 14px; color: #1f2937; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; }
  .chip { padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 500; }
  .chip-cve { background: #fee2e2; color: #991b1b; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .chip-mitre { background: #ede9fe; color: #5b21b6; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .iocs { background: #0f172a; color: #f8fafc; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; padding: 12px 14px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .actions { margin: 0; padding-left: 22px; font-size: 14px; color: #1f2937; }
  .actions li { margin: 4px 0; }
  footer { margin-top: 30px; text-align: center; color: #64748b; font-size: 12px; }
</style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>🛡️ OptraSight CIRT Deep Dive Report</h1>
      <div class="sub">Generated Wed, 17 Jun 2026 10:30:00 GMT · 1 finding analysed · Static demo AI</div>
      <div class="badges">
        <span class="badge">CIRT-grade structured analysis</span>
        <span class="badge">MITRE ATT&CK-anchored</span>
        <span class="badge">Source-fetched</span>
      </div>
      <div class="profile">
        <div><strong>Industries:</strong> security-operations</div>
        <div><strong>Geographies:</strong> Global</div>
        <div><strong>Monitored Tech:</strong> osint, threat-intelligence, detection-engineering</div>
      </div>
    </section>

    <section class="overview">
      <h2>📋 Overall Assessment</h2>
      <p>Synthesised from a source-fetched DFIR finding. The intrusion chain is high priority because it joins C2 relay activity, remote access, credential access, staged exfiltration, and ransomware impact preparation into one defender-traceable timeline. Treat the source as an immediate hunt seed and validate each stage across endpoint, identity, DNS, proxy, and storage telemetry before standing down.</p>
    </section>

    <div class="cards">
      <article class="card" id="finding-1">
        <header class="card-head">
          <div class="sev-pill">🚨 CRITICAL</div>
          <div class="rel">Relevance 95%</div>
        </header>
        <div class="card-body">
          <h2 class="card-title">${dfirFinding.title}</h2>
          <div class="meta"><strong>${dfirFinding.sourceName}</strong> <a class="src-link" href="${dfirFinding.url}" target="_blank" rel="noopener">🔗 Source</a></div>
          <p class="exec">The DFIR Report item is the recommended deep-dive candidate because it links EtherRAT/TukTuk command and control, remote access, Active Directory credential access, rclone-to-Wasabi exfiltration, and The Gentlemen ransomware impact in one chain.</p>
          <div class="block">
            <div class="block-label">📋 Detailed Analysis</div>
            <p class="analysis">The activity is actionable because it gives defenders multiple telemetry pivots before encryption: suspicious installer or user-execution behavior, relay/C2 terms such as EtherRAT, TukTuk, TryCloudflare, and 1rpc.io, remote-support tooling, credential-access utilities, and cloud-storage exfiltration. The strongest signal is not a single IoC; it is the ordered sequence across process, identity, network, and storage logs. Endpoint analysts should review command-line and service-creation telemetry around remote-access installation and credential tooling. Network analysts should pair DNS/proxy evidence with high-byte outbound transfer patterns, especially rclone use against Wasabi-style object storage. Incident responders should escalate immediately if C2, credential access, exfiltration, and impact-preparation commands appear on the same host or account timeline.</p>
          </div>
          <div class="block">
            <div class="block-label">🧬 MITRE ATT&amp;CK</div>
            <div class="chips">
              <span class="chip chip-mitre">T1059 — Command and Scripting Interpreter</span>
              <span class="chip chip-mitre">T1219 — Remote Access Software</span>
              <span class="chip chip-mitre">T1003 — OS Credential Dumping</span>
              <span class="chip chip-mitre">T1558 — Steal or Forge Kerberos Tickets</span>
              <span class="chip chip-mitre">T1074 — Data Staged</span>
              <span class="chip chip-mitre">T1041 — Exfiltration Over C2 Channel</span>
              <span class="chip chip-mitre">T1486 — Data Encrypted for Impact</span>
            </div>
          </div>
          <div class="block">
            <div class="block-label">🎯 Indicators of Compromise</div>
            <pre class="iocs">EtherRAT
TukTuk
TryCloudflare
1rpc.io
GoTo Resolve
NetExec / NXC
Mimikatz
ntds.dit
rclone
Wasabi
vssadmin delete shadows
wmic shadowcopy delete
wevtutil cl</pre>
          </div>
          <div class="block">
            <div class="block-label">⚙️ Detection &amp; Mitigation Actions</div>
            <ol class="actions">
              <li>Search the last 14 days for EtherRAT, TukTuk, TryCloudflare, 1rpc.io, remote-support installs, and first-seen relay destinations.</li>
              <li>Correlate GoTo Resolve or comparable remote-access process ancestry with unusual logons, new services, and administrative command execution.</li>
              <li>Review domain-controller and endpoint telemetry for NetExec/NXC, Mimikatz, LSASS access, NTDS access, Kerberoasting, and abnormal service-account requests.</li>
              <li>Hunt rclone execution, Wasabi destinations, archive staging, and high-byte outbound HTTPS transfer before ransomware-impact commands.</li>
              <li>Escalate immediately if shadow-copy deletion, event-log clearing, Defender tampering, or GPO/script fan-out appears near the same host/account timeline.</li>
            </ol>
          </div>
        </div>
      </article>
    </div>

    <footer>OptraSight · CIRT Deep Dive · Self-contained report — view offline or attach to incident tickets.</footer>
  </div>
</body>
</html>`;
  const result = base.kind.includes("deep")
    ? {
        perFinding: [
          {
            findingId: dfirFinding.id,
            title: dfirFinding.title,
            url: dfirFinding.url,
            source: dfirFinding.sourceName,
            severityLabel: "CRITICAL",
            relevanceScore: 0.95,
            executiveSummary:
              "High-priority deep-dive candidate because the DFIR source links EtherRAT/TukTuk C2, credential access, staged exfiltration, and The Gentlemen ransomware impact in one timeline.",
            detailedAnalysis:
              "The activity is actionable because it gives defenders multiple telemetry pivots before encryption: suspicious installer or user-execution behavior, EtherRAT/TukTuk C2, relay infrastructure, remote-support tooling, credential-access utilities, and cloud-storage exfiltration. The strongest signal is not a single IoC; it is the ordered sequence across endpoint, identity, network, and storage logs. Prioritize timelines where remote access, credential access, rclone transfer, and impact-preparation commands converge.",
            mitreTtps: ["T1059 — Command and Scripting Interpreter", "T1219 — Remote Access Software", "T1003 — OS Credential Dumping", "T1558 — Steal or Forge Kerberos Tickets", "T1074 — Data Staged", "T1041 — Exfiltration Over C2 Channel", "T1486 — Data Encrypted for Impact"],
            iocs: ["EtherRAT", "TukTuk", "TryCloudflare", "1rpc.io", "GoTo Resolve", "NetExec / NXC", "Mimikatz", "ntds.dit", "rclone", "Wasabi", "vssadmin delete shadows", "wmic shadowcopy delete", "wevtutil cl"],
            detectionActions: [
              "Search the last 14 days for EtherRAT, TukTuk, TryCloudflare, 1rpc.io, remote-support installs, and first-seen relay destinations.",
              "Correlate remote-access process ancestry with unusual logons, new services, and administrative command execution.",
              "Review domain-controller and endpoint telemetry for NetExec/NXC, Mimikatz, LSASS access, NTDS access, Kerberoasting, and abnormal service-account requests.",
              "Hunt rclone execution, Wasabi destinations, archive staging, and high-byte outbound HTTPS transfer before ransomware-impact commands.",
              "Escalate immediately if shadow-copy deletion, event-log clearing, Defender tampering, or GPO/script fan-out appears near the same host/account timeline.",
            ],
            cveIds: [],
          },
        ],
        overallAssessment:
          "Selected findings align to C2 relay abuse, credential access, staged collection, exfiltration, and impact-stage ransomware tradecraft.",
        htmlReport: platformDeepHtml,
        htmlFileName: "optrasight-static-deep-dive.html",
        providerLabel: base.providerLabel,
        generatedAt: iso(-1),
      }
    : base.kind.includes("hunt")
      ? {
          queries: huntQueries.find((q) => q.id === "hq-006")?.queries ?? {},
          findingId: "f-011",
          title: "DFIR EtherRAT to The Gentlemen ransomware hunt pack",
          providerLabel: base.providerLabel,
          generatedAt: iso(-0.5),
        }
      : {
          reportMd: triageReport,
          rangeLabel: "the last 7 days",
          itemsAnalysed: findings.length,
          providerLabel: base.providerLabel,
          generatedAt: iso(-1),
        };
  return { ...base, status: base.status === "succeeded" ? "completed" : base.status, result, error: null };
}

export function staticDemoRequest(method: string, url: string, data?: unknown): Response | null {
  if (!STATIC_DEMO_MODE) return null;
  const parsed = new URL(url, window.location.origin);
  let path = parsed.pathname;
  if (path.endsWith("/") && path !== "/") path = path.slice(0, -1);

  if (path === "/api/v1/me") return json(STATIC_DEMO_USER);
  if (path === "/api/v1/auth/login") return json({ access_token: "static-demo-token" });
  if (path === "/api/v1/auth/logout") return json({ ok: true });

  if (path === "/api/v1/taxonomies") {
    return json({
      huntLanguages: [
        { id: "splunk", label: "Splunk SPL" },
        { id: "kql", label: "Microsoft KQL" },
        { id: "defender", label: "Microsoft Defender" },
        { id: "chronicle", label: "Google SecOps" },
        { id: "cortex_xdr", label: "Cortex XDR XQL" },
        { id: "crowdstrike", label: "CrowdStrike Falcon" },
        { id: "sentinelone", label: "SentinelOne" },
        { id: "sigma", label: "Sigma YAML" },
      ],
      osintCategoryLabels: Object.fromEntries(sourceSummary().map((s) => [s.category, s.label])),
      osintOverviewPersonas: [{ id: "analyst", label: "Threat analyst", blurb: "Evidence-led triage" }],
    });
  }

  if (path === "/api/v1/ai/providers") {
    return json({ providers, hasUsableProvider: true });
  }
  if (path === "/api/v1/ai/assignments") {
    return json({ assignments, tasks: BATCH_ONE_AI_TASKS });
  }
  if (/^\/api\/v1\/ai\/providers\/[^/]+\/test$/.test(path)) {
    return json({ ok: true, message: "Static demo mode: provider test simulated successfully.", latencyMs: 120 });
  }
  if (path.startsWith("/api/v1/ai/providers")) return json({ ok: true, provider: providers[0] });

  if (path === "/api/v1/admin/platform-users") return json({ users: platformUsers });
  if (path.startsWith("/api/v1/admin/platform-users")) return json({ ok: true, users: platformUsers });

  if (path === "/api/v1/admin/osint/ingest/status") {
    return json({
      busy: false,
      startedAt: null,
      finishedAt: iso(-2),
      summary: { count: 0, feedsTried: sources.length, feedsOk: sources.length, errors: [], durationMs: 0 },
      error: null,
    });
  }
  if (path === "/api/v1/admin/osint/ingest") {
    return json({
      status: "static_demo",
      message: "Static demo data is already loaded.",
      count: findings.length,
      feedsOk: sources.length,
      feedsTried: sources.length,
    });
  }
  if (path === "/api/v1/osint/sources") {
    const q = (parsed.searchParams.get("q") ?? "").toLowerCase();
    const category = parsed.searchParams.get("category");
    const rows = sources.filter(
      (s) =>
        (!q || s.englishName.toLowerCase().includes(q) || s.url.toLowerCase().includes(q)) &&
        (!category || s.category === category),
    );
    return json({ sources: rows, summary: sourceSummary() });
  }
  if (path === "/api/v1/osint/sources/bulk")
    return json({ changed: Array.isArray((data as any)?.ids) ? (data as any).ids.length : 0 });
  if (path === "/api/v1/osint/findings") return json({ findings: filteredFindings(parsed.searchParams) });
  if (/^\/api\/v1\/osint\/findings\/[^/]+$/.test(path)) {
    const id = path.split("/").pop();
    const finding = findings.find((f) => f.id === id);
    if (!finding) return json({ detail: "finding not found" }, 404);
    if (method.toUpperCase() === "PATCH") return json({ ...finding, ...(data as Record<string, unknown>) });
    return json(finding);
  }
  if (path === "/api/v1/osint/findings/ai-analyze") {
    const body = (data ?? {}) as { findingIds?: string[] };
    const targetFindingId = Array.isArray(body.findingIds) && body.findingIds.length > 0 ? body.findingIds[0] : "f-011";
    const id = `job-osint-${Date.now()}`;
    const created = job(
      id,
      "osint_analysis",
      "completed",
      100,
      "OSINT AI analysis - DFIR EtherRAT to The Gentlemen",
      `#/osint?finding=${targetFindingId}`,
      -0.01,
    );
    aiJobs.unshift(created);
    return json({
      jobId: id,
      status: "queued",
      kind: "osint_analysis",
      targetUrl: created.targetUrl,
      targetLabel: created.targetLabel,
    });
  }
  if (path === "/api/v1/osint/hunt-queries" && method.toUpperCase() === "POST") {
    const body = (data ?? {}) as { findingIds?: string[]; languages?: string[]; title?: string };
    const findingIds = Array.isArray(body.findingIds) && body.findingIds.length > 0 ? body.findingIds : ["f-011"];
    const selected =
      findings.find((f) => f.id === findingIds[0]) ?? findings.find((f) => f.id === "f-011") ?? findings[0];
    const generatedId = `hq-static-${Date.now()}`;
    const allPlatformQueries = {
      splunk:
        'index=edr ("RAMMap" OR "EtherRAT" OR "TukTuk" OR "1rpc.io" OR "trycloudflare.com" OR "GoTo Resolve" OR "NetExec" OR "mimikatz" OR "ntds.dit" OR "rclone" OR "Wasabi" OR "vssadmin delete shadows" OR "wevtutil cl") | stats earliest(_time) as first latest(_time) as last values(CommandLine) as commands values(process_name) as tools by host,user',
      kql: 'DeviceProcessEvents | where ProcessCommandLine has_any ("RAMMap","EtherRAT","TukTuk","1rpc.io","trycloudflare.com","GoTo Resolve","NetExec","mimikatz","ntds.dit","rclone","Wasabi","vssadmin delete shadows","wevtutil cl") or FileName in~ ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe") | summarize firstSeen=min(Timestamp), lastSeen=max(Timestamp), Commands=make_set(ProcessCommandLine) by DeviceName, AccountName, FileName',
      defender:
        'DeviceProcessEvents | where ProcessCommandLine has_any ("RAMMap","EtherRAT","TukTuk","1rpc.io","trycloudflare.com","GoTo Resolve","NetExec","mimikatz","ntds.dit","rclone","Wasabi","vssadmin delete shadows","wevtutil cl") or FileName in~ ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe") | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine',
      chronicle:
        'metadata.event_type = "PROCESS_LAUNCH" and (principal.process.command_line = /(?i)(RAMMap|EtherRAT|TukTuk|1rpc\\.io|trycloudflare|GoTo Resolve|NetExec|mimikatz|ntds\\.dit|Wasabi|rclone|vssadmin delete shadows|wevtutil cl)/ or principal.process.file.full_path = /(?i)(rclone|netexec|nxc|mimikatz|vssadmin|wevtutil)\\.exe/)',
      cortex_xdr:
        'dataset = xdr_data | filter action_process_image_command_line contains "EtherRAT" or action_process_image_command_line contains "TukTuk" or action_process_image_command_line contains "trycloudflare.com" or action_process_image_command_line contains "Wasabi" or action_process_image_name in ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe")',
      crowdstrike:
        '#event_simpleName=ProcessRollup2 (CommandLine="*EtherRAT*" OR CommandLine="*TukTuk*" OR CommandLine="*trycloudflare*" OR CommandLine="*Wasabi*" OR CommandLine="*ntds.dit*" OR FileName="rclone.exe" OR FileName="netexec.exe" OR FileName="nxc.exe" OR FileName="mimikatz.exe" OR FileName="vssadmin.exe" OR FileName="wevtutil.exe") | groupBy([ComputerName, UserName, FileName])',
      sentinelone:
        'EventType = "Process Creation" AND (CmdLine Contains AnyCase ("EtherRAT","TukTuk","1rpc.io","trycloudflare.com","Wasabi","ntds.dit","vssadmin delete shadows","wevtutil cl") OR TgtProcName In Contains AnyCase ("rclone.exe","netexec.exe","nxc.exe","mimikatz.exe","vssadmin.exe","wevtutil.exe"))',
      sigma:
        "title: DFIR EtherRAT TukTuk Rclone Ransomware Staging\nstatus: experimental\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection_cmd:\n    CommandLine|contains:\n      - 'RAMMap'\n      - 'EtherRAT'\n      - 'TukTuk'\n      - '1rpc.io'\n      - 'trycloudflare.com'\n      - 'GoTo Resolve'\n      - 'Wasabi'\n      - 'ntds.dit'\n      - 'vssadmin delete shadows'\n      - 'wevtutil cl'\n  selection_tools:\n    Image|endswith:\n      - '\\\\rclone.exe'\n      - '\\\\netexec.exe'\n      - '\\\\nxc.exe'\n      - '\\\\mimikatz.exe'\n      - '\\\\vssadmin.exe'\n      - '\\\\wevtutil.exe'\n  condition: selection_cmd or selection_tools",
    };
    const requested =
      Array.isArray(body.languages) && body.languages.length > 0 ? body.languages : Object.keys(allPlatformQueries);
    const queries = Object.fromEntries(
      requested.map((language) => [
        language,
        allPlatformQueries[language as keyof typeof allPlatformQueries] ?? allPlatformQueries.splunk,
      ]),
    );
    const generated = hunt(
      generatedId,
      body.title?.trim() || `${selected.sourceName} - ${selected.title}`,
      findingIds,
      queries,
    );
    huntQueries = [generated, ...huntQueries];
    const jobId = `job-hunt-${Date.now()}`;
    const created = job(
      jobId,
      "hunt_query_generation",
      "completed",
      100,
      `Hunt query - ${generated.title}`,
      `#/osint?tab=hunt&hunt=${generatedId}`,
      -0.01,
    );
    aiJobs.unshift(created);
    return json({
      jobId,
      id: generatedId,
      query: generated,
      status: "queued",
      kind: "hunt_query_generation",
      targetUrl: created.targetUrl,
      targetLabel: created.targetLabel,
    });
  }
  if (path === "/api/v1/osint/hunt-queries") return json({ queries: huntQueries });
  if (path === "/api/v1/osint/dictionaries")
    return json({
      iocTypes: ["ipv4", "domain", "url", "sha256"],
      statuses: ["new", "triaged", "assessed", "dismissed"],
      tags: ["hunt-candidate", "actor-linked", "watch"],
    });
  if (path === "/api/v1/osint/scan")
    return json({ count: 0, mode: "static_demo", feedsOk: sources.length, feedsTried: sources.length });
  if (path === "/api/v1/exchange/stix/preview")
    return json({ bundle: { type: "bundle", id: "bundle--static-demo", objects: [] }, objects: [] });
  if (path === "/api/v1/osint/ai-jobs/history")
    return json({ jobs: aiJobs.filter((j) => j.kind === "chat_triage" || j.kind === "chat_deep_dive") });
  if (path === "/api/v1/osint/chat/triage") {
    const id = `job-cirt-${Date.now()}`;
    const created = job(
      id,
      "chat_triage",
      "completed",
      100,
      "CIRT triage - aggregated OSINT sources",
      `#/osint?ai=triage&job=${id}`,
      -0.01,
    );
    aiJobs.unshift(created);
    return json({
      jobId: id,
      status: "queued",
      kind: "chat_triage",
      targetUrl: created.targetUrl,
      targetLabel: created.targetLabel,
    });
  }
  if (path === "/api/v1/osint/chat/deep-dive") {
    const id = `job-deep-${Date.now()}`;
    const created = job(
      id,
      "chat_deep_dive",
      "completed",
      100,
      "CIRT deep-dive - EtherRAT/TukTuk to The Gentlemen",
      `#/osint?ai=deep-dive&job=${id}`,
      -0.01,
    );
    aiJobs.unshift(created);
    return json({
      jobId: id,
      status: "queued",
      kind: "chat_deep_dive",
      targetUrl: created.targetUrl,
      targetLabel: created.targetLabel,
    });
  }

  if (path === "/api/v1/threat-actors" && method.toUpperCase() === "POST")
    return json({ actor: actors[0], id: actors[0].id, enriched: false });
  if (path === "/api/v1/threat-actors") {
    const status = parsed.searchParams.get("status");
    return json({ actors: status ? actors.filter((a) => a.status === status) : actors });
  }
  if (path === "/api/v1/threat-actors/portrait-generator/availability") {
    return json({
      available: false,
      tool: "static-demo",
      message: "Portrait generation is disabled in the static public demo.",
    });
  }
  if (path === "/api/v1/threat-actors-tenant-tags") {
    return json({ tags: [], available: [], relevances: ["targeted", "sector-match", "watching"] });
  }
  if (/^\/api\/v1\/threat-actors\/[^/]+\/full$/.test(path)) {
    const id = path.split("/").slice(-2)[0];
    const actorRow = actors.find((a) => a.id === id);
    if (!actorRow) return json({ detail: "actor not found" }, 404);
    return json(actorRow);
  }
  if (/^\/api\/v1\/threat-actors\/[^/]+\/tenants$/.test(path)) {
    return json({ tags: [], available: [], relevances: ["targeted", "sector-match", "watching"] });
  }
  if (/^\/api\/v1\/threat-actors\/[^/]+\/export\.docx$/.test(path)) {
    return text("Static demo export is disabled.", 409);
  }
  if (path.startsWith("/api/v1/threat-actors/")) {
    const id = path.split("/")[4];
    const actorRow = actors.find((a) => a.id === id) ?? actors[0];
    if (method.toUpperCase() === "PATCH") return json({ ...actorRow, ...(data as Record<string, unknown>) });
    const created = job(
      `job-tap-${Date.now()}`,
      "threat_actor_enrichment",
      "completed",
      100,
      `TAP analysis - ${actorRow.primaryName}`,
      `#/threat-actors?focus=${actorRow.id}`,
      -0.01,
    );
    aiJobs.unshift(created);
    return json({ ...created, jobId: created.id, portraitUrl: actorRow.portraitUrl });
  }
  if (path === "/api/v1/ai-jobs/active") return json({ jobs: aiJobs });
  if (/^\/api\/v1\/ai-jobs\/[^/]+\/full$/.test(path)) return json(fullJob(path.split("/").slice(-2)[0]));
  if (/^\/api\/v1\/ai-jobs\/[^/]+$/.test(path)) {
    const id = path.split("/").pop()!;
    return json(
      aiJobs.find((j) => j.id === id) ??
        job(id, "osint_analysis", "completed", 100, "Static demo job", "#/osint", -0.01),
    );
  }

  if (path === "/api/v1/operations/audit") {
    return json({
      summary: { active: 0, failed: 0, completed: aiJobs.length, cancelled: 0 },
      jobs: aiJobs.map((j) => ({
        source: "ai_job",
        id: j.id,
        kind: j.kind,
        label: j.targetLabel,
        status: j.status,
        progressPct: j.progressPct,
        providerLabel: j.providerLabel,
        actor: "demo-admin",
        createdAt: j.createdAt,
        startedAt: j.startedAt,
        finishedAt: j.completedAt,
        heartbeatAt: j.heartbeatAt,
        target: j.targetLabel,
        targetUrl: j.targetUrl,
        errorMessage: null,
        cancellable: false,
      })),
      auditEntries: [
        {
          id: "audit-001",
          tenantId: "batchone",
          actor: "demo-admin",
          action: "static_demo_loaded",
          target: "public-demo",
          detail: '{"message":"Static demo dataset loaded"}',
          createdAt: iso(-1),
        },
      ],
      globalIngest: null,
    });
  }
  if (path.startsWith("/api/v1/operations/jobs")) return json({ ok: true, results: [] });

  if (path === "/api/v1/search") {
    const q = (parsed.searchParams.get("q") ?? "").toLowerCase();
    const results = [
      ...actors
        .filter((a) => a.primaryName.toLowerCase().includes(q))
        .map((a) => ({
          type: "Threat Actor",
          title: a.primaryName,
          subtitle: a.profileId,
          url: `#/threat-actors?focus=${a.id}`,
        })),
      ...findings
        .filter((f) => f.title.toLowerCase().includes(q))
        .slice(0, 5)
        .map((f) => ({ type: "Intel", title: f.title, subtitle: f.sourceName, url: `#/osint?finding=${f.id}` })),
    ];
    return json({ results });
  }

  if (path === "/api/v1/global/groups") return json({ groups: [] });
  if (path === "/api/v1/osint/automation/settings") {
    return json({
      settings: {
        tenantId: "batchone",
        autoFetchEnabled: false,
        fetchIntervalMin: 60,
        autoAnalyzeEnabled: false,
        analyzeConcurrency: 2,
        analyzeMaxPerTick: 8,
        lastFetchAt: iso(-2),
        lastFetchCount: 13,
        lastFetchError: null,
        lastAnalyzeAt: iso(-1),
        lastAnalyzeOkCount: 7,
        lastAnalyzeFailCount: 0,
        lastAnalyzeError: null,
        updatedAt: iso(-1),
      },
      queue: {
        pending: 0,
        done: findings.length,
        failed: 0,
        total: findings.length,
      },
    });
  }

  return json({ detail: `Static demo endpoint not implemented: ${method} ${path}` }, 404);
}
