export type ClientProfileBulkCsvRecord = {
  name: string;
  clientTypes: string[];
  geographies: string[];
  industries: string[];
  monitoredTechnologies: string[];
  mappingTerms: string[];
  notificationEmails: string[];
  digestEnabled: boolean;
  digestCadence: "daily" | "weekly" | "biweekly" | "monthly";
};

export const CLIENT_PROFILE_BULK_CSV_TEMPLATE = `name,client_types,geographies,industries,technologies,mapping_terms,notification_emails,digest_enabled,digest_cadence
Northstar Intelligence,TI,Hong Kong|Singapore,Financial Services,,APAC threat actors|regional campaigns,cti@example.com,true,weekly
Contoso Managed Security,MSS|MDR,Hong Kong,Financial Services,Microsoft 365|Fortinet,Internet-facing services|identity estate,soc@example.com|ir@example.com,true,daily
Example Advisory,VCISO,United Kingdom,Professional Services,,Regulatory change|supply-chain risk,security@example.com,false,monthly`;

function parseCsvRows(input: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  const value = input.replace(/^\uFEFF/, "");
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (quoted) {
      if (char === '"' && value[index + 1] === '"') {
        cell += '"';
        index += 1;
      } else if (char === '"') {
        quoted = false;
      } else {
        cell += char;
      }
    } else if (char === '"') {
      quoted = true;
    } else if (char === ",") {
      row.push(cell.trim());
      cell = "";
    } else if (char === "\n") {
      row.push(cell.trim());
      if (row.some(Boolean)) rows.push(row);
      row = [];
      cell = "";
    } else if (char !== "\r") {
      cell += char;
    }
  }
  if (quoted) throw new Error("CSV contains an unclosed quoted value.");
  row.push(cell.trim());
  if (row.some(Boolean)) rows.push(row);
  return rows;
}

function list(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[|;]/g)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  );
}

function bool(value: string): boolean {
  return ["1", "true", "yes", "enabled"].includes(value.trim().toLowerCase());
}

export function parseClientProfileBulkCsv(input: string): ClientProfileBulkCsvRecord[] {
  const rows = parseCsvRows(input.trim());
  if (rows.length < 2) throw new Error("CSV must contain a header and at least one client row.");
  const aliases: Record<string, keyof ClientProfileBulkCsvRecord> = {
    name: "name",
    client_types: "clientTypes",
    clienttypes: "clientTypes",
    geographies: "geographies",
    geos: "geographies",
    industries: "industries",
    technologies: "monitoredTechnologies",
    monitored_technologies: "monitoredTechnologies",
    mapping_terms: "mappingTerms",
    notification_emails: "notificationEmails",
    digest_enabled: "digestEnabled",
    digest_cadence: "digestCadence",
  };
  const headers = rows[0].map((header) => aliases[header.trim().toLowerCase()]);
  if (!headers.includes("name")) throw new Error("CSV header must include name.");
  if (rows.length - 1 > 100) throw new Error("Import at most 100 Client Profiles at a time.");
  return rows.slice(1).map((values, index) => {
    const raw: Record<string, string> = {};
    headers.forEach((header, column) => {
      if (header) raw[header] = values[column] ?? "";
    });
    const name = String(raw.name ?? "").trim();
    if (name.length < 2) throw new Error(`Row ${index + 2}: client name must contain at least two characters.`);
    const cadence = String(raw.digestCadence || "weekly").toLowerCase();
    if (!["daily", "weekly", "biweekly", "monthly"].includes(cadence)) {
      throw new Error(`Row ${index + 2}: digest_cadence must be daily, weekly, biweekly, or monthly.`);
    }
    return {
      name,
      clientTypes: list(raw.clientTypes || ""),
      geographies: list(raw.geographies || ""),
      industries: list(raw.industries || ""),
      monitoredTechnologies: list(raw.monitoredTechnologies || ""),
      mappingTerms: list(raw.mappingTerms || ""),
      notificationEmails: list(raw.notificationEmails || ""),
      digestEnabled: bool(raw.digestEnabled || "false"),
      digestCadence: cadence as ClientProfileBulkCsvRecord["digestCadence"],
    };
  });
}
