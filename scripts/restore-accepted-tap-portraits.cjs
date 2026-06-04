#!/usr/bin/env node

const Database = require("better-sqlite3");
const { copyFileSync, existsSync, mkdirSync, statSync } = require("node:fs");
const { join, resolve } = require("node:path");

const THREAD_ID = "019e827a-2639-7bd0-bd5f-6bee01543cca";
const ACCEPTED_IMAGE_DIR = resolve(process.env.HOME || "", ".codex", "generated_images", THREAD_ID);
const PORTRAITS_DIR = resolve(process.cwd(), "data", "portraits");
const DB_PATHS = ["data.db", "data/data.db"].filter((p) => existsSync(p));

const ACCEPTED = [
  ["Qilin", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e5da3c5d4819199caf349e84dcf18.png"],
  ["Cl0p", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e5ed0d40c8191ac1d23fbc214deda.png"],
  ["Play", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e5f466068819191b6146af36bb741.png"],
  ["LockBit", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e5fd6b5f081919f9d2ef7cb38cab5.png"],
  ["Scattered Spider", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e6062d8e48191a0f6777602896992.png"],
  ["RansomHub", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e61d50cb881918c32cadf9ec45253.png"],
  ["DragonForce", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e625304fc8191bb0532f0a11dff27.png"],
  ["INC Ransom", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e62cf2c6481919a8fb608bc1f49a2.png"],
  ["SafePay", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e63497dd881918cebec57f3c99494.png"],
  ["FIN7", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e63c548088191a5f1ddf22db24117.png"],
  ["TA505", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e664e5788819183046a065bd60c88.png"],
  ["Conti", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e66e099788191a3f05a5f44ef099c.png"],
  ["Hive", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e679a66c88191bc17e118a6e09d4f.png"],
  ["ShinyHunters", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e68359030819190f8433ebe403766.png"],
  ["Octo Tempest", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e68cbbc748191a209d54de5b3be5f.png"],
  ["APT32", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e6db7e5b48191b2d69f9f3cb2104d.png"],
  ["UNC4841", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e6e4e9f2c81919acd3a5d42c8cc86.png"],
  ["LAPSUS$", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e714b12988191b2cd086c1f7084a9.png"],
  ["BlueNoroff", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e72067fa48191bea0144508a37f49.png"],
  ["APT38", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e72a19f8881918a150025fb624a1f.png"],
  ["FIN11", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e80c14860819193911cfe1cf4bfdc.png"],
  ["FIN8", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e82c21ef88191882f97cbb4ac2cc8.png"],
  ["Equation Group", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e8370ce288191a10d7ac9ce4f850f.png"],
  ["Cuba", "019e85aa-47b7-7a71-aa65-542836c1042b/ig_03b7b1f69881f6e4016a1e842851308191bae3e41a571a6213.png"],
  ["BianLian", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1ccdcb7cd88191a829ee00ae660f73.png"],
  ["Black Basta", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1cd07d08d88191860f41e286681de4.png"],
  ["BlackByte", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1cd19f5b648191aded71e2a87b80d3.png"],
  ["BlackCat", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1cd2d1077c8191b8d3ed7d31ac8bba.png"],
  ["Akira", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1c403994888191927920936c6a96f7.png"],
  ["Andariel", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1c433c43f88191b5f3235c93f7df05.png"],
  ["8Base", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1083e04a108191b871a4bb360d1f6c.png"],
  ["APT28", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a108579324c8191a94b41a0b8173dfa.png"],
  ["APT29", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a10876def308191b0d03f27de6899a3.png"],
  ["APT31", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1088d6cfe88191b062318346f6cb72.png"],
  ["APT33", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a108998399c8191809e99954569eb94.png"],
  ["APT35", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a108b6febac81919cdaa34903dd0cd0.png"],
  ["APT40", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a108e0bc6c88191a5e2f03a686b3c71.png"],
  ["APT43", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a108f5f782481919502b31344222b79.png"],
  ["Agrius", "019e4b83-670c-7e01-97e0-448b590b712d/ig_0d0b270a84126480016a1090ef80348191a4a3c8508c3324e6.png"],
  ["Evil Corp", "ig_055afb3885fb19b8016a1d4efbfac88191b71ee6b78c0b2d27.png"],
  ["Lazarus Group", "ig_055afb3885fb19b8016a1d4fb247488191b6e7587487e643ab.png"],
  ["Kimsuky", "ig_055afb3885fb19b8016a1d502b649c8191a54c0cdffa0c158c.png"],
  ["Volt Typhoon", "ig_055afb3885fb19b8016a1d5097224081919de4713f16650fa3.png"],
  ["Salt Typhoon", "ig_055afb3885fb19b8016a1d50ef4a44819183f6f92c4322a3cd.png"],
  ["Flax Typhoon", "ig_055afb3885fb19b8016a1d516edd10819192b9d1df3c3c8bdd.png"],
  ["Mustang Panda", "ig_055afb3885fb19b8016a1d51ed4d1c8191b1e3fe1cc328f33c.png"],
  ["APT41", "ig_055afb3885fb19b8016a1d528182548191bee834cb22ba1c32.png"],
  ["UNC3886", "ig_055afb3885fb19b8016a1d53627e0081919eb7611233e162ca.png"],
  ["Turla", "ig_055afb3885fb19b8016a1d53e135a88191b3b2a6ef7cc4330c.png"],
  ["Sandworm Team", "ig_055afb3885fb19b8016a1d547677bc8191b5e7dadfe88999ae.png"],
  ["Gamaredon", "ig_055afb3885fb19b8016a1d5532d66c81918c6088521cc0a0f6.png"],
  ["FIN6", "ig_055afb3885fb19b8016a1d561da0088191b58fdf23b595a6ad.png"],
  ["MuddyWater", "ig_055afb3885fb19b8016a1d56c8b7d08191a971c8c0ec20f851.png"],
  ["OilRig", "ig_055afb3885fb19b8016a1d57ea72248191b2565cc43870ff97.png"],
  ["Charming Kitten", "ig_055afb3885fb19b8016a1d5886778081919462461e702ac7b0.png"],
  ["Royal", "ig_055afb3885fb19b8016a1d591930f48191b3456f0868cbd1b4.png"],
  ["BlackSuit", "ig_055afb3885fb19b8016a1d59c54ed88191834dbc1d2fba20f7.png"],
  ["Hunters International", "ig_055afb3885fb19b8016a1d5a5b935481918c9b735a11763027.png"],
  ["Medusa", "ig_055afb3885fb19b8016a1d5af060f08191b8b9903826925bbd.png"],
  ["Rhysida", "ig_055afb3885fb19b8016a1d5b8f4f148191b3ca792e018b2730.png"],
  ["Cactus", "ig_055afb3885fb19b8016a1d5c240e688191aa3bee1963bef759.png"],
  ["TA577", "ig_055afb3885fb19b8016a1d5cd9b3088191853252d9670d036b.png"],
  ["Storm-0501", "ig_055afb3885fb19b8016a1d5de159c48191b808671485c2f561.png"],
  ["Anubis", "ig_055afb3885fb19b8016a1d87febb708191996b2c3eccfae8b7.png"],
  ["ScarCruft", "ig_055afb3885fb19b8016a1d88654d3881918e42f4e3628c7e00.png"],
  ["Everest", "ig_055afb3885fb19b8016a1da4d0b29881918a919e92d83b8bd4.png"],
  ["WorldLeaks", "ig_055afb3885fb19b8016a1da63d3a1881918a7fd21abf5259b4.png"],
];

function norm(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function parseAliases(value) {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function namesFor(actorName) {
  const names = new Set([norm(actorName)]);
  const n = norm(actorName);
  if (n === "lazarusgroup") names.add("lazarus");
  if (n === "sandwormteam") names.add("sandworm");
  if (n === "blacksuit") names.add("royalransomware");
  if (n === "scarcruft") {
    names.add("apt37");
    names.add("reaper");
    names.add("group123");
  }
  return names;
}

function rowMatches(row, wanted) {
  if (wanted.has(norm(row.primary_name))) return true;
  for (const alias of parseAliases(row.aliases)) {
    if (wanted.has(norm(alias))) return true;
  }
  return false;
}

function requireInputs() {
  if (!DB_PATHS.length) throw new Error("No OptraSight database found.");
  if (!existsSync(ACCEPTED_IMAGE_DIR)) throw new Error(`Accepted image directory not found: ${ACCEPTED_IMAGE_DIR}`);
  for (const [, fileName] of ACCEPTED) {
    const fullPath = fileName.includes("/") ? resolve(ACCEPTED_IMAGE_DIR, "..", fileName) : join(ACCEPTED_IMAGE_DIR, fileName);
    if (!existsSync(fullPath)) throw new Error(`Accepted image not found: ${fullPath}`);
    if (statSync(fullPath).size < 1_000_000) {
      throw new Error(`Accepted image is unexpectedly small, refusing restore: ${fullPath}`);
    }
  }
}

function main() {
  requireInputs();
  mkdirSync(PORTRAITS_DIR, { recursive: true });

  const ts = new Date().toISOString();
  const cacheBust = Date.now();
  const restoredActors = new Set();
  let totalRows = 0;

  for (const dbPath of DB_PATHS) {
    const db = new Database(dbPath);
    db.pragma("busy_timeout = 10000");
    const rows = db.prepare("SELECT id, tenant_id, primary_name, aliases FROM threat_actors").all();
    const update = db.prepare(`
      UPDATE threat_actors
         SET portrait_url = ?,
             portrait_generated_at = ?,
             portrait_status = 'ready'
       WHERE id = ? AND tenant_id = ?
    `);

    const tx = db.transaction(() => {
      let dbRows = 0;
      for (const [actorName, fileName] of ACCEPTED) {
        const source = fileName.includes("/") ? resolve(ACCEPTED_IMAGE_DIR, "..", fileName) : join(ACCEPTED_IMAGE_DIR, fileName);
        const wanted = namesFor(actorName);
        const matches = rows.filter((row) => rowMatches(row, wanted));
        if (!matches.length) continue;
        restoredActors.add(actorName);
        for (const row of matches) {
          const target = join(PORTRAITS_DIR, `${row.id}.png`);
          copyFileSync(source, target);
          update.run(`/portraits/${row.id}.png?v=${cacheBust}`, ts, row.id, row.tenant_id);
          dbRows += 1;
          totalRows += 1;
        }
      }
      console.log(`${dbPath}: restored ${dbRows} portrait row(s)`);
    });

    tx();
    db.close();
  }

  const missing = ACCEPTED.map(([actorName]) => actorName).filter((actorName) => !restoredActors.has(actorName));
  console.log(`Restored ${restoredActors.size}/${ACCEPTED.length} accepted actor portrait(s), ${totalRows} row file(s).`);
  if (missing.length) console.log(`No matching rows for: ${missing.join(", ")}`);
}

main();
