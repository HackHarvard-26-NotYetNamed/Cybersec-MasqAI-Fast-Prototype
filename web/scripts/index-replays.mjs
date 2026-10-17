// Regenerates public/data/replays/index.json (an array of {id, title, file}) from the replay files in that folder.
// Runs before `dev` and `build`, so dropping in a new uc*.json is enough to add it to /demo.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "public", "data", "replays");
const replays = [];
for (const file of readdirSync(dir).filter((f) => f.endsWith(".json") && f !== "index.json").sort()) {
  try {
    const { id, title } = JSON.parse(readFileSync(join(dir, file), "utf8"));
    replays.push({ id: id ?? file.replace(/\.json$/, ""), title: title ?? file, file });
  } catch (err) {
    // Keep it listed: /demo shows a friendly validation error for the broken file.
    console.warn(`index-replays: ${file} is not valid JSON (${err.message})`);
    replays.push({ id: file.replace(/\.json$/, ""), title: file, file });
  }
}
writeFileSync(join(dir, "index.json"), JSON.stringify(replays, null, 2) + "\n");
console.log(`index-replays: ${replays.length} replays`);
