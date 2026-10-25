import { spawnSync } from "node:child_process";
import { REPOSITORY_ROOT } from "./evidence.mjs";

// AICODE-NOTE: BDD and this CLI share semantic verification. Hash integrity
// cannot turn producer-reported flags into evidence of real product effects.
const args = process.argv.slice(2).filter((value) => value !== "--");
const scenarioIndex = args.indexOf("--scenario");
const selected = scenarioIndex >= 0 ? args[scenarioIndex + 1] : args.find((value) => value === "all" || /^OID-SC-\d{3}$/.test(value)) ?? "all";
if (!/^(all|OID-SC-(00[1-9]|01[0-2]))$/.test(selected ?? "")) {
  console.error("Expected all or OID-SC-001 through OID-SC-012");
  process.exit(2);
}
const result = spawnSync("python", ["tools/replay_oid_acceptance.py", "--scenario", selected,
  ...(args.includes("--require-passed") ? ["--require-passed"] : [])], {
  cwd: REPOSITORY_ROOT, stdio: "inherit",
});
if (result.error) console.error("The container Python replay verifier could not start");
process.exitCode = result.status ?? 1;
