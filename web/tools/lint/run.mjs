// Runs ESLint for web/. The lint toolchain is a separate npm project (own lockfile) because
// typescript-eslint needs the TypeScript <=6 compiler API, while the workspace builds with TypeScript 7.
// Installs it with `npm ci` when missing or when its lockfile is newer than the install.
import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = join(here, "..", "..");
const lock = join(here, "package-lock.json");
const stamp = join(here, "node_modules", ".package-lock.json");
const eslintBin = join(here, "node_modules", "eslint", "bin", "eslint.js");

function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

if (!existsSync(eslintBin) || !existsSync(stamp) || statSync(lock).mtimeMs > statSync(stamp).mtimeMs) {
  run("npm", ["ci", "--no-audit", "--no-fund", "--loglevel=error"], here);
}
run(process.execPath, [eslintBin, "--max-warnings", "0", ...process.argv.slice(2), "."], webRoot);
