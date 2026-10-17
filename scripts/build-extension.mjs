import { cp, mkdir, readdir, rm, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(projectRoot, "extension");
const output = resolve(projectRoot, "dist", "extension");

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const file of ["manifest.json", "popup.html", "popup.css", "THIRD_PARTY_NOTICES.txt"]) {
  await cp(resolve(source, file), resolve(output, file));
}
await build({
  absWorkingDir: projectRoot,
  entryPoints: ["extension/background.js", "extension/popup.js"],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome110",
  outdir: output,
  legalComments: "eof",
  sourcemap: false,
});
async function directoryBytes(path) {
  let bytes = 0;
  for (const entry of await readdir(path)) {
    const entryPath = resolve(path, entry);
    const details = await stat(entryPath);
    bytes += details.isDirectory() ? await directoryBytes(entryPath) : details.size;
  }
  return bytes;
}
console.log(`Built locally bundled extension at ${output} (${await directoryBytes(output)} bytes across packaged files)`);
