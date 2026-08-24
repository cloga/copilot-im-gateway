import { cp, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const source = path.join(
  repositoryRoot,
  ".github",
  "extensions",
  "im-gateway",
);
const destination = path.join(
  os.homedir(),
  ".copilot",
  "extensions",
  "im-gateway",
);

await mkdir(path.dirname(destination), { recursive: true });
await cp(source, destination, { recursive: true, force: true });
console.error(`Installed user extension at ${destination}`);
