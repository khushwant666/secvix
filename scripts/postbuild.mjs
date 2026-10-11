import { chmodSync } from "node:fs";
import { join } from "node:path";

const binPath = join(process.cwd(), "dist", "bin", "secvix.js");
try {
  chmodSync(binPath, 0o755);
} catch {
  // Windows may ignore mode bits; executable still runs via `node dist/bin/secvix.js`
}
