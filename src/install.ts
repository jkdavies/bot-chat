import { readFileSync, writeFileSync } from "node:fs";
import { passwordHash } from "./security.js";
// Read a password from stdin (pipe from a password manager or protected file).
const password = readFileSync(0, "utf8").trim();
const path = process.argv[2];
if (!path || password.length < 12 || password.length > 1024) {
  console.error(
    "Usage: npm run install-owner -- /path/to/owner.hash < /protected/password-file (12+ characters)",
  );
  process.exit(1);
}
writeFileSync(path, passwordHash(password), { mode: 0o600, flag: "wx" });
console.log("Owner hash created");
