import { isIP } from "node:net";

const hostnamePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;
const host = process.env.REMOTE_CODEX_VERIFY_HOST ?? "";
const origin = process.env.REMOTE_CODEX_VERIFY_ORIGIN ?? "";
let parsed;

try {
  parsed = new URL(origin);
} catch {
  process.exitCode = 2;
}

if (
  parsed === undefined ||
  !hostnamePattern.test(host) ||
  isIP(host) !== 0 ||
  host.includes("*") ||
  parsed.protocol !== "https:" ||
  parsed.origin !== origin ||
  parsed.username !== "" ||
  parsed.password !== "" ||
  origin.includes("@") ||
  parsed.pathname !== "/" ||
  parsed.search !== "" ||
  parsed.hash !== "" ||
  !hostnamePattern.test(parsed.hostname) ||
  isIP(parsed.hostname) !== 0 ||
  parsed.hostname.includes("*")
) {
  process.exitCode = 2;
}
