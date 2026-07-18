import { generateKeyPairSync } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { IdentityKeyRole, type IdentityKeyRole as IdentityKeyRoleType } from "@remote-codex/shared";

import { fail } from "./errors.js";
import { createOwnerOnlyDirectory, writeNewFile } from "./secure-files.js";

export interface GeneratedIdentityFiles {
  readonly role: IdentityKeyRoleType;
  readonly keyId: string;
  readonly publicKeyPath: string;
  readonly privateKeyPath: string;
  readonly descriptorPath: string;
}

const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

function assertRole(role: IdentityKeyRoleType): void {
  if (!Object.values(IdentityKeyRole).includes(role)) {
    fail("OPS_IDENTITY_ROLE_INVALID");
  }
}

/** 生成不可覆盖的 Ed25519 材料；命令输出只包含路径和 key ID，不包含密钥正文。 */
export function generateIdentityFiles(input: {
  readonly rootDirectory: string;
  readonly outputDirectory: string;
  readonly role: IdentityKeyRoleType;
  readonly keyId: string;
}): GeneratedIdentityFiles {
  assertRole(input.role);
  if (!IDENTIFIER_PATTERN.test(input.keyId)) {
    return fail("OPS_INVALID_IDENTIFIER", "keyId");
  }
  const directory = createOwnerOnlyDirectory(input.rootDirectory, input.outputDirectory);
  const publicKeyPath = `${input.outputDirectory}/public.pem`;
  const privateKeyPath = `${input.outputDirectory}/private.pem`;
  const descriptorPath = `${input.outputDirectory}/identity.json`;
  if (
    existsSync(join(directory, "private.pem")) ||
    existsSync(join(directory, "public.pem")) ||
    existsSync(join(directory, "identity.json"))
  ) {
    return fail("OPS_FILE_ALREADY_EXISTS");
  }
  const keys = generateKeyPairSync("ed25519");
  const publicPem = keys.publicKey.export({ format: "pem", type: "spki" });
  const privatePem = keys.privateKey.export({ format: "pem", type: "pkcs8" });
  writeNewFile(join(directory, "private.pem"), privatePem, "owner-only");
  writeNewFile(join(directory, "public.pem"), publicPem, "public-readonly");
  writeNewFile(
    join(directory, "identity.json"),
    `${JSON.stringify({ role: input.role, keyId: input.keyId, publicKeyPath, privateKeyPath }, null, 2)}\n`,
    "owner-only"
  );
  return Object.freeze({ role: input.role, keyId: input.keyId, publicKeyPath, privateKeyPath, descriptorPath });
}
