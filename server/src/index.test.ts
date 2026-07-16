import { describe, expect, it } from "vitest";

import { packageName, sharedProtocolVersion } from "./index.js";

describe("server package", () => {
  it("exports its stable package name", () => {
    expect(packageName).toBe("@remote-codex/server");
    expect(sharedProtocolVersion).toBe(1);
  });
});
