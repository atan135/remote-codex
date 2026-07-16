import { describe, expect, it } from "vitest";

import { packageName, sharedProtocolVersion } from "./index.js";

describe("edge-client package", () => {
  it("exports its stable package name", () => {
    expect(packageName).toBe("@remote-codex/edge-client");
    expect(sharedProtocolVersion).toBe(2);
  });
});
