import { describe, expect, it } from "vitest";

import { packageName } from "./index.js";

describe("edge-client package", () => {
  it("exports its stable package name", () => {
    expect(packageName).toBe("@remote-codex/edge-client");
  });
});
