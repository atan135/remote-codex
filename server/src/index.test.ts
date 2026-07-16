import { describe, expect, it } from "vitest";

import { packageName } from "./index.js";

describe("server package", () => {
  it("exports its stable package name", () => {
    expect(packageName).toBe("@remote-codex/server");
  });
});
