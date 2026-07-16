import { describe, expect, it } from "vitest";

import { packageName } from "./index.js";

describe("egress-agent package", () => {
  it("exports its stable package name", () => {
    expect(packageName).toBe("@remote-codex/egress-agent");
  });
});
