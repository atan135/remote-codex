import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      all: true,
      include: ["shared/src/**/*.ts", "server/src/**/*.ts", "egress-agent/src/**/*.ts", "edge-client/src/**/*.ts"],
      exclude: ["**/*.test.ts"],
      thresholds: {
        statements: 85,
        branches: 70,
        functions: 90,
        lines: 85
      }
    }
  }
});
