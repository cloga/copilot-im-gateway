import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      exclude: [".github/extensions/im-gateway/extension.mjs"],
      include: [
        "src/**/*.ts",
        ".github/extensions/im-gateway/**/*.mjs",
      ],
      provider: "v8",
      reporter: ["text", "json-summary"],
    },
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
