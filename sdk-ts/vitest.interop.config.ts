import { defineConfig } from "vitest/config";

export default defineConfig({ test: { include: ["interop/**/*.test.ts"], testTimeout: 90_000 } });
