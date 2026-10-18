import { defineConfig } from "vitest/config";

export default defineConfig({ test: { include: ["test/demo/wallet.demo.ts"], testTimeout: 0 } });
