import { configDefaults, defineConfig } from "vitest/config";

// Interop tests need the relay and wallet binaries; run them with `npm run test:interop`.
export default defineConfig({ test: { exclude: [...configDefaults.exclude, "interop/**"] } });
