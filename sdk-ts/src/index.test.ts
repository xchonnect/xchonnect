import { describe, expect, it } from "vitest";
import { PROTOCOL_VERSION } from "./index.js";

describe("sdk", () => {
  it("speaks protocol v1", () => {
    expect(PROTOCOL_VERSION).toBe(1);
  });
});
