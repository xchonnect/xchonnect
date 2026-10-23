/**
 * Assets and amounts as the agent writes them and as the wallet takes them. An agent writes
 * amounts in units ("0.25" XCH, "12.5" of a CAT); the wallet takes mojos. The conversion is
 * exact (strings and bigints, never floating point), and an amount with more decimals than the
 * asset has is refused rather than rounded.
 */

/** XCH has 12 decimals, every CAT 3. */
export const XCH_DECIMALS = 12;
export const CAT_DECIMALS = 3;

/** `"xch"`, or a CAT's asset id (TAIL hash) as 64 lowercase hex digits. */
export type AssetId = string;

export class AmountError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AmountError";
  }
}

/** `"xch"` or 64 lowercase hex digits, from `xch`, `XCH`, or a hex id with or without `0x`. */
export function assetId(text: unknown, name = "asset"): AssetId {
  if (typeof text !== "string") throw new AmountError(`${name} must be a string`);
  const t = text.trim();
  if (t.toLowerCase() === "xch") return "xch";
  const hex = t.replace(/^0x/i, "").toLowerCase();
  if (/^[0-9a-f]{64}$/.test(hex)) return hex;
  throw new AmountError(`${name}: "${t.slice(0, 80)}" is not xch or a CAT asset id (64 hex characters); look the id up first (nodexch search_assets)`);
}

export function decimalsOf(asset: AssetId): number {
  return asset === "xch" ? XCH_DECIMALS : CAT_DECIMALS;
}

/** Units as a decimal string ("1", "0.25") to mojos, exactly. Positive only. */
export function toMojos(units: unknown, asset: AssetId, name = "amount"): bigint {
  // A JSON number past 2^53 has already lost digits: only strings, or numbers that are exact.
  if (typeof units === "number" && !(Number.isSafeInteger(units) || (Number.isFinite(units) && Math.abs(units) < 2 ** 53 && String(units).length <= 17 && !/e/i.test(String(units))))) {
    throw new AmountError(`${name}: write large or precise amounts as a string, like "0.25"`);
  }
  const text = typeof units === "number" ? String(units) : units;
  if (typeof text !== "string" || !/^\d+(\.\d+)?$/.test(text.trim())) {
    throw new AmountError(`${name} must be a positive decimal number of units, like "0.25"`);
  }
  const decimals = decimalsOf(asset);
  const [whole = "0", fraction = ""] = text.trim().split(".");
  if (fraction.length > decimals) {
    throw new AmountError(`${name} has more than ${decimals} decimals, the most ${asset === "xch" ? "XCH" : "a CAT"} has`);
  }
  const mojos = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, "0") || "0");
  if (mojos <= 0n) throw new AmountError(`${name} must be more than 0`);
  return mojos;
}

/** What a malformed wallet amount gives: fixed, never the wallet's text (T22). */
export const WALLET_AMOUNT_ERROR = "the wallet answered with an amount that is not a whole number of mojos";

/**
 * A mojo amount off the wire (the wallet's rules or balances): 1 to 40 digits, or a safe
 * non-negative whole number. Anything else is refused with a fixed message, so a wallet's
 * long or odd text never reaches `BigInt` (whose error would carry it) or the agent.
 */
export function mojoText(v: unknown): bigint {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === "string" && /^\d{1,40}$/.test(v)) return BigInt(v);
  throw new Error(WALLET_AMOUNT_ERROR);
}

/** Mojos to units as a decimal string without trailing zeros. */
export function fromMojos(mojos: bigint | string | number, asset: AssetId): string {
  const value = BigInt(mojos);
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const decimals = decimalsOf(asset);
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const fraction = (abs % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${negative ? "-" : ""}${whole}${fraction ? `.${fraction}` : ""}`;
}

/** A fee in XCH units (default 0) to mojos; 0 is allowed. */
export function feeMojos(fee: unknown): bigint {
  if (fee === undefined || fee === null || fee === "" || fee === "0" || fee === 0) return 0n;
  return toMojos(fee, "xch", "fee");
}
