/**
 * The pairing QR code: as a PNG opened in the system image viewer (the most reliable to scan),
 * and as text drawn with half-height block characters for a chat to show in a code block. The
 * PNG is written here (zlib from Node), so nothing but the QR matrix comes from a library.
 */
import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { crc32, deflateSync } from "node:zlib";
import qrcode from "qrcode-generator";

/** The QR matrix of `text`: `true` for a dark module. Error correction M. */
export function matrix(text: string): boolean[][] {
  const qr = qrcode(0, "M");
  qr.addData(text, "Byte");
  qr.make();
  const n = qr.getModuleCount();
  return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => qr.isDark(r, c)));
}

const QUIET = 2;

/**
 * The QR code as text, two module rows per line. For a dark terminal (light text on dark), the
 * light modules are drawn, so the code reads dark on light like a printed one; `lightTerminal`
 * draws the dark modules instead.
 */
export function text(m: boolean[][], lightTerminal = false): string {
  const n = m.length;
  const at = (r: number, c: number): boolean => {
    const inside = r >= 0 && r < n && c >= 0 && c < n;
    const dark = inside ? (m[r]?.[c] ?? false) : false;
    return lightTerminal ? dark : !dark;
  };
  const lines: string[] = [];
  for (let r = -QUIET; r < n + QUIET; r += 2) {
    let line = "";
    for (let c = -QUIET; c < n + QUIET; c++) {
      const top = at(r, c);
      const bottom = r + 1 < n + QUIET ? at(r + 1, c) : !lightTerminal;
      line += top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ";
    }
    lines.push(line);
  }
  return lines.join("\n");
}

function chunk(type: string, data: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body) >>> 0);
  return Buffer.concat([length, body, crc]);
}

/** The QR code as a grayscale PNG, `scale` pixels per module, with a 4-module quiet zone. */
export function png(m: boolean[][], scale = 8): Buffer {
  const n = m.length;
  const quiet = 4;
  const size = (n + 2 * quiet) * scale;
  const rows: Buffer[] = [];
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(size + 1, 255);
    row[0] = 0; // filter: none
    const r = Math.floor(y / scale) - quiet;
    for (let x = 0; x < size; x++) {
      const c = Math.floor(x / scale) - quiet;
      if (r >= 0 && r < n && c >= 0 && c < n && m[r]?.[c]) row[x + 1] = 0;
    }
    rows.push(row);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 0; // grayscale
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(Buffer.concat(rows))),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/** Writes the PNG and opens it in the system image viewer. Whether a viewer was started. */
export async function showImage(m: boolean[][], path: string, open = true): Promise<boolean> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, png(m), { mode: 0o600 });
  if (!open) return false;
  const [command, args] =
    process.platform === "darwin" ? ["open", [path]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", path]] : ["xdg-open", [path]];
  return new Promise((resolve) => {
    try {
      const child = spawn(command as string, args as string[], { stdio: "ignore", detached: true });
      child.on("error", () => resolve(false));
      child.on("spawn", () => {
        child.unref();
        resolve(true);
      });
    } catch {
      resolve(false);
    }
  });
}
