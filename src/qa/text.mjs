import { open } from "node:fs/promises";

// A file is text unless its first 8 KB hold a NUL byte. Pages publishes every file in the output,
// so anything readable is checked, whatever its extension.
export async function isText(path) {
  const fh = await open(path, "r");
  try {
    const buf = Buffer.alloc(8192);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    return !buf.subarray(0, bytesRead).includes(0);
  } finally {
    await fh.close();
  }
}
