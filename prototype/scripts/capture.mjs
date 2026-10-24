// Capture every UX figure as a PNG in ../ux-flows/images/<figure id>.png.
// Builds the app, serves the build, and screenshots each storyboard at its
// native 2000 px width. Run from prototype/: npm run capture [figure-id...]

import { execFileSync, spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "..", "ux-flows", "images");
const PORT = 5198;
const only = process.argv.slice(2);

execFileSync("npx", ["vite", "build", "--logLevel", "warn"], { cwd: root, stdio: "inherit" });
const server = spawn("npx", ["vite", "preview", "--port", String(PORT), "--strictPort"], { cwd: root, stdio: "ignore" });

try {
  const base = `http://localhost:${PORT}/ux.html`;
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 2000, height: 1200 }, deviceScaleFactor: 1 });
  for (let i = 0; ; i++) {
    try { await page.goto(`${base}?figures`); break; } catch { if (i > 50) throw new Error("preview server did not start"); await new Promise((r) => setTimeout(r, 200)); }
  }
  const ids = (await page.$$eval(".index a", (as) => as.map((a) => new URL(a.href).searchParams.get("figure"))))
    .filter((id) => id && (!only.length || only.includes(id)));
  mkdirSync(out, { recursive: true });
  for (const id of ids) {
    await page.goto(`${base}?figure=${id}`);
    await page.waitForSelector(".figure");
    await page.evaluate(() => document.fonts.ready);
    const file = join(out, `${id}.png`);
    await (await page.$(".figure")).screenshot({ path: file });
    console.log(`captured ${id}`);
  }
  await browser.close();
} finally {
  server.kill();
}
