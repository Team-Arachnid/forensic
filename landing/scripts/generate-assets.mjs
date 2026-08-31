/**
 * Generates all brand + social assets from the source logo files in ../media.
 * Run once (and whenever the logo changes): `npm run assets`.
 * Outputs are committed static files, so the Vercel build never depends on
 * this script or on any font/text backend at deploy time.
 */
import sharp from "sharp";
import { mkdir, copyFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const media = path.resolve(root, "..", "media");
const pub = path.resolve(root, "public");
const brand = path.resolve(pub, "brand");

const VOID = "#08080a";

async function ensureDirs() {
  await mkdir(brand, { recursive: true });
}

/** Build a minimal ICO container that embeds PNG entries. */
function pngsToIco(entries) {
  const count = entries.length;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(count, 4);
  const dir = Buffer.alloc(16 * count);
  const blobs = [];
  let offset = 6 + 16 * count;
  entries.forEach((e, i) => {
    const b = e.buffer;
    const o = i * 16;
    dir.writeUInt8(e.size >= 256 ? 0 : e.size, o + 0);
    dir.writeUInt8(e.size >= 256 ? 0 : e.size, o + 1);
    dir.writeUInt8(0, o + 2);
    dir.writeUInt8(0, o + 3);
    dir.writeUInt16LE(1, o + 4);
    dir.writeUInt16LE(32, o + 6);
    dir.writeUInt32LE(b.length, o + 8);
    dir.writeUInt32LE(offset, o + 12);
    offset += b.length;
    blobs.push(b);
  });
  return Buffer.concat([header, dir, ...blobs]);
}

async function brandMarks() {
  const src = path.join(media, "logo.png"); // white emblem, transparent bg
  // trimmed, square, transparent — for nav/footer over dark surfaces
  const mark = await sharp(src)
    .trim()
    .resize(256, 256, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .png()
    .toBuffer();
  await writeFile(path.join(brand, "mark.png"), mark);

  // optimised copies of the originals for reference/use
  await sharp(src)
    .resize(512, 512, { fit: "inside" })
    .png({ compressionLevel: 9 })
    .toFile(path.join(brand, "logo.png"));
  await copyFile(
    path.join(media, "logo-badge.png"),
    path.join(brand, "logo-badge.png"),
  );
}

async function favicons() {
  const badge = path.join(media, "logo-badge.png"); // white emblem on dark disc
  const sizes = [16, 32, 48, 180, 192, 512];
  const pngs = {};
  for (const s of sizes) {
    pngs[s] = await sharp(badge)
      .resize(s, s, { fit: "cover" })
      .flatten({ background: VOID })
      .png()
      .toBuffer();
  }
  await writeFile(path.join(pub, "favicon-16.png"), pngs[16]);
  await writeFile(path.join(pub, "favicon-32.png"), pngs[32]);
  await writeFile(path.join(pub, "apple-touch-icon.png"), pngs[180]);
  await writeFile(path.join(pub, "favicon-192.png"), pngs[192]);
  await writeFile(path.join(pub, "favicon-512.png"), pngs[512]);
  await writeFile(
    path.join(pub, "favicon.ico"),
    pngsToIco([
      { size: 16, buffer: pngs[16] },
      { size: 32, buffer: pngs[32] },
      { size: 48, buffer: pngs[48] },
    ]),
  );
}

async function webmanifest() {
  const manifest = {
    name: "Arachnid Forensic",
    short_name: "Arachnid",
    description:
      "Open-source, unified digital forensics: live triage, file recovery, certified secure erasure.",
    start_url: "/",
    display: "standalone",
    background_color: VOID,
    theme_color: VOID,
    icons: [
      { src: "/favicon-192.png", sizes: "192x192", type: "image/png" },
      {
        src: "/favicon-512.png",
        sizes: "512x512",
        type: "image/png",
        purpose: "any maskable",
      },
    ],
  };
  await writeFile(
    path.join(pub, "site.webmanifest"),
    JSON.stringify(manifest, null, 2),
  );
}

async function ogImage() {
  const W = 1200;
  const H = 630;
  // decorative + text layer (sharp renders SVG text via its bundled backend)
  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}">
  <defs>
    <radialGradient id="v" cx="30%" cy="42%" r="82%">
      <stop offset="0%" stop-color="#141418"/>
      <stop offset="100%" stop-color="${VOID}"/>
    </radialGradient>
  </defs>
  <rect width="${W}" height="${H}" fill="url(#v)"/>
  <rect x="0" y="0" width="${W}" height="6" fill="#c81e3a"/>
  <rect x="40" y="40" width="${W - 80}" height="${H - 80}" fill="none" stroke="#26262b" stroke-width="1"/>

  <text x="472" y="140" fill="#e23150" font-family="Consolas, monospace" font-size="21" letter-spacing="5">OPEN-SOURCE DIGITAL FORENSICS</text>

  <text x="468" y="232" fill="#f3f2ee" font-family="Segoe UI, Arial, sans-serif" font-size="70" font-weight="700">One thread.</text>
  <text x="468" y="314" fill="#f3f2ee" font-family="Segoe UI, Arial, sans-serif" font-size="70" font-weight="700">Every phase</text>
  <text x="468" y="396" fill="#f3f2ee" font-family="Segoe UI, Arial, sans-serif" font-size="70" font-weight="700">of the case.</text>

  <rect x="472" y="430" width="110" height="3" fill="#c81e3a"/>

  <text x="472" y="490" fill="#8d8c92" font-family="Segoe UI, Arial, sans-serif" font-size="27">Live triage · File recovery · Certified erasure —</text>
  <text x="472" y="528" fill="#8d8c92" font-family="Segoe UI, Arial, sans-serif" font-size="27">one signed chain of custody, built in Rust.</text>

  <text x="472" y="582" fill="#5a5a61" font-family="Consolas, monospace" font-size="21">github.com/ArachnidGs/forensic</text>
</svg>`;

  const mark = await sharp(path.join(media, "logo.png"))
    .trim()
    .resize(300, 300, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .png()
    .toBuffer();

  await sharp(Buffer.from(svg))
    .composite([{ input: mark, left: 96, top: 168 }])
    .png()
    .toFile(path.join(pub, "og.png"));
}

async function main() {
  await ensureDirs();
  await brandMarks();
  await favicons();
  await webmanifest();
  await ogImage();
  console.log("assets: brand marks, favicons, webmanifest, og.png generated");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
