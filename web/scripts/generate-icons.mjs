#!/usr/bin/env node
// Generates PWA icons and favicon for IceQ — Ice Bloom Q mark.
// Run: node web/scripts/generate-icons.mjs
//
// Renders the six-lobe crystalline Ice Bloom Q SVG at every required
// raster size using sharp.  No external fonts or bitmap sources.

import sharp from 'sharp';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { mkdirSync, writeFileSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '../public/icons');
mkdirSync(outDir, { recursive: true });

// ── Ice Bloom Q SVG (compact, favicon-safe) ──────────────────────────
//
// Geometry matches the IceQMark React component exactly:
//   6 rounded crystalline lobes · lower-right Q-tail · central mint dot
//
// viewBox 0 0 100 100 — rendered at target size by sharp.

const PALETTE = {
  bg:     "#050713",   // abyss
  electric: "#35D5F4", // lobe 0°, 60°, 300°
  violet:   "#735CFF", // lobe 180°, 240°
  magenta:  "#F13CA8", // lobe 120° (Q-tail)
  mint:     "#21D6A0", // center
};

// Canonical ice-bloom lobe — smooth rounded petal pointing UP from (50,50)
const LOBE =
  "M46,48 " +
  "C40,45 36,38 36,28 " +
  "C36,18 42,8 50,5 " +
  "C58,8 64,18 64,28 " +
  "C64,38 60,45 54,48 " +
  "Z";

// Q-tail stroke — starts **inside** the 120° lobe, sweeps beyond its tip
const QTAIL = "M73,64 Q85,66 92,82";

// Six lobes: all use the SAME shape.  Only the 120° lobe gets colour + tail.
// Angles from top: 0° 60° 120°(Q) 180° 240° 300°
// Colours:         ice ice magenta  violet violet ice
const LOBES = [
  { angle: 0,   color: PALETTE.electric },
  { angle: 60,  color: PALETTE.electric },
  { angle: 120, color: PALETTE.magenta },
  { angle: 180, color: PALETTE.violet },
  { angle: 240, color: PALETTE.violet },
  { angle: 300, color: PALETTE.electric },
];

const Q_INDEX = 2; // 120°

function iceBloomSvg(size, addBackground, compact) {
  const vb = 100;
  const tailW = compact ? "4.5" : "3";
  const dotR = compact ? "2.8" : "2";

  const bgRect = addBackground
    ? `<rect width="${vb}" height="${vb}" fill="${PALETTE.bg}" rx="${Math.round(vb * 0.18)}" />`
    : "";

  const lobeEls = LOBES.map(({ angle, color }, i) => {
    const lobePath = `<g transform="rotate(${angle},50,50)"><path d="${LOBE}" fill="${color}" opacity="0.88"/></g>`;
    if (i === Q_INDEX) {
      return `${lobePath}
      <path d="${QTAIL}" stroke="${PALETTE.magenta}" stroke-width="${tailW}" stroke-linecap="round" fill="none" opacity="0.88"/>`;
    }
    return lobePath;
  }).join("\n      ");

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${vb} ${vb}">
  ${bgRect}
  ${lobeEls}
  <circle cx="50" cy="50" r="${dotR}" fill="${PALETTE.mint}"/>
</svg>`;
}

// ── Generate PWA icons ──────────────────────────────────────────────

const icons = [
  { name: 'icon-192.png', size: 192 },
  { name: 'icon-512.png', size: 512 },
  { name: 'apple-touch-icon.png', size: 180 },
];

for (const { name, size } of icons) {
  const svg = iceBloomSvg(size, true, false);
  const outPath = join(outDir, name);
  await sharp(Buffer.from(svg))
    .png()
    .toFile(outPath);
  console.log(`✓ ${name} (${size}×${size})`);
}

// ── Generate favicon PNGs (compact for legibility at tiny sizes) ────

const faviconSizes = [16, 32, 48];
const faviconPngs = [];

for (const size of faviconSizes) {
  const svg = iceBloomSvg(size, true, true); // compact
  const buf = await sharp(Buffer.from(svg)).png().toBuffer();
  faviconPngs.push({ size, buf });
  console.log(`✓ favicon-${size}.png (${size}×${size})`);
}

// ── Generate multi-size .ico ────────────────────────────────────────
// Sharp doesn't write .ico directly — write the 32px PNG as favicon.ico
// (modern browsers accept PNG inside .ico). Also write standalone PNGs.
const favicon32 = faviconPngs.find(f => f.size === 32);
writeFileSync(join(outDir, 'favicon.ico'), favicon32.buf);
console.log(`✓ favicon.ico (32×32 PNG-wrapped)`);

// Write standalone favicon PNGs
for (const { size, buf } of faviconPngs) {
  writeFileSync(join(outDir, `favicon-${size}.png`), buf);
}

// ── Generate maskable variants (extra padding for Android) ──────────
//
// Maskable icons need the content within the inner 66.67% safe zone.
// We add a background rect and keep the mark within the safe area.

const maskableSizes = [192, 512];
for (const size of maskableSizes) {
  const svg = iceBloomSvg(size, true, false);
  const outPath = join(outDir, `maskable-${size}.png`);
  await sharp(Buffer.from(svg))
    .png()
    .toFile(outPath);
  console.log(`✓ maskable-${size}.png (${size}×${size})`);
}

// ── Safari pinned-tab SVG (compact geometry) ────────────────────────

const pinnedSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" fill="${PALETTE.bg}" rx="16"/>
  <g transform="translate(50,50) scale(0.7) translate(-50,-50)">
    ${LOBES.map(({ angle, color }, i) => {
      const lobe = `<g transform="rotate(${angle},50,50)"><path d="${LOBE}" fill="${color}"/></g>`;
      if (i === Q_INDEX) {
        return `${lobe}
    <path d="${QTAIL}" stroke="${PALETTE.magenta}" stroke-width="4.5" stroke-linecap="round" fill="none"/>`;
      }
      return lobe;
    }).join("\n    ")}
    <circle cx="50" cy="50" r="2.8" fill="${PALETTE.mint}"/>
  </g>
</svg>`;
writeFileSync(join(outDir, 'safari-pinned-tab.svg'), pinnedSvg + '\n');
console.log(`✓ safari-pinned-tab.svg`);

console.log(`\nIcons generated in ${outDir}/`);
