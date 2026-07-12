#!/usr/bin/env node
// Generates PWA icons for IceQ using sharp.
// Run: node web/scripts/generate-icons.mjs

import sharp from 'sharp';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { mkdirSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outDir = join(__dirname, '../public/icons');
mkdirSync(outDir, { recursive: true });

function makeSvg(size) {
  const safeZone = size * 0.8;
  const offset = (size - safeZone) / 2;
  const fontSize = Math.round(safeZone * 0.42);
  const cx = size / 2;
  const cy = size / 2 + fontSize * 0.35;
  return Buffer.from(`
    <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}">
      <rect width="${size}" height="${size}" fill="#0a0a0a" rx="${Math.round(size * 0.18)}"/>
      <text
        x="${cx}"
        y="${cy}"
        font-family="Arial, Helvetica, sans-serif"
        font-weight="bold"
        font-size="${fontSize}"
        fill="#00b4d8"
        text-anchor="middle"
      >IQ</text>
    </svg>
  `);
}

const icons = [
  { name: 'icon-192.png', size: 192 },
  { name: 'icon-512.png', size: 512 },
  { name: 'apple-touch-icon.png', size: 180 },
];

for (const { name, size } of icons) {
  const svg = makeSvg(size);
  const outPath = join(outDir, name);
  await sharp(svg)
    .png()
    .toFile(outPath);
  console.log(`✓ ${name} (${size}×${size})`);
}

console.log('Icons generated in web/public/icons/');
