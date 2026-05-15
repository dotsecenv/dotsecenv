import sharp from 'sharp';
import { mkdir } from 'fs/promises';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = `${__dirname}/../src/assets/logo.png`;
const outDir = `${__dirname}/../public`;

const sizes = [
  { name: 'favicon.png', size: 32 },
  { name: 'apple-touch-icon.png', size: 180 },
  { name: 'icon-192.png', size: 192 },
];

async function generate() {
  await mkdir(outDir, { recursive: true });

  for (const { name, size } of sizes) {
    await sharp(source)
      .resize(size, size)
      .png()
      .toFile(`${outDir}/${name}`);
    console.log(`Generated ${name} (${size}x${size})`);
  }
}

generate().catch(console.error);
