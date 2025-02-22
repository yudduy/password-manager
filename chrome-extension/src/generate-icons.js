const fs = require('fs');
const { createCanvas } = require('canvas');

const sizes = [16, 48, 128];

function generateIcon(size) {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');

  // Background
  ctx.fillStyle = '#1a73e8';
  ctx.beginPath();
  ctx.arc(size/2, size/2, size/2, 0, Math.PI * 2);
  ctx.fill();

  // Lock shape
  ctx.fillStyle = '#ffffff';
  const lockWidth = size * 0.6;
  const lockHeight = size * 0.8;
  const x = (size - lockWidth) / 2;
  const y = (size - lockHeight) / 2;

  // Lock body
  ctx.fillRect(x, y + lockHeight * 0.3, lockWidth, lockHeight * 0.7);

  // Lock arc
  ctx.beginPath();
  ctx.arc(size/2, y + lockHeight * 0.3, lockWidth/2, Math.PI, Math.PI * 2);
  ctx.fill();

  return canvas.toBuffer();
}

// Create public directory if it doesn't exist
if (!fs.existsSync('../public')) {
  fs.mkdirSync('../public', { recursive: true });
}

// Generate icons for each size
sizes.forEach(size => {
  const iconBuffer = generateIcon(size);
  fs.writeFileSync(`../public/icon${size}.png`, iconBuffer);
  console.log(`Generated icon${size}.png`);
}); 