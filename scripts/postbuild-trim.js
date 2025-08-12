// Post-build pruning to reduce package size
// Removes duplicate .d.cts/.d.mts files when matching .d.ts exists
import { readdirSync, statSync, unlinkSync } from 'fs';
import { join } from 'path';

const distDir = join(process.cwd(), 'dist');

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full);
    else if (/\.d\.cts$/.test(entry)) {
      const tsVariant = full.replace(/\.d\.cts$/, '.d.ts');
      try {
        // If the standard .d.ts exists and sizes are similar, remove the .d.cts variant
        const tsStat = statSync(tsVariant);
        if (Math.abs(tsStat.size - st.size) < 32) {
          unlinkSync(full);
        }
      } catch { /* ignore */ }
    }
  }
}

try {
  walk(distDir);
  // eslint-disable-next-line no-console
  console.log('[postbuild-trim] Pruned duplicate declaration variants');
} catch (e) {
  console.warn('[postbuild-trim] Failed:', e?.message);
}
