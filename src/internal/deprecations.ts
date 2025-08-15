import { logger } from '../utils/logger';
// One-time deprecation logger utility (P1)

const emitted = new Set<string>();

export function warnDep(oldName: string, newUsage: string) {
  if (process.env.NODE_ENV === 'production') return;
  const key = `${oldName}->${newUsage}`;
  if (emitted.has(key)) return;
  emitted.add(key);
  // eslint-disable-next-line no-console
  logger.structuredWarn({ category: 'deprecation', action: oldName, message: `${oldName} deprecated. Use ${newUsage}`, replacement: newUsage });
}

export function resetDepWarnings() { emitted.clear(); }
