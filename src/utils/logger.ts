/**
 * Lightweight logger utility to avoid circular dependencies.
 * Can be imported anywhere (including config initialization) safely.
 * Provides level-based logging with optional namespace filtering.
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LoggerOptions {
  namespace?: string;
  level?: LogLevel;
}

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function resolveLevel(): LogLevel {
  const env = (process.env.AUTHRIX_LOG_LEVEL || '').toLowerCase();
  if (env === 'debug' || env === 'info' || env === 'warn' || env === 'error') return env;
  return process.env.NODE_ENV === 'production' ? 'info' : 'debug';
}

export class AuthrixLogger {
  readonly namespace?: string;
  private level: LogLevel;

  constructor(opts: LoggerOptions = {}) {
    this.namespace = opts.namespace;
    this.level = opts.level || resolveLevel();
  }

  setLevel(level: LogLevel) { this.level = level; }
  getLevel(): LogLevel { return this.level; }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_ORDER[level] >= LEVEL_ORDER[this.level];
  }

  private fmt(args: any[]): any[] {
    const prefix = this.namespace ? `[AUTHRIX][${this.namespace}]` : '[AUTHRIX]';
    return [prefix, ...args];
  }

  debug(...args: any[]) { if (this.shouldLog('debug')) console.debug(...this.fmt(args)); }
  info(...args: any[])  { if (this.shouldLog('info'))  console.info(...this.fmt(args)); }
  warn(...args: any[])  { if (this.shouldLog('warn'))  console.warn(...this.fmt(args)); }
  error(...args: any[]) { if (this.shouldLog('error')) console.error(...this.fmt(args)); }
}

// Default shared logger instance
export const logger = new AuthrixLogger({ namespace: 'core' });

// Factory for feature-specific loggers
export function createLogger(namespace: string, level?: LogLevel) {
  return new AuthrixLogger({ namespace, level });
}

// Allow runtime level escalation (e.g., for debugging in production via env flip)
export function reconfigureLogger(level?: LogLevel) {
  if (level) logger.setLevel(level);
  else logger.setLevel(resolveLevel());
}

// Hot reload / test convenience: auto-adjust level when debug env set
if (process.env.AUTHRIX_DEBUG === 'true' && logger.getLevel() !== 'debug') {
  logger.setLevel('debug');
}
