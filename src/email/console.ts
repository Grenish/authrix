import { EmailService } from "../core/twoFactor";

/**
 * Console Email Service (for development/testing)
 * Logs emails to console instead of sending them
 * 
 * Features:
 * - No external dependencies
 * - Perfect for development and testing
 * - Simulates email sending with delays
 * - Colorful console output for better visibility
 * - Email content preview
 */
export class ConsoleEmailService implements EmailService {
  private readonly colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    dim: '\x1b[2m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    bgBlue: '\x1b[44m',
    bgGreen: '\x1b[42m'
  };

  private readonly enableColors: boolean;

  constructor(options: {
    enableColors?: boolean;
    simulateDelay?: boolean;
  } = {}) {
    this.enableColors = options.enableColors !== false;
  }

  async sendVerificationEmail(
    to: string,
    code: string,
    options: {
      subject?: string;
      template?: string;
      metadata?: any;
    } = {}
  ): Promise<void> {
    const {
      subject = 'Email Verification Code',
      template,
      metadata = {}
    } = options;

    const timestamp = new Date().toLocaleString();
    const emailId = this.generateEmailId();

    // Create colorized output if colors are enabled
    const c = this.enableColors ? this.colors : this.createNoColorObject();

    console.log(`\n${c.bgBlue}${c.white}${c.bright} 📧 EMAIL SERVICE (CONSOLE MODE) ${c.reset}`);
    console.log(`${c.cyan}${'='.repeat(50)}${c.reset}`);
    console.log(`${c.bright}Email ID:${c.reset} ${c.dim}${emailId}${c.reset}`);
    console.log(`${c.bright}Timestamp:${c.reset} ${c.dim}${timestamp}${c.reset}`);
    console.log(`${c.bright}To:${c.reset} ${c.green}${to}${c.reset}`);
    console.log(`${c.bright}Subject:${c.reset} ${c.yellow}${subject}${c.reset}`);
    console.log(`${c.bright}Verification Code:${c.reset} ${c.bgGreen}${c.white}${c.bright} ${code} ${c.reset}`);
    
    if (Object.keys(metadata).length > 0) {
      console.log(`${c.bright}Metadata:${c.reset}`);
      console.log(this.formatMetadata(metadata, c));
    }

    // Show email content preview if template is provided
    if (template) {
      console.log(`${c.bright}Email Content Preview:${c.reset}`);
      console.log(`${c.dim}${this.getTextPreview(template, code)}${c.reset}`);
    } else {
      console.log(`${c.bright}Email Content:${c.reset} ${c.dim}Default template used${c.reset}`);
    }

    console.log(`${c.cyan}${'='.repeat(50)}${c.reset}\n`);

    // Simulate email sending delay (realistic timing)
    const delay = Math.random() * 200 + 100; // 100-300ms
    await new Promise(resolve => setTimeout(resolve, delay));

    // Log success message
    console.log(`${c.green}✅ Email sent successfully to ${to}${c.reset}`);
  }

  /**
   * Generate a unique email ID for tracking
   */
  private generateEmailId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `console-${timestamp}-${random}`;
  }

  /**
   * Format metadata for console display
   */
  private formatMetadata(metadata: any, colors: any): string {
    const formatted = Object.entries(metadata)
      .map(([key, value]) => {
        const formattedValue = typeof value === 'object' 
          ? JSON.stringify(value, null, 2).replace(/\n/g, '\n    ')
          : String(value);
        return `  ${colors.blue}${key}:${colors.reset} ${colors.dim}${formattedValue}${colors.reset}`;
      })
      .join('\n');
    
    return formatted;
  }

  /**
   * Extract text preview from HTML template
   */
  private getTextPreview(template: string, code: string): string {
    // Simple HTML to text conversion
    const textContent = template
      .replace(/<[^>]*>/g, '') // Remove HTML tags
      .replace(/\s+/g, ' ') // Normalize whitespace
      .trim();
    
    // Truncate if too long
    const maxLength = 200;
    if (textContent.length > maxLength) {
      return textContent.substring(0, maxLength) + '...';
    }
    
    return textContent;
  }

  /**
   * Create object with empty color codes when colors are disabled
   */
  private createNoColorObject(): Record<string, string> {
    const noColor: Record<string, string> = {};
    Object.keys(this.colors).forEach(key => {
      noColor[key] = '';
    });
    return noColor;
  }

  /**
   * Test the console email service
   */
  static async test(): Promise<void> {
    const service = new ConsoleEmailService();
    
    console.log('Testing Console Email Service...\n');
    
    await service.sendVerificationEmail(
      'test@example.com',
      '123456',
      {
        subject: 'Test Email - Console Service',
        metadata: {
          appName: 'Authrix Test',
          purpose: 'service_test',
          timestamp: new Date().toISOString(),
          userAgent: 'Test Runner',
          ipAddress: '127.0.0.1'
        }
      }
    );
  }
}

// Export default instance
export const consoleEmailService = new ConsoleEmailService();

// Export factory function
export function createConsoleEmailService(options?: {
  enableColors?: boolean;
  simulateDelay?: boolean;
}): ConsoleEmailService {
  return new ConsoleEmailService(options);
}