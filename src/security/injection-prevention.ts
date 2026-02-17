/**
 * Injection Prevention
 * Prompt injection, SQL injection, XSS, and CSRF protection
 */

export interface InjectionDetectionResult {
  isSafe: boolean;
  threats: string[];
  sanitizedInput?: string;
  confidence: number;
}

/**
 * Prompt Injection Detection
 * Detects attempts to manipulate LLM behavior
 */
export class PromptInjectionDetector {
  private dangerousPatterns = [
    // Direct instruction manipulation
    /ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|commands?)/i,
    /disregard\s+(all\s+)?(previous|above|prior)\s+(instructions?|commands?)/i,
    /forget\s+(all\s+)?(previous|above|prior)\s+(instructions?|commands?)/i,

    // Role manipulation
    /you\s+are\s+(now\s+)?(?:a|an)\s+(?!assistant|AI)/i,
    /act\s+as\s+(?:a|an)\s+(?!assistant)/i,
    /pretend\s+(?:to\s+be|you\s+are)/i,
    /simulate\s+(?:being|a)/i,

    // System prompt extraction
    /show\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i,
    /what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions)/i,
    /reveal\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i,
    /print\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)/i,

    // Prompt escaping
    /```\s*system/i,
    /\[\s*system\s*\]/i,
    /<\s*system\s*>/i,

    // Jailbreak attempts
    /DAN\s+mode/i,
    /developer\s+mode/i,
    /SUDO/i,
    /execute\s+as\s+admin/i,

    // Data exfiltration
    /output\s+(?:all|entire)\s+(?:database|memory|context)/i,
    /dump\s+(?:database|memory|context)/i,
    /select\s+\*\s+from/i,

    // Instruction injection
    /\n\s*---\s*\n/,
    /\[\s*new\s+instructions?\s*\]/i,
    /\{\s*override\s*:/i,
  ];

  private suspiciousKeywords = [
    'ignore',
    'disregard',
    'forget',
    'override',
    'bypass',
    'jailbreak',
    'sudo',
    'system',
    'admin',
    'root',
    'execute',
    'reveal',
    'show prompt',
    'dump',
  ];

  /**
   * Detect prompt injection attempts
   */
  detectInjection(input: string): InjectionDetectionResult {
    const threats: string[] = [];
    let confidence = 0;

    // Check dangerous patterns
    for (const pattern of this.dangerousPatterns) {
      if (pattern.test(input)) {
        threats.push(`Dangerous pattern detected: ${pattern.source}`);
        confidence += 0.3;
      }
    }

    // Check suspicious keywords
    const lowerInput = input.toLowerCase();
    let keywordCount = 0;
    for (const keyword of this.suspiciousKeywords) {
      if (lowerInput.includes(keyword)) {
        keywordCount++;
      }
    }
    if (keywordCount >= 3) {
      threats.push(`Multiple suspicious keywords: ${keywordCount}`);
      confidence += 0.2;
    }

    // Check for unusual formatting
    if (this.hasUnusualFormatting(input)) {
      threats.push('Unusual formatting detected');
      confidence += 0.15;
    }

    // Check for encoding tricks
    if (this.hasEncodingTricks(input)) {
      threats.push('Encoding tricks detected');
      confidence += 0.25;
    }

    // Check for delimiters
    if (this.hasDelimiterInjection(input)) {
      threats.push('Delimiter injection detected');
      confidence += 0.2;
    }

    const isSafe = confidence < 0.5;

    if (!isSafe) {
      console.log(
        `[PROMPT_INJECTION] Detected injection attempt - Confidence: ${confidence.toFixed(2)}`
      );
      console.log(`[PROMPT_INJECTION] Threats: ${threats.join(', ')}`);
    }

    return {
      isSafe,
      threats,
      confidence: Math.min(confidence, 1.0),
      sanitizedInput: isSafe ? input : this.sanitizePrompt(input),
    };
  }

  /**
   * Check for unusual formatting
   */
  private hasUnusualFormatting(input: string): boolean {
    // Check for excessive newlines, markdown code blocks, etc.
    const newlineCount = (input.match(/\n/g) || []).length;
    const codeBlockCount = (input.match(/```/g) || []).length;

    return newlineCount > 10 || codeBlockCount > 2;
  }

  /**
   * Check for encoding tricks
   */
  private hasEncodingTricks(input: string): boolean {
    // Check for base64, hex encoding, unicode tricks
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/;
    const hexPattern = /(?:\\x[0-9a-f]{2}){5,}/i;
    const unicodePattern = /(?:\\u[0-9a-f]{4}){5,}/i;

    return (
      base64Pattern.test(input) ||
      hexPattern.test(input) ||
      unicodePattern.test(input)
    );
  }

  /**
   * Check for delimiter injection
   */
  private hasDelimiterInjection(input: string): boolean {
    const delimiters = ['---', '###', '===', '|||', '<<<', '>>>'];
    return delimiters.some((d) => input.includes(d));
  }

  /**
   * Sanitize prompt by removing dangerous content
   */
  private sanitizePrompt(input: string): string {
    let sanitized = input;

    // Remove dangerous patterns
    for (const pattern of this.dangerousPatterns) {
      sanitized = sanitized.replace(pattern, '[REDACTED]');
    }

    // Remove code blocks
    sanitized = sanitized.replace(/```[\s\S]*?```/g, '[CODE_BLOCK_REMOVED]');

    // Limit length
    if (sanitized.length > 5000) {
      sanitized = sanitized.substring(0, 5000) + '...[TRUNCATED]';
    }

    return sanitized;
  }
}

/**
 * SQL Injection Prevention
 */
export class SQLInjectionPrevention {
  private sqlPatterns = [
    /('|")(\s|\S)*(\bOR\b|\bAND\b)(\s|\S)*('|")/i,
    /\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b/i,
    /--/,
    /\/\*/,
    /;\s*(drop|delete|truncate)/i,
    /\bxp_cmdshell\b/i,
  ];

  /**
   * Detect SQL injection attempts
   */
  detectSQLInjection(input: string): InjectionDetectionResult {
    const threats: string[] = [];
    let confidence = 0;

    for (const pattern of this.sqlPatterns) {
      if (pattern.test(input)) {
        threats.push(`SQL pattern detected: ${pattern.source}`);
        confidence += 0.4;
      }
    }

    const isSafe = confidence < 0.4;

    if (!isSafe) {
      console.log(
        `[SQL_INJECTION] Detected SQL injection attempt - Confidence: ${confidence.toFixed(2)}`
      );
    }

    return {
      isSafe,
      threats,
      confidence: Math.min(confidence, 1.0),
      sanitizedInput: isSafe ? input : this.sanitizeSQL(input),
    };
  }

  /**
   * Sanitize SQL input
   */
  private sanitizeSQL(input: string): string {
    // Always use parameterized queries instead of string concatenation
    return input
      .replace(/['"]/g, '')
      .replace(/;/g, '')
      .replace(/--/g, '')
      .replace(/\/\*/g, '')
      .replace(/\*\//g, '');
  }

  /**
   * Generate parameterized query
   */
  createParameterizedQuery(
    query: string,
    params: Record<string, any>
  ): { sql: string; values: any[] } {
    // Convert named parameters to positional
    const values: any[] = [];
    let paramIndex = 1;

    const sql = query.replace(/:(\w+)/g, (match, paramName) => {
      if (paramName in params) {
        values.push(params[paramName]);
        return `$${paramIndex++}`;
      }
      return match;
    });

    return { sql, values };
  }
}

/**
 * XSS Prevention
 */
export class XSSPrevention {
  private xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>.*?<\/iframe>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi, // onclick, onload, etc.
    /<embed[^>]*>/gi,
    /<object[^>]*>/gi,
  ];

  /**
   * Detect XSS attempts
   */
  detectXSS(input: string): InjectionDetectionResult {
    const threats: string[] = [];
    let confidence = 0;

    for (const pattern of this.xssPatterns) {
      if (pattern.test(input)) {
        threats.push(`XSS pattern detected: ${pattern.source}`);
        confidence += 0.4;
      }
    }

    const isSafe = confidence < 0.4;

    if (!isSafe) {
      console.log(
        `[XSS_PREVENTION] Detected XSS attempt - Confidence: ${confidence.toFixed(2)}`
      );
    }

    return {
      isSafe,
      threats,
      confidence: Math.min(confidence, 1.0),
      sanitizedInput: isSafe ? input : this.sanitizeHTML(input),
    };
  }

  /**
   * Sanitize HTML to prevent XSS
   */
  sanitizeHTML(input: string): string {
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Sanitize URL
   */
  sanitizeURL(url: string): string {
    // Only allow http/https protocols
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return '';
      }
      return parsed.toString();
    } catch {
      return '';
    }
  }
}

/**
 * CSRF Protection
 */
export class CSRFProtection {
  /**
   * Generate CSRF token
   */
  generateToken(sessionId: string): string {
    const timestamp = Date.now().toString();
    const randomBytes = Math.random().toString(36).substring(2);
    const token = `${sessionId}:${timestamp}:${randomBytes}`;

    // TODO: Use crypto.createHmac for production
    // const hmac = crypto.createHmac('sha256', SECRET_KEY);
    // hmac.update(token);
    // return hmac.digest('hex');

    return Buffer.from(token).toString('base64');
  }

  /**
   * Validate CSRF token
   */
  validateToken(token: string, sessionId: string): boolean {
    try {
      const decoded = Buffer.from(token, 'base64').toString('utf-8');
      const [tokenSessionId, timestamp, randomBytes] = decoded.split(':');

      // Check session ID matches
      if (tokenSessionId !== sessionId) {
        return false;
      }

      // Check token age (15 minutes)
      const tokenAge = Date.now() - parseInt(timestamp);
      if (tokenAge > 15 * 60 * 1000) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Input Validation
 */
export class InputValidator {
  /**
   * Validate request payload
   */
  validatePayload(
    payload: any,
    schema: Record<string, any>
  ): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (const [key, rules] of Object.entries(schema)) {
      const value = payload[key];

      // Check required
      if (rules.required && value === undefined) {
        errors.push(`${key} is required`);
        continue;
      }

      if (value === undefined) continue;

      // Check type
      if (rules.type && typeof value !== rules.type) {
        errors.push(`${key} must be of type ${rules.type}`);
      }

      // Check string length
      if (rules.minLength && value.length < rules.minLength) {
        errors.push(`${key} must be at least ${rules.minLength} characters`);
      }
      if (rules.maxLength && value.length > rules.maxLength) {
        errors.push(`${key} must be at most ${rules.maxLength} characters`);
      }

      // Check number range
      if (rules.min !== undefined && value < rules.min) {
        errors.push(`${key} must be at least ${rules.min}`);
      }
      if (rules.max !== undefined && value > rules.max) {
        errors.push(`${key} must be at most ${rules.max}`);
      }

      // Check pattern
      if (rules.pattern && !rules.pattern.test(value)) {
        errors.push(`${key} format is invalid`);
      }

      // Check enum
      if (rules.enum && !rules.enum.includes(value)) {
        errors.push(`${key} must be one of: ${rules.enum.join(', ')}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}

/**
 * Export singleton instances
 */
export const promptInjectionDetector = new PromptInjectionDetector();
export const sqlInjectionPrevention = new SQLInjectionPrevention();
export const xssPrevention = new XSSPrevention();
export const csrfProtection = new CSRFProtection();
export const inputValidator = new InputValidator();
