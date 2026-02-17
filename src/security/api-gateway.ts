/**
 * Zero-Trust API Gateway
 * Entry point for all API requests with security enforcement
 * Implements defense-in-depth with multiple security layers
 */

import { TenantContext, tenantIsolationManager } from './tenant-isolation';

export interface RateLimitConfig {
  requestsPerMinute: number;
  requestsPerHour: number;
  requestsPerDay: number;
  burstSize: number;
}

export interface SecurityConfig {
  enableMTLS: boolean;
  enableCSRF: boolean;
  enableCORS: boolean;
  allowedOrigins: string[];
  maxRequestSize: number; // bytes
  requestTimeout: number; // milliseconds
}

export class ZeroTrustAPIGateway {
  private rateLimiters = new Map<string, RateLimiter>();
  private circuitBreakers = new Map<string, CircuitBreaker>();
  private requestMetrics = new Map<string, RequestMetrics>();

  constructor(private securityConfig: SecurityConfig) {}

  /**
   * Main request handler - validates and routes all requests
   */
  async handleRequest(request: any): Promise<any> {
    const startTime = Date.now();

    try {
      // Step 1: Extract tenant context from JWT
      const tenantContext = await this.extractAndValidateTenant(request);

      // Step 2: Rate limiting (prevent abuse)
      await this.enforceRateLimit(tenantContext.tenantId, request);

      // Step 3: Sanitize request (prevent injection attacks)
      const sanitizedRequest = this.sanitizeRequest(request);

      // Step 4: Validate request size
      this.validateRequestSize(sanitizedRequest);

      // Step 5: Check circuit breaker
      this.checkCircuitBreaker(tenantContext.tenantId);

      // Step 6: Add security headers
      const headers = this.addSecurityHeaders();

      // Step 7: Verify resource ownership
      if (sanitizedRequest.resourceId) {
        tenantIsolationManager.validateTenantAccess(
          tenantContext.tenantId,
          sanitizedRequest.resourceId,
          sanitizedRequest.method
        );
      }

      // Step 8: Record metrics
      this.recordMetrics(tenantContext.tenantId, 'SUCCESS', Date.now() - startTime);

      // Return sanitized request with context
      return {
        tenantContext,
        request: sanitizedRequest,
        headers,
      };
    } catch (error) {
      // Record failure metrics
      const tenantId = this.extractTenantIdSafe(request);
      this.recordMetrics(tenantId || 'UNKNOWN', 'FAILURE', Date.now() - startTime);

      // Trip circuit breaker if too many failures
      if (tenantId) {
        this.recordFailure(tenantId);
      }

      throw error;
    }
  }

  /**
   * Extract and validate tenant from JWT token
   */
  private async extractAndValidateTenant(request: any): Promise<TenantContext> {
    const authHeader = request.headers?.['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new Error('Unauthorized: Missing authorization header');
    }

    const token = authHeader.replace('Bearer ', '');

    // Validate JWT signature and claims
    const claims = await this.validateJWT(token);

    // Extract tenant ID from claims
    const tenantId = claims.tenant_id || claims.tid;
    if (!tenantId) {
      throw new Error('Unauthorized: Missing tenant ID in token');
    }

    // Get tenant context
    const tenantContext = tenantIsolationManager.getTenantContext(tenantId);
    if (!tenantContext) {
      throw new Error('Unauthorized: Tenant not found');
    }

    // Validate token expiration
    if (claims.exp && claims.exp < Date.now() / 1000) {
      throw new Error('Unauthorized: Token expired');
    }

    // Validate token issuer
    if (claims.iss !== 'openclaw-auth-service') {
      throw new Error('Unauthorized: Invalid token issuer');
    }

    return tenantContext;
  }

  /**
   * Validate JWT token (verify signature, expiration, claims)
   */
  private async validateJWT(token: string): Promise<any> {
    // TODO: Implement actual JWT validation
    // Use jsonwebtoken library with public key
    // Verify:
    // - Signature (RSA/ECDSA)
    // - Expiration (exp claim)
    // - Not Before (nbf claim)
    // - Issuer (iss claim)
    // - Audience (aud claim)

    // Placeholder implementation
    return {
      tenant_id: 'tenant-123',
      user_id: 'user-456',
      exp: Date.now() / 1000 + 3600,
      iss: 'openclaw-auth-service',
    };
  }

  /**
   * Rate limiting - prevent abuse and enforce quotas
   */
  private async enforceRateLimit(
    tenantId: string,
    request: any
  ): Promise<void> {
    let rateLimiter = this.rateLimiters.get(tenantId);

    if (!rateLimiter) {
      // Get tenant-specific rate limits from context
      const tenantContext = tenantIsolationManager.getTenantContext(tenantId);
      const config = this.getRateLimitConfig(tenantContext!);
      rateLimiter = new RateLimiter(config);
      this.rateLimiters.set(tenantId, rateLimiter);
    }

    const allowed = rateLimiter.allowRequest();

    if (!allowed) {
      throw new Error('Rate limit exceeded. Please try again later.');
    }
  }

  /**
   * Get rate limit configuration based on tenant tier
   */
  private getRateLimitConfig(tenantContext: TenantContext): RateLimitConfig {
    // Different limits based on isolation level (pricing tier)
    switch (tenantContext.isolationLevel) {
      case 'standard':
        return {
          requestsPerMinute: 100,
          requestsPerHour: 5000,
          requestsPerDay: 100000,
          burstSize: 20,
        };
      case 'enhanced':
        return {
          requestsPerMinute: 500,
          requestsPerHour: 25000,
          requestsPerDay: 500000,
          burstSize: 100,
        };
      case 'dedicated':
        return {
          requestsPerMinute: 2000,
          requestsPerHour: 100000,
          requestsPerDay: 2000000,
          burstSize: 500,
        };
      default:
        return {
          requestsPerMinute: 60,
          requestsPerHour: 1000,
          requestsPerDay: 10000,
          burstSize: 10,
        };
    }
  }

  /**
   * Sanitize request to prevent injection attacks
   */
  private sanitizeRequest(request: any): any {
    const sanitized = { ...request };

    // Sanitize query parameters
    if (sanitized.query) {
      sanitized.query = this.sanitizeObject(sanitized.query);
    }

    // Sanitize body
    if (sanitized.body) {
      sanitized.body = this.sanitizeObject(sanitized.body);
    }

    // Sanitize headers (remove dangerous headers)
    if (sanitized.headers) {
      delete sanitized.headers['x-forwarded-host'];
      delete sanitized.headers['x-original-url'];
    }

    return sanitized;
  }

  /**
   * Recursively sanitize object properties
   */
  private sanitizeObject(obj: any): any {
    if (typeof obj === 'string') {
      return this.sanitizeString(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.sanitizeObject(item));
    }

    if (typeof obj === 'object' && obj !== null) {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = this.sanitizeObject(value);
      }
      return sanitized;
    }

    return obj;
  }

  /**
   * Sanitize string input (prevent XSS, SQL injection, NoSQL injection)
   */
  private sanitizeString(input: string): string {
    let sanitized = input;

    // Remove SQL injection patterns
    const sqlPatterns = [
      /('|(\-\-)|(;)|(\|\|)|(\*))/gi,
      /(\bOR\b|\bAND\b).*?=/gi,
      /\bUNION\b.*?\bSELECT\b/gi,
      /\bDROP\b.*?\bTABLE\b/gi,
    ];

    // Remove NoSQL injection patterns
    const nosqlPatterns = [
      /\$where/gi,
      /\$ne/gi,
      /\$gt/gi,
      /\$regex/gi,
    ];

    // Remove XSS patterns
    const xssPatterns = [
      /<script[^>]*>.*?<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
    ];

    // Apply all sanitization patterns
    [...sqlPatterns, ...nosqlPatterns, ...xssPatterns].forEach((pattern) => {
      sanitized = sanitized.replace(pattern, '');
    });

    return sanitized;
  }

  /**
   * Validate request size (prevent memory exhaustion)
   */
  private validateRequestSize(request: any): void {
    const size = JSON.stringify(request).length;

    if (size > this.securityConfig.maxRequestSize) {
      throw new Error(
        `Request too large: ${size} bytes (max: ${this.securityConfig.maxRequestSize} bytes)`
      );
    }
  }

  /**
   * Check circuit breaker status
   */
  private checkCircuitBreaker(tenantId: string): void {
    const circuitBreaker = this.circuitBreakers.get(tenantId);

    if (circuitBreaker && circuitBreaker.isOpen()) {
      throw new Error('Service temporarily unavailable. Please try again later.');
    }
  }

  /**
   * Record failure for circuit breaker
   */
  private recordFailure(tenantId: string): void {
    let circuitBreaker = this.circuitBreakers.get(tenantId);

    if (!circuitBreaker) {
      circuitBreaker = new CircuitBreaker();
      this.circuitBreakers.set(tenantId, circuitBreaker);
    }

    circuitBreaker.recordFailure();
  }

  /**
   * Add security headers to response
   */
  private addSecurityHeaders(): Record<string, string> {
    return {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; object-src 'none'",
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    };
  }

  /**
   * Record request metrics
   */
  private recordMetrics(
    tenantId: string,
    status: 'SUCCESS' | 'FAILURE',
    latencyMs: number
  ): void {
    let metrics = this.requestMetrics.get(tenantId);

    if (!metrics) {
      metrics = {
        successCount: 0,
        failureCount: 0,
        totalLatencyMs: 0,
        lastRequestTime: new Date(),
      };
      this.requestMetrics.set(tenantId, metrics);
    }

    if (status === 'SUCCESS') {
      metrics.successCount++;
    } else {
      metrics.failureCount++;
    }

    metrics.totalLatencyMs += latencyMs;
    metrics.lastRequestTime = new Date();
  }

  /**
   * Safely extract tenant ID (for error handling)
   */
  private extractTenantIdSafe(request: any): string | null {
    try {
      const authHeader = request.headers?.['authorization'];
      if (!authHeader) return null;

      const token = authHeader.replace('Bearer ', '');
      // Basic decode without validation (for error logging only)
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
      return payload.tenant_id || payload.tid || null;
    } catch {
      return null;
    }
  }
}

/**
 * Rate limiter using token bucket algorithm
 */
class RateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(private config: RateLimitConfig) {
    this.tokens = config.burstSize;
    this.lastRefill = Date.now();
  }

  allowRequest(): boolean {
    this.refillTokens();

    if (this.tokens >= 1) {
      this.tokens--;
      return true;
    }

    return false;
  }

  private refillTokens(): void {
    const now = Date.now();
    const timePassed = (now - this.lastRefill) / 1000; // seconds
    const tokensToAdd = timePassed * (this.config.requestsPerMinute / 60);

    this.tokens = Math.min(
      this.tokens + tokensToAdd,
      this.config.burstSize
    );
    this.lastRefill = now;
  }
}

/**
 * Circuit breaker to prevent cascading failures
 */
class CircuitBreaker {
  private failures = 0;
  private lastFailureTime = 0;
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  private readonly failureThreshold = 5;
  private readonly timeout = 60000; // 60 seconds

  recordFailure(): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.failureThreshold) {
      this.state = 'OPEN';
    }
  }

  isOpen(): boolean {
    // Check if timeout has passed and circuit should attempt half-open
    if (
      this.state === 'OPEN' &&
      Date.now() - this.lastFailureTime > this.timeout
    ) {
      this.state = 'HALF_OPEN';
      this.failures = 0;
      return false;
    }

    return this.state === 'OPEN';
  }
}

interface RequestMetrics {
  successCount: number;
  failureCount: number;
  totalLatencyMs: number;
  lastRequestTime: Date;
}

/**
 * Export singleton instance
 */
export const apiGateway = new ZeroTrustAPIGateway({
  enableMTLS: true,
  enableCSRF: true,
  enableCORS: true,
  allowedOrigins: ['https://app.openclaw.ai'],
  maxRequestSize: 10 * 1024 * 1024, // 10 MB
  requestTimeout: 30000, // 30 seconds
});
