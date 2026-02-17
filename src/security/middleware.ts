/**
 * Security Middleware Integration
 * Unified security pipeline for Express/Fastify
 */

import { Request, Response, NextFunction } from 'express';
import { FastifyRequest, FastifyReply } from 'fastify';
import {
  distributedRateLimiter,
  ddosProtection,
  RateLimitResult,
} from './rate-limiter';
import {
  promptInjectionDetector,
  sqlInjectionPrevention,
  xssPrevention,
  csrfProtection,
  inputValidator,
  InjectionDetectionResult,
} from './injection-prevention';
import { databaseRLS } from './database-rls';
import { auditLogger } from './audit-logging';

export interface SecurityContext {
  tenantId: string;
  userId: string;
  sessionId: string;
  tier: 'standard' | 'enhanced' | 'dedicated';
  ipAddress: string;
  userAgent: string;
}

export interface SecurityMiddlewareConfig {
  enableRateLimiting: boolean;
  enableDDoSProtection: boolean;
  enablePromptInjection: boolean;
  enableSQLInjection: boolean;
  enableXSS: boolean;
  enableCSRF: boolean;
  enableInputValidation: boolean;
  enableAuditLogging: boolean;
}

/**
 * Extract security context from request
 */
export function extractSecurityContext(
  req: Request | FastifyRequest
): SecurityContext {
  // Extract from JWT token or session
  const token = req.headers.authorization?.replace('Bearer ', '');

  // TODO: Decode JWT and extract claims
  // const decoded = jwt.verify(token, JWT_SECRET);

  return {
    tenantId: (req as any).tenantId || 'unknown',
    userId: (req as any).userId || 'unknown',
    sessionId: (req as any).sessionId || 'unknown',
    tier: (req as any).tier || 'standard',
    ipAddress:
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req as any).ip ||
      'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
  };
}

/**
 * Master Security Middleware
 * Apply all security checks in order
 */
export function createSecurityMiddleware(
  config: SecurityMiddlewareConfig = {
    enableRateLimiting: true,
    enableDDoSProtection: true,
    enablePromptInjection: true,
    enableSQLInjection: true,
    enableXSS: true,
    enableCSRF: true,
    enableInputValidation: true,
    enableAuditLogging: true,
  }
) {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const context = extractSecurityContext(req);
      const startTime = Date.now();

      // 1. DDoS Protection (first line of defense)
      if (config.enableDDoSProtection) {
        const ipCheck = await ddosProtection.checkIP(context.ipAddress);
        if (!ipCheck.allowed) {
          await auditLogger.logSecurityEvent({
            tenantId: context.tenantId,
            userId: context.userId,
            eventType: 'DDOS_BLOCKED',
            severity: 'CRITICAL',
            details: {
              ip: context.ipAddress,
              reason: ipCheck.reason,
              blockUntil: ipCheck.blockUntil,
            },
            timestamp: new Date(),
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
          });

          res.status(429).json({
            error: 'Too Many Requests',
            message: 'Your IP has been temporarily blocked',
            reason: ipCheck.reason,
            retryAfter: ipCheck.blockUntil,
          });
          return;
        }

        // Track request
        await ddosProtection.trackIPRequest(context.ipAddress);
      }

      // 2. Rate Limiting
      if (config.enableRateLimiting) {
        const endpoint = req.path;
        const rateLimitResult = await distributedRateLimiter.checkTenantRateLimit(
          context.tenantId,
          context.tier,
          endpoint
        );

        // Set rate limit headers
        res.setHeader('X-RateLimit-Limit', rateLimitResult.remaining + 1);
        res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining);
        res.setHeader(
          'X-RateLimit-Reset',
          rateLimitResult.resetAt.toISOString()
        );

        if (!rateLimitResult.allowed) {
          await auditLogger.logSecurityEvent({
            tenantId: context.tenantId,
            userId: context.userId,
            eventType: 'RATE_LIMIT_EXCEEDED',
            severity: 'WARNING',
            details: {
              endpoint,
              tier: context.tier,
              retryAfter: rateLimitResult.retryAfterSeconds,
            },
            timestamp: new Date(),
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
          });

          res.status(429).json({
            error: 'Rate Limit Exceeded',
            message: `You have exceeded your ${context.tier} tier rate limit`,
            retryAfter: rateLimitResult.retryAfterSeconds,
            resetAt: rateLimitResult.resetAt,
          });
          return;
        }
      }

      // 3. CSRF Protection (for state-changing operations)
      if (
        config.enableCSRF &&
        ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)
      ) {
        const csrfToken = req.headers['x-csrf-token'] as string;
        if (!csrfToken || !csrfProtection.validateToken(csrfToken, context.sessionId)) {
          await auditLogger.logSecurityEvent({
            tenantId: context.tenantId,
            userId: context.userId,
            eventType: 'CSRF_TOKEN_INVALID',
            severity: 'HIGH',
            details: {
              method: req.method,
              path: req.path,
              hasToken: !!csrfToken,
            },
            timestamp: new Date(),
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
          });

          res.status(403).json({
            error: 'Forbidden',
            message: 'Invalid or missing CSRF token',
          });
          return;
        }
      }

      // 4. Input Validation (on request body)
      if (config.enableInputValidation && req.body) {
        // Define schemas per endpoint
        const schema = getEndpointSchema(req.path, req.method);
        if (schema) {
          const validation = inputValidator.validatePayload(req.body, schema);
          if (!validation.isValid) {
            await auditLogger.logSecurityEvent({
              tenantId: context.tenantId,
              userId: context.userId,
              eventType: 'INPUT_VALIDATION_FAILED',
              severity: 'MEDIUM',
              details: {
                errors: validation.errors,
                path: req.path,
              },
              timestamp: new Date(),
              ipAddress: context.ipAddress,
              userAgent: context.userAgent,
            });

            res.status(400).json({
              error: 'Validation Error',
              message: 'Request validation failed',
              errors: validation.errors,
            });
            return;
          }
        }
      }

      // 5. Prompt Injection Detection (for LLM endpoints)
      if (config.enablePromptInjection && isLLMEndpoint(req.path)) {
        const userInput = extractUserInput(req.body);
        if (userInput) {
          const injectionResult = promptInjectionDetector.detectInjection(
            userInput
          );

          if (!injectionResult.isSafe) {
            await auditLogger.logSecurityEvent({
              tenantId: context.tenantId,
              userId: context.userId,
              eventType: 'PROMPT_INJECTION_DETECTED',
              severity: 'CRITICAL',
              details: {
                threats: injectionResult.threats,
                confidence: injectionResult.confidence,
                input: userInput.substring(0, 200), // Log first 200 chars
              },
              timestamp: new Date(),
              ipAddress: context.ipAddress,
              userAgent: context.userAgent,
            });

            res.status(400).json({
              error: 'Security Violation',
              message: 'Potential prompt injection detected',
              details: injectionResult.threats,
            });
            return;
          }

          // Use sanitized input if needed
          if (injectionResult.sanitizedInput) {
            (req.body as any)._sanitizedInput =
              injectionResult.sanitizedInput;
          }
        }
      }

      // 6. SQL Injection Detection (for endpoints with database queries)
      if (config.enableSQLInjection) {
        const sqlInputs = extractPotentialSQLInputs(req.body, req.query);
        for (const input of sqlInputs) {
          const sqlResult = sqlInjectionPrevention.detectSQLInjection(input);
          if (!sqlResult.isSafe) {
            await auditLogger.logSecurityEvent({
              tenantId: context.tenantId,
              userId: context.userId,
              eventType: 'SQL_INJECTION_DETECTED',
              severity: 'CRITICAL',
              details: {
                threats: sqlResult.threats,
                input: input.substring(0, 200),
              },
              timestamp: new Date(),
              ipAddress: context.ipAddress,
              userAgent: context.userAgent,
            });

            res.status(400).json({
              error: 'Security Violation',
              message: 'Potential SQL injection detected',
            });
            return;
          }
        }
      }

      // 7. Set Tenant Context for Database RLS
      // This ensures all database queries are automatically filtered
      (req as any).dbContext = await databaseRLS.setTenantContext(
        context.tenantId,
        (req as any).db
      );

      // 8. Audit Logging
      if (config.enableAuditLogging) {
        await auditLogger.logSecurityEvent({
          tenantId: context.tenantId,
          userId: context.userId,
          eventType: 'API_REQUEST',
          severity: 'INFO',
          details: {
            method: req.method,
            path: req.path,
            tier: context.tier,
          },
          timestamp: new Date(),
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
        });
      }

      // Store context in request for downstream middleware
      (req as any).securityContext = context;

      // Continue to next middleware
      next();
    } catch (error) {
      console.error('[SECURITY_MIDDLEWARE] Error:', error);
      res.status(500).json({
        error: 'Internal Server Error',
        message: 'Security check failed',
      });
    }
  };
}

/**
 * XSS Protection Middleware (for responses)
 */
export function xssProtectionMiddleware() {
  return (req: Request, res: Response, next: NextFunction): void => {
    const originalJson = res.json.bind(res);

    res.json = function (body: any): Response {
      // Sanitize response body to prevent XSS
      const sanitized = sanitizeResponseBody(body);

      // Set security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; object-src 'none'"
      );

      return originalJson(sanitized);
    };

    next();
  };
}

/**
 * Concurrent Request Tracking Middleware
 */
export function concurrentRequestMiddleware() {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const context = extractSecurityContext(req);

    // Check concurrent request limit
    const concurrentCheck = await distributedRateLimiter.checkConcurrentRequests(
      context.tenantId,
      context.tier
    );

    if (!concurrentCheck.allowed) {
      res.status(429).json({
        error: 'Too Many Concurrent Requests',
        message: `Maximum ${concurrentCheck.max} concurrent requests allowed for ${context.tier} tier`,
        current: concurrentCheck.current,
      });
      return;
    }

    // Release slot when request completes
    res.on('finish', async () => {
      await distributedRateLimiter.releaseConcurrentSlot(context.tenantId);
    });

    next();
  };
}

/**
 * Helper: Check if endpoint is an LLM endpoint
 */
function isLLMEndpoint(path: string): boolean {
  return (
    path.includes('/chat') ||
    path.includes('/completion') ||
    path.includes('/agent') ||
    path.includes('/generate')
  );
}

/**
 * Helper: Extract user input from request body
 */
function extractUserInput(body: any): string | null {
  if (!body) return null;

  // Check common input fields
  return (
    body.prompt ||
    body.message ||
    body.input ||
    body.query ||
    body.text ||
    null
  );
}

/**
 * Helper: Extract potential SQL inputs
 */
function extractPotentialSQLInputs(
  body: any,
  query: any
): string[] {
  const inputs: string[] = [];

  // Extract from body
  if (body) {
    for (const value of Object.values(body)) {
      if (typeof value === 'string') {
        inputs.push(value);
      }
    }
  }

  // Extract from query params
  if (query) {
    for (const value of Object.values(query)) {
      if (typeof value === 'string') {
        inputs.push(value);
      }
    }
  }

  return inputs;
}

/**
 * Helper: Get validation schema for endpoint
 */
function getEndpointSchema(
  path: string,
  method: string
): Record<string, any> | null {
  // Define schemas for each endpoint
  const schemas: Record<string, Record<string, any>> = {
    'POST:/api/chat': {
      message: {
        required: true,
        type: 'string',
        minLength: 1,
        maxLength: 10000,
      },
      sessionId: {
        required: false,
        type: 'string',
        pattern: /^[a-zA-Z0-9-_]+$/,
      },
    },
    'POST:/api/agent/create': {
      name: {
        required: true,
        type: 'string',
        minLength: 1,
        maxLength: 100,
      },
      type: {
        required: true,
        type: 'string',
        enum: ['SIMPLE', 'CHAIN', 'GRAPH', 'SUPERVISOR'],
      },
    },
  };

  return schemas[`${method}:${path}`] || null;
}

/**
 * Helper: Sanitize response body
 */
function sanitizeResponseBody(body: any): any {
  if (typeof body === 'string') {
    return xssPrevention.sanitizeHTML(body);
  }

  if (Array.isArray(body)) {
    return body.map(sanitizeResponseBody);
  }

  if (typeof body === 'object' && body !== null) {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(body)) {
      sanitized[key] = sanitizeResponseBody(value);
    }
    return sanitized;
  }

  return body;
}

/**
 * Error Handling Middleware
 */
export function securityErrorHandler() {
  return async (
    error: any,
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const context = extractSecurityContext(req);

    // Log security error
    await auditLogger.logSecurityEvent({
      tenantId: context.tenantId,
      userId: context.userId,
      eventType: 'SECURITY_ERROR',
      severity: 'HIGH',
      details: {
        error: error.message,
        stack: error.stack,
        path: req.path,
      },
      timestamp: new Date(),
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
    });

    // Don't expose internal errors
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'An error occurred while processing your request',
    });
  };
}

/**
 * Export middleware factory
 */
export const securityMiddleware = {
  create: createSecurityMiddleware,
  xssProtection: xssProtectionMiddleware,
  concurrentRequests: concurrentRequestMiddleware,
  errorHandler: securityErrorHandler,
};
