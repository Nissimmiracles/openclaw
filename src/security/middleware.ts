/**
 * Security Middleware Integration
 * Unified security pipeline for Express/Fastify
 * Ties together all security modules
 */

import { Request, Response, NextFunction } from 'express';
import { tenantIsolationManager } from './tenant-isolation';
import { apiGateway } from './api-gateway';
import { iamManager } from './iam';
import { distributedRateLimiter, ddosProtection } from './rate-limiter';
import {
  promptInjectionDetector,
  sqlInjectionPrevention,
  xssPrevention,
  csrfProtection,
  inputValidator,
} from './injection-prevention';
import { databaseRLS } from './database-rls';

/**
 * Security Context attached to request
 */
export interface SecurityContext {
  tenantId: string;
  userId: string;
  sessionId: string;
  ipAddress: string;
  userAgent: string;
  roles: string[];
  permissions: string[];
  requestId: string;
  timestamp: Date;
}

/**
 * Extended Request with security context
 */
export interface SecureRequest extends Request {
  security: SecurityContext;
  dbConnection?: any;
}

/**
 * Security Middleware Manager
 */
export class SecurityMiddleware {
  /**
   * Phase 1: Pre-Request Security Checks
   * Must run before any business logic
   */
  async preRequestSecurity(
    req: SecureRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      const requestId = this.generateRequestId();
      const startTime = Date.now();

      console.log(
        `[SECURITY] ${requestId} - Starting security pipeline for ${req.method} ${req.path}`
      );

      // Step 1: DDoS Protection - Check IP
      const ipCheck = await ddosProtection.checkIP(
        this.getClientIP(req)
      );
      if (!ipCheck.allowed) {
        return this.sendSecurityError(res, 429, 'IP_BLOCKED', {
          reason: ipCheck.reason,
          blockUntil: ipCheck.blockUntil,
        });
      }

      // Track IP request
      await ddosProtection.trackIPRequest(this.getClientIP(req));

      // Step 2: JWT Validation & Tenant Extraction
      let tenantContext;
      try {
        const gatewayResult = await apiGateway.handleRequest(req);
        tenantContext = gatewayResult.tenantContext;

        // Add security headers to response
        Object.entries(gatewayResult.headers).forEach(([key, value]) => {
          res.setHeader(key, value);
        });
      } catch (error: any) {
        return this.sendSecurityError(res, 401, 'UNAUTHORIZED', {
          message: error.message,
        });
      }

      // Step 3: Rate Limiting
      const rateLimitResult = await distributedRateLimiter.checkTenantRateLimit(
        tenantContext.tenantId,
        tenantContext.isolationLevel,
        req.path
      );

      // Add rate limit headers
      res.setHeader('X-RateLimit-Limit', rateLimitResult.remaining);
      res.setHeader(
        'X-RateLimit-Reset',
        rateLimitResult.resetAt.toISOString()
      );

      if (!rateLimitResult.allowed) {
        return this.sendSecurityError(res, 429, 'RATE_LIMIT_EXCEEDED', {
          retryAfter: rateLimitResult.retryAfterSeconds,
          resetAt: rateLimitResult.resetAt,
        });
      }

      // Step 4: Check Concurrent Requests
      const concurrentCheck = await distributedRateLimiter.checkConcurrentRequests(
        tenantContext.tenantId,
        tenantContext.isolationLevel
      );

      if (!concurrentCheck.allowed) {
        return this.sendSecurityError(res, 429, 'TOO_MANY_CONCURRENT_REQUESTS', {
          current: concurrentCheck.current,
          max: concurrentCheck.max,
        });
      }

      // Step 5: Build Security Context
      const securityContext: SecurityContext = {
        tenantId: tenantContext.tenantId,
        userId: req.headers['x-user-id'] as string,
        sessionId: req.headers['x-session-id'] as string || this.generateSessionId(),
        ipAddress: this.getClientIP(req),
        userAgent: req.headers['user-agent'] || '',
        roles: [], // Will be populated from IAM
        permissions: [],
        requestId,
        timestamp: new Date(),
      };

      // Get user and roles from IAM
      if (securityContext.userId) {
        const user = iamManager.getUser(securityContext.userId);
        if (user) {
          securityContext.roles = user.roles as string[];
        }
      }

      // Attach security context to request
      req.security = securityContext;

      // Step 6: Set Database Tenant Context (RLS)
      if (req.dbConnection) {
        await databaseRLS.setTenantContext(
          tenantContext.tenantId,
          req.dbConnection
        );
      }

      // Log security event
      console.log(
        `[SECURITY] ${requestId} - Pre-request checks passed (${Date.now() - startTime}ms)`
      );

      next();
    } catch (error: any) {
      console.error('[SECURITY] Pre-request security error:', error);
      return this.sendSecurityError(res, 500, 'SECURITY_ERROR', {
        message: error.message,
      });
    }
  }

  /**
   * Phase 2: Request Validation
   * Validates request body, query params, and headers
   */
  async validateRequest(
    schema: Record<string, any>
  ): Promise<(req: SecureRequest, res: Response, next: NextFunction) => void> {
    return async (req: SecureRequest, res: Response, next: NextFunction) => {
      try {
        // Validate request body against schema
        const validation = inputValidator.validatePayload(req.body, schema);

        if (!validation.isValid) {
          return this.sendSecurityError(res, 400, 'VALIDATION_ERROR', {
            errors: validation.errors,
          });
        }

        next();
      } catch (error: any) {
        return this.sendSecurityError(res, 400, 'VALIDATION_ERROR', {
          message: error.message,
        });
      }
    };
  }

  /**
   * Phase 3: CSRF Protection
   * Validates CSRF token on state-changing requests
   */
  async csrfProtection(
    req: SecureRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    // Only check CSRF on mutating requests
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
      const token = req.headers['x-csrf-token'] as string;

      if (!token) {
        return this.sendSecurityError(res, 403, 'CSRF_TOKEN_MISSING');
      }

      const isValid = csrfProtection.validateToken(
        token,
        req.security.sessionId
      );

      if (!isValid) {
        return this.sendSecurityError(res, 403, 'CSRF_TOKEN_INVALID');
      }
    }

    next();
  }

  /**
   * Phase 4: Injection Detection
   * Scans all text inputs for injection attempts
   */
  async injectionDetection(
    req: SecureRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    try {
      // Check all string fields in body
      const textInputs = this.extractTextInputs(req.body);

      for (const input of textInputs) {
        // Prompt injection detection
        const promptCheck = promptInjectionDetector.detectInjection(input);
        if (!promptCheck.isSafe) {
          console.warn(
            `[SECURITY] Prompt injection detected: ${promptCheck.threats.join(', ')}`
          );
          return this.sendSecurityError(res, 400, 'PROMPT_INJECTION_DETECTED', {
            threats: promptCheck.threats,
            confidence: promptCheck.confidence,
          });
        }

        // SQL injection detection
        const sqlCheck = sqlInjectionPrevention.detectSQLInjection(input);
        if (!sqlCheck.isSafe) {
          console.warn(
            `[SECURITY] SQL injection detected: ${sqlCheck.threats.join(', ')}`
          );
          return this.sendSecurityError(res, 400, 'SQL_INJECTION_DETECTED', {
            threats: sqlCheck.threats,
          });
        }

        // XSS detection
        const xssCheck = xssPrevention.detectXSS(input);
        if (!xssCheck.isSafe) {
          console.warn(
            `[SECURITY] XSS detected: ${xssCheck.threats.join(', ')}`
          );
          return this.sendSecurityError(res, 400, 'XSS_DETECTED', {
            threats: xssCheck.threats,
          });
        }
      }

      next();
    } catch (error: any) {
      console.error('[SECURITY] Injection detection error:', error);
      next(); // Don't block request on detection error
    }
  }

  /**
   * Phase 5: Permission Check
   * Verifies user has required permissions
   */
  requirePermission(
    resource: string,
    action: string
  ): (req: SecureRequest, res: Response, next: NextFunction) => Promise<void> {
    return async (req: SecureRequest, res: Response, next: NextFunction) => {
      try {
        const hasPermission = await iamManager.checkPermission(
          req.security.userId,
          resource,
          action,
          {
            tenantId: req.security.tenantId,
            ipAddress: req.security.ipAddress,
          }
        );

        if (!hasPermission) {
          return this.sendSecurityError(res, 403, 'INSUFFICIENT_PERMISSIONS', {
            required: { resource, action },
          });
        }

        next();
      } catch (error: any) {
        return this.sendSecurityError(res, 403, 'PERMISSION_CHECK_FAILED', {
          message: error.message,
        });
      }
    };
  }

  /**
   * Phase 6: Post-Request Audit
   * Logs request completion for compliance
   */
  async postRequestAudit(
    req: SecureRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    // Hook into response finish event
    const originalSend = res.send;
    const self = this;

    res.send = function (data: any) {
      // Log audit event
      self.logAuditEvent(req, res, data);

      // Release concurrent request slot
      distributedRateLimiter.releaseConcurrentSlot(req.security.tenantId);

      return originalSend.call(this, data);
    };

    next();
  }

  /**
   * Error Handler with Security Context
   */
  errorHandler(
    err: any,
    req: SecureRequest,
    res: Response,
    next: NextFunction
  ): void {
    console.error(
      `[SECURITY] Error in request ${req.security?.requestId}:`,
      err
    );

    // Log security-related errors
    if (req.security) {
      this.logSecurityError(req, err);
    }

    // Don't expose internal errors
    const statusCode = err.statusCode || 500;
    const message =
      statusCode === 500 ? 'Internal server error' : err.message;

    res.status(statusCode).json({
      error: {
        code: err.code || 'INTERNAL_ERROR',
        message,
        requestId: req.security?.requestId,
      },
    });
  }

  /**
   * Helper: Generate Request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Helper: Generate Session ID
   */
  private generateSessionId(): string {
    return `sess_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  }

  /**
   * Helper: Get Client IP
   */
  private getClientIP(req: Request): string {
    return (
      (req.headers['x-forwarded-for'] as string)?.split(',')[0] ||
      (req.headers['x-real-ip'] as string) ||
      req.socket.remoteAddress ||
      'unknown'
    );
  }

  /**
   * Helper: Extract text inputs from object
   */
  private extractTextInputs(obj: any, maxDepth = 3): string[] {
    const inputs: string[] = [];

    const extract = (value: any, depth: number) => {
      if (depth > maxDepth) return;

      if (typeof value === 'string' && value.length > 0) {
        inputs.push(value);
      } else if (Array.isArray(value)) {
        value.forEach((item) => extract(item, depth + 1));
      } else if (typeof value === 'object' && value !== null) {
        Object.values(value).forEach((v) => extract(v, depth + 1));
      }
    };

    extract(obj, 0);
    return inputs;
  }

  /**
   * Helper: Send Security Error Response
   */
  private sendSecurityError(
    res: Response,
    statusCode: number,
    code: string,
    details?: any
  ): void {
    res.status(statusCode).json({
      error: {
        code,
        message: this.getErrorMessage(code),
        ...details,
      },
    });
  }

  /**
   * Helper: Get Error Message
   */
  private getErrorMessage(code: string): string {
    const messages: Record<string, string> = {
      IP_BLOCKED: 'Your IP address has been temporarily blocked',
      UNAUTHORIZED: 'Authentication required',
      RATE_LIMIT_EXCEEDED: 'Rate limit exceeded',
      TOO_MANY_CONCURRENT_REQUESTS: 'Too many concurrent requests',
      VALIDATION_ERROR: 'Request validation failed',
      CSRF_TOKEN_MISSING: 'CSRF token is required',
      CSRF_TOKEN_INVALID: 'Invalid CSRF token',
      PROMPT_INJECTION_DETECTED: 'Potentially malicious input detected',
      SQL_INJECTION_DETECTED: 'SQL injection attempt detected',
      XSS_DETECTED: 'Cross-site scripting attempt detected',
      INSUFFICIENT_PERMISSIONS: 'Insufficient permissions',
      PERMISSION_CHECK_FAILED: 'Permission check failed',
    };

    return messages[code] || 'Security error';
  }

  /**
   * Helper: Log Audit Event
   */
  private logAuditEvent(
    req: SecureRequest,
    res: Response,
    responseData: any
  ): void {
    const auditLog = {
      requestId: req.security.requestId,
      tenantId: req.security.tenantId,
      userId: req.security.userId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      ipAddress: req.security.ipAddress,
      userAgent: req.security.userAgent,
      timestamp: new Date(),
      duration: Date.now() - req.security.timestamp.getTime(),
    };

    console.log('[AUDIT]', JSON.stringify(auditLog));

    // TODO: Send to audit logging system
    // - Append to immutable log store
    // - Send to SIEM (Splunk, Datadog)
    // - Store in compliance database
  }

  /**
   * Helper: Log Security Error
   */
  private logSecurityError(req: SecureRequest, error: any): void {
    const errorLog = {
      requestId: req.security.requestId,
      tenantId: req.security.tenantId,
      userId: req.security.userId,
      error: error.message,
      stack: error.stack,
      timestamp: new Date(),
    };

    console.error('[SECURITY_ERROR]', JSON.stringify(errorLog));

    // TODO: Alert security team if critical
    // - Send to PagerDuty/Opsgenie
    // - Slack notification
    // - Email security@company.com
  }
}

/**
 * Export singleton instance
 */
export const securityMiddleware = new SecurityMiddleware();
