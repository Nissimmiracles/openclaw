/**
 * Security Middleware Integration Examples
 * Shows how to use security middleware in Express and Fastify
 */

import express, { Express } from 'express';
import { securityMiddleware, SecureRequest } from './middleware';
import { csrfProtection } from './injection-prevention';

/**
 * Express Integration Example
 */
export function setupExpressSecurity(app: Express): void {
  // Global security middleware (applies to all routes)
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Phase 1: Pre-request security (DDoS, rate limiting, JWT validation)
  app.use(
    securityMiddleware.preRequestSecurity.bind(securityMiddleware)
  );

  // Phase 2: CSRF protection (for state-changing requests)
  app.use(
    securityMiddleware.csrfProtection.bind(securityMiddleware)
  );

  // Phase 3: Injection detection (prompt, SQL, XSS)
  app.use(
    securityMiddleware.injectionDetection.bind(securityMiddleware)
  );

  // Phase 4: Post-request audit logging
  app.use(
    securityMiddleware.postRequestAudit.bind(securityMiddleware)
  );

  // Example protected route with input validation
  app.post(
    '/api/agents/create',
    securityMiddleware.validateRequest({
      name: {
        required: true,
        type: 'string',
        minLength: 3,
        maxLength: 100,
      },
      description: {
        type: 'string',
        maxLength: 500,
      },
      tools: {
        type: 'object',
      },
    }),
    securityMiddleware.requirePermission('agent', 'create'),
    async (req: SecureRequest, res) => {
      // Business logic here
      // req.security contains authenticated user context
      const { tenantId, userId } = req.security;

      res.json({
        success: true,
        agent: {
          id: 'agent_123',
          name: req.body.name,
          tenantId,
          createdBy: userId,
        },
      });
    }
  );

  // Example: Agent execution with prompt injection check
  app.post(
    '/api/agents/:agentId/execute',
    securityMiddleware.validateRequest({
      prompt: {
        required: true,
        type: 'string',
        maxLength: 10000,
      },
      context: {
        type: 'object',
      },
    }),
    securityMiddleware.requirePermission('agent', 'execute'),
    async (req: SecureRequest, res) => {
      // Prompt injection is already checked in injectionDetection middleware
      const { prompt, context } = req.body;

      // Execute agent safely
      res.json({
        success: true,
        result: 'Agent execution result',
      });
    }
  );

  // Example: Database query with SQL injection protection
  app.get(
    '/api/memories/search',
    securityMiddleware.validateRequest({
      query: {
        required: true,
        type: 'string',
        maxLength: 1000,
      },
      limit: {
        type: 'number',
        min: 1,
        max: 100,
      },
    }),
    securityMiddleware.requirePermission('memory', 'read'),
    async (req: SecureRequest, res) => {
      // SQL injection is already checked
      const { query, limit = 10 } = req.body;

      // Use parameterized queries (handled by database-rls.ts)
      res.json({
        success: true,
        results: [],
      });
    }
  );

  // Generate CSRF token for frontend
  app.get('/api/csrf-token', async (req: SecureRequest, res) => {
    const token = csrfProtection.generateToken(req.security.sessionId);
    res.json({ csrfToken: token });
  });

  // Global error handler (must be last)
  app.use(
    securityMiddleware.errorHandler.bind(securityMiddleware)
  );
}

/**
 * Fastify Integration Example
 */
export async function setupFastifySecurity(fastify: any): Promise<void> {
  // Register global hooks
  fastify.addHook('onRequest', async (request: any, reply: any) => {
    // Convert Fastify request/reply to Express-like interface
    const req: any = {
      method: request.method,
      path: request.url,
      headers: request.headers,
      body: request.body,
      query: request.query,
      socket: request.socket,
    };

    const res: any = {
      setHeader: (key: string, value: string) => reply.header(key, value),
      status: (code: number) => {
        reply.code(code);
        return res;
      },
      json: (data: any) => reply.send(data),
      send: (data: any) => reply.send(data),
    };

    const next = (err?: any) => {
      if (err) throw err;
    };

    // Run security middleware
    await securityMiddleware.preRequestSecurity(req, res, next);
    await securityMiddleware.csrfProtection(req, res, next);
    await securityMiddleware.injectionDetection(req, res, next);

    // Attach security context to Fastify request
    request.security = req.security;
  });

  // Example protected route
  fastify.post(
    '/api/agents/create',
    {
      schema: {
        body: {
          type: 'object',
          required: ['name'],
          properties: {
            name: { type: 'string', minLength: 3, maxLength: 100 },
            description: { type: 'string', maxLength: 500 },
          },
        },
      },
    },
    async (request: any, reply: any) => {
      // Check permissions
      const hasPermission = await securityMiddleware.requirePermission(
        'agent',
        'create'
      );

      if (!hasPermission) {
        return reply.code(403).send({
          error: { code: 'INSUFFICIENT_PERMISSIONS' },
        });
      }

      // Business logic
      const { tenantId, userId } = request.security;

      return {
        success: true,
        agent: {
          id: 'agent_123',
          name: request.body.name,
          tenantId,
          createdBy: userId,
        },
      };
    }
  );

  // Error handler
  fastify.setErrorHandler((error: any, request: any, reply: any) => {
    console.error('[SECURITY] Fastify error:', error);

    const statusCode = error.statusCode || 500;
    reply.code(statusCode).send({
      error: {
        code: error.code || 'INTERNAL_ERROR',
        message: statusCode === 500 ? 'Internal server error' : error.message,
        requestId: request.security?.requestId,
      },
    });
  });
}

/**
 * Standalone Security Check Function
 * For use in serverless functions, workers, etc.
 */
export async function performSecurityCheck(
  tenantId: string,
  userId: string,
  input: string,
  resource: string,
  action: string
): Promise<{
  allowed: boolean;
  reason?: string;
}> {
  // Check rate limit
  const rateLimitResult = await distributedRateLimiter.checkTenantRateLimit(
    tenantId,
    'standard', // Get from tenant context
    resource
  );

  if (!rateLimitResult.allowed) {
    return { allowed: false, reason: 'RATE_LIMIT_EXCEEDED' };
  }

  // Check prompt injection
  const promptCheck = promptInjectionDetector.detectInjection(input);
  if (!promptCheck.isSafe) {
    return {
      allowed: false,
      reason: 'PROMPT_INJECTION_DETECTED',
    };
  }

  // Check permissions
  const hasPermission = await iamManager.checkPermission(
    userId,
    resource,
    action
  );

  if (!hasPermission) {
    return { allowed: false, reason: 'INSUFFICIENT_PERMISSIONS' };
  }

  return { allowed: true };
}

// Import statements for standalone function
import { distributedRateLimiter } from './rate-limiter';
import { promptInjectionDetector } from './injection-prevention';
import { iamManager } from './iam';
