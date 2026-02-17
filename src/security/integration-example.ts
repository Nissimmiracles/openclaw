/**
 * Security Middleware Integration Example
 * Shows how to use security middleware in Express/Fastify
 */

import express, { Express } from 'express';
import { securityMiddleware } from './middleware';
import { csrfProtection } from './injection-prevention';
import { agentSandbox, SANDBOX_CONFIGS } from './agent-sandbox';

/**
 * Express Integration Example
 */
export function createSecureExpressApp(): Express {
  const app = express();

  // 1. Parse request body
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // 2. Apply security middleware (MUST be before routes)
  app.use(
    securityMiddleware.create({
      enableRateLimiting: true,
      enableDDoSProtection: true,
      enablePromptInjection: true,
      enableSQLInjection: true,
      enableXSS: true,
      enableCSRF: true,
      enableInputValidation: true,
      enableAuditLogging: true,
    })
  );

  // 3. Apply XSS protection for responses
  app.use(securityMiddleware.xssProtection());

  // 4. Apply concurrent request tracking
  app.use(securityMiddleware.concurrentRequests());

  // 5. Define routes
  app.post('/api/chat', async (req, res) => {
    try {
      const { message, sessionId } = req.body;
      const context = (req as any).securityContext;

      // Use sanitized input if prompt injection was detected
      const safeMessage = (req.body as any)._sanitizedInput || message;

      // Process chat message
      const response = await processChat({
        message: safeMessage,
        sessionId,
        tenantId: context.tenantId,
        userId: context.userId,
      });

      res.json({
        success: true,
        response,
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  });

  app.post('/api/agent/execute', async (req, res) => {
    try {
      const { agentId, code, language } = req.body;
      const context = (req as any).securityContext;

      // Create sandbox for agent execution
      const sandbox = await agentSandbox.createSandbox(
        context.tenantId,
        agentId,
        SANDBOX_CONFIGS[context.tier as keyof typeof SANDBOX_CONFIGS]
      );

      // Execute code in sandbox
      const result = await agentSandbox.executeInSandbox(
        sandbox.sandboxId,
        code,
        language
      );

      // Stop sandbox
      await agentSandbox.stopSandbox(sandbox.sandboxId);

      res.json({
        success: true,
        result,
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  });

  // 6. CSRF token endpoint
  app.get('/api/csrf-token', (req, res) => {
    const context = (req as any).securityContext;
    const token = csrfProtection.generateToken(context.sessionId);

    res.json({
      token,
      expiresIn: 900, // 15 minutes
    });
  });

  // 7. Health check (bypass security)
  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  // 8. Apply error handler (MUST be last)
  app.use(securityMiddleware.errorHandler());

  return app;
}

/**
 * Fastify Integration Example
 */
export async function createSecureFastifyApp() {
  const fastify = require('fastify')({ logger: true });

  // 1. Register plugins
  await fastify.register(require('@fastify/cors'), {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
  });

  await fastify.register(require('@fastify/helmet'), {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
      },
    },
  });

  // 2. Add security hooks
  fastify.addHook('onRequest', async (request: any, reply: any) => {
    // Convert Fastify request to Express-like request
    const expressReq = {
      ...request,
      body: request.body,
      query: request.query,
      params: request.params,
      headers: request.headers,
      method: request.method,
      path: request.url,
      ip: request.ip,
    };

    const expressRes = {
      status: (code: number) => {
        reply.code(code);
        return expressRes;
      },
      json: (data: any) => {
        reply.send(data);
      },
      setHeader: (name: string, value: string) => {
        reply.header(name, value);
      },
    };

    // Apply security middleware
    const middleware = securityMiddleware.create();
    await new Promise<void>((resolve, reject) => {
      middleware(expressReq as any, expressRes as any, (error?: any) => {
        if (error) reject(error);
        else resolve();
      });
    });

    // Copy security context to Fastify request
    request.securityContext = (expressReq as any).securityContext;
  });

  // 3. Define routes
  fastify.post('/api/chat', async (request: any, reply: any) => {
    const { message, sessionId } = request.body;
    const context = request.securityContext;

    const response = await processChat({
      message,
      sessionId,
      tenantId: context.tenantId,
      userId: context.userId,
    });

    return { success: true, response };
  });

  // 4. Error handler
  fastify.setErrorHandler(async (error: any, request: any, reply: any) => {
    const errorHandler = securityMiddleware.errorHandler();
    await new Promise<void>((resolve) => {
      errorHandler(
        error,
        request as any,
        reply as any,
        resolve as any
      );
    });
  });

  return fastify;
}

/**
 * Helper function to process chat
 */
async function processChat(params: {
  message: string;
  sessionId: string;
  tenantId: string;
  userId: string;
}): Promise<string> {
  // TODO: Implement actual chat processing
  // - Load conversation history
  // - Send to LLM
  // - Store response

  return `Echo: ${params.message}`;
}

/**
 * Start Express server
 */
export async function startExpressServer(port = 3000) {
  const app = createSecureExpressApp();

  app.listen(port, () => {
    console.log(`🔒 Secure Express server running on port ${port}`);
    console.log('Security features enabled:');
    console.log('  ✓ Rate Limiting (tier-based)');
    console.log('  ✓ DDoS Protection (IP blocking)');
    console.log('  ✓ Prompt Injection Detection');
    console.log('  ✓ SQL Injection Prevention');
    console.log('  ✓ XSS Protection');
    console.log('  ✓ CSRF Token Validation');
    console.log('  ✓ Input Validation');
    console.log('  ✓ Audit Logging');
  });

  return app;
}

/**
 * Start Fastify server
 */
export async function startFastifyServer(port = 3000) {
  const app = await createSecureFastifyApp();

  await app.listen({ port, host: '0.0.0.0' });

  console.log(`🔒 Secure Fastify server running on port ${port}`);
  console.log('Security features enabled:');
  console.log('  ✓ Rate Limiting (tier-based)');
  console.log('  ✓ DDoS Protection (IP blocking)');
  console.log('  ✓ Prompt Injection Detection');
  console.log('  ✓ SQL Injection Prevention');
  console.log('  ✓ XSS Protection');
  console.log('  ✓ CSRF Token Validation');
  console.log('  ✓ Input Validation');
  console.log('  ✓ Audit Logging');

  return app;
}

// Run if executed directly
if (require.main === module) {
  const framework = process.env.FRAMEWORK || 'express';
  const port = parseInt(process.env.PORT || '3000');

  if (framework === 'fastify') {
    startFastifyServer(port);
  } else {
    startExpressServer(port);
  }
}
