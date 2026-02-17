/**
 * Security Monitoring & Metrics
 * Prometheus metrics exporter and Grafana dashboards
 */

import { Registry, Counter, Histogram, Gauge } from 'prom-client';

export class SecurityMetrics {
  private registry: Registry;

  // Rate Limiting Metrics
  public rateLimitExceeded: Counter;
  public rateLimitAllowed: Counter;

  // DDoS Protection Metrics
  public ipBlockedTotal: Counter;
  public suspiciousIPDetected: Counter;

  // Injection Detection Metrics
  public promptInjectionDetected: Counter;
  public sqlInjectionDetected: Counter;
  public xssAttemptDetected: Counter;
  public csrfTokenInvalid: Counter;

  // Authentication Metrics
  public authSuccess: Counter;
  public authFailure: Counter;
  public tokenGenerated: Counter;
  public tokenExpired: Counter;

  // Request Metrics
  public httpRequestDuration: Histogram;
  public httpRequestTotal: Counter;
  public httpRequestErrors: Counter;

  // Tenant Metrics
  public activeTenants: Gauge;
  public tenantApiCalls: Counter;

  // Agent Metrics
  public agentExecutionDuration: Histogram;
  public agentSandboxCreated: Counter;
  public agentSandboxKilled: Counter;

  // Audit Metrics
  public auditEventsTotal: Counter;
  public securityEventsTotal: Counter;

  constructor() {
    this.registry = new Registry();

    // Rate Limiting
    this.rateLimitExceeded = new Counter({
      name: 'openclaw_rate_limit_exceeded_total',
      help: 'Total number of rate limit violations',
      labelNames: ['tenant_id', 'endpoint', 'tier'],
      registers: [this.registry],
    });

    this.rateLimitAllowed = new Counter({
      name: 'openclaw_rate_limit_allowed_total',
      help: 'Total number of allowed requests',
      labelNames: ['tenant_id', 'endpoint'],
      registers: [this.registry],
    });

    // DDoS Protection
    this.ipBlockedTotal = new Counter({
      name: 'openclaw_ip_blocked_total',
      help: 'Total number of IPs blocked',
      labelNames: ['reason'],
      registers: [this.registry],
    });

    this.suspiciousIPDetected = new Counter({
      name: 'openclaw_suspicious_ip_detected_total',
      help: 'Total number of suspicious IPs detected',
      registers: [this.registry],
    });

    // Injection Detection
    this.promptInjectionDetected = new Counter({
      name: 'openclaw_prompt_injection_detected_total',
      help: 'Total number of prompt injection attempts',
      labelNames: ['tenant_id', 'confidence'],
      registers: [this.registry],
    });

    this.sqlInjectionDetected = new Counter({
      name: 'openclaw_sql_injection_detected_total',
      help: 'Total number of SQL injection attempts',
      labelNames: ['tenant_id'],
      registers: [this.registry],
    });

    this.xssAttemptDetected = new Counter({
      name: 'openclaw_xss_attempt_detected_total',
      help: 'Total number of XSS attempts',
      labelNames: ['tenant_id'],
      registers: [this.registry],
    });

    this.csrfTokenInvalid = new Counter({
      name: 'openclaw_csrf_token_invalid_total',
      help: 'Total number of invalid CSRF tokens',
      labelNames: ['tenant_id'],
      registers: [this.registry],
    });

    // Authentication
    this.authSuccess = new Counter({
      name: 'openclaw_auth_success_total',
      help: 'Total number of successful authentications',
      labelNames: ['tenant_id'],
      registers: [this.registry],
    });

    this.authFailure = new Counter({
      name: 'openclaw_auth_failure_total',
      help: 'Total number of failed authentications',
      labelNames: ['tenant_id', 'reason'],
      registers: [this.registry],
    });

    this.tokenGenerated = new Counter({
      name: 'openclaw_token_generated_total',
      help: 'Total number of tokens generated',
      labelNames: ['tenant_id', 'type'],
      registers: [this.registry],
    });

    this.tokenExpired = new Counter({
      name: 'openclaw_token_expired_total',
      help: 'Total number of expired tokens',
      labelNames: ['tenant_id'],
      registers: [this.registry],
    });

    // Requests
    this.httpRequestDuration = new Histogram({
      name: 'openclaw_http_request_duration_seconds',
      help: 'HTTP request latency in seconds',
      labelNames: ['method', 'route', 'status_code', 'tenant_id'],
      buckets: [0.1, 0.5, 1, 2, 5, 10],
      registers: [this.registry],
    });

    this.httpRequestTotal = new Counter({
      name: 'openclaw_http_request_total',
      help: 'Total number of HTTP requests',
      labelNames: ['method', 'route', 'status_code'],
      registers: [this.registry],
    });

    this.httpRequestErrors = new Counter({
      name: 'openclaw_http_request_errors_total',
      help: 'Total number of HTTP request errors',
      labelNames: ['method', 'route', 'error_type'],
      registers: [this.registry],
    });

    // Tenants
    this.activeTenants = new Gauge({
      name: 'openclaw_active_tenants',
      help: 'Number of active tenants',
      registers: [this.registry],
    });

    this.tenantApiCalls = new Counter({
      name: 'openclaw_tenant_api_calls_total',
      help: 'Total API calls per tenant',
      labelNames: ['tenant_id', 'tier'],
      registers: [this.registry],
    });

    // Agents
    this.agentExecutionDuration = new Histogram({
      name: 'openclaw_agent_execution_duration_seconds',
      help: 'Agent execution duration in seconds',
      labelNames: ['tenant_id', 'agent_id'],
      buckets: [1, 5, 10, 30, 60, 300],
      registers: [this.registry],
    });

    this.agentSandboxCreated = new Counter({
      name: 'openclaw_agent_sandbox_created_total',
      help: 'Total number of agent sandboxes created',
      labelNames: ['tenant_id', 'tier'],
      registers: [this.registry],
    });

    this.agentSandboxKilled = new Counter({
      name: 'openclaw_agent_sandbox_killed_total',
      help: 'Total number of agent sandboxes killed',
      labelNames: ['tenant_id', 'reason'],
      registers: [this.registry],
    });

    // Audit
    this.auditEventsTotal = new Counter({
      name: 'openclaw_audit_events_total',
      help: 'Total number of audit events',
      labelNames: ['tenant_id', 'event_type'],
      registers: [this.registry],
    });

    this.securityEventsTotal = new Counter({
      name: 'openclaw_security_events_total',
      help: 'Total number of security events',
      labelNames: ['tenant_id', 'severity'],
      registers: [this.registry],
    });
  }

  /**
   * Get metrics in Prometheus format
   */
  async getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  /**
   * Get registry for custom metrics
   */
  getRegistry(): Registry {
    return this.registry;
  }
}

/**
 * Export singleton instance
 */
export const securityMetrics = new SecurityMetrics();

/**
 * Metrics middleware for Express/Fastify
 */
export function metricsMiddleware() {
  return async (req: any, res: any, next: any) => {
    const start = Date.now();

    // Track request
    res.on('finish', () => {
      const duration = (Date.now() - start) / 1000;
      const tenantId = req.securityContext?.tenantId || 'unknown';

      // Record duration
      securityMetrics.httpRequestDuration.observe(
        {
          method: req.method,
          route: req.path,
          status_code: res.statusCode,
          tenant_id: tenantId,
        },
        duration
      );

      // Record total
      securityMetrics.httpRequestTotal.inc({
        method: req.method,
        route: req.path,
        status_code: res.statusCode,
      });

      // Record errors
      if (res.statusCode >= 400) {
        securityMetrics.httpRequestErrors.inc({
          method: req.method,
          route: req.path,
          error_type:
            res.statusCode >= 500 ? 'server_error' : 'client_error',
        });
      }

      // Record tenant API calls
      if (tenantId !== 'unknown') {
        securityMetrics.tenantApiCalls.inc({
          tenant_id: tenantId,
          tier: req.securityContext?.tier || 'standard',
        });
      }
    });

    next();
  };
}
