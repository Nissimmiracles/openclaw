/**
 * Security Monitoring & Metrics
 * Prometheus metrics and real-time alerting
 */

import { securityConfig } from './config';

export interface SecurityMetrics {
  // Request metrics
  totalRequests: number;
  requestsPerSecond: number;
  averageLatencyMs: number;

  // Security events
  rateLimitViolations: number;
  ddosBlockedIPs: number;
  promptInjectionDetected: number;
  sqlInjectionDetected: number;
  xssDetected: number;
  csrfFailures: number;
  unauthorizedAccess: number;

  // Authentication
  loginAttempts: number;
  loginSuccesses: number;
  loginFailures: number;
  mfaEnabled: number;

  // Tenant metrics
  activeTenants: number;
  activeUsers: number;
  activeSessions: number;

  // Resource usage
  cpuUsagePercent: number;
  memoryUsageMB: number;
  diskUsageMB: number;
}

/**
 * Monitoring Dashboard
 */
export class SecurityMonitoring {
  private metrics: SecurityMetrics = {
    totalRequests: 0,
    requestsPerSecond: 0,
    averageLatencyMs: 0,
    rateLimitViolations: 0,
    ddosBlockedIPs: 0,
    promptInjectionDetected: 0,
    sqlInjectionDetected: 0,
    xssDetected: 0,
    csrfFailures: 0,
    unauthorizedAccess: 0,
    loginAttempts: 0,
    loginSuccesses: 0,
    loginFailures: 0,
    mfaEnabled: 0,
    activeTenants: 0,
    activeUsers: 0,
    activeSessions: 0,
    cpuUsagePercent: 0,
    memoryUsageMB: 0,
    diskUsageMB: 0,
  };

  private requestLatencies: number[] = [];

  /**
   * Record request
   */
  recordRequest(latencyMs: number): void {
    this.metrics.totalRequests++;
    this.requestLatencies.push(latencyMs);

    // Keep only last 1000 latencies
    if (this.requestLatencies.length > 1000) {
      this.requestLatencies.shift();
    }

    // Calculate average latency
    this.metrics.averageLatencyMs =
      this.requestLatencies.reduce((a, b) => a + b, 0) /
      this.requestLatencies.length;
  }

  /**
   * Record security event
   */
  recordSecurityEvent(eventType: string): void {
    switch (eventType) {
      case 'RATE_LIMIT_EXCEEDED':
        this.metrics.rateLimitViolations++;
        break;
      case 'DDOS_BLOCKED':
        this.metrics.ddosBlockedIPs++;
        break;
      case 'PROMPT_INJECTION_DETECTED':
        this.metrics.promptInjectionDetected++;
        break;
      case 'SQL_INJECTION_DETECTED':
        this.metrics.sqlInjectionDetected++;
        break;
      case 'XSS_DETECTED':
        this.metrics.xssDetected++;
        break;
      case 'CSRF_TOKEN_INVALID':
        this.metrics.csrfFailures++;
        break;
      case 'UNAUTHORIZED_ACCESS':
        this.metrics.unauthorizedAccess++;
        break;
      case 'LOGIN_SUCCESS':
        this.metrics.loginAttempts++;
        this.metrics.loginSuccesses++;
        break;
      case 'LOGIN_FAILED':
        this.metrics.loginAttempts++;
        this.metrics.loginFailures++;
        break;
    }
  }

  /**
   * Get current metrics
   */
  getMetrics(): SecurityMetrics {
    return { ...this.metrics };
  }

  /**
   * Export Prometheus metrics
   */
  exportPrometheusMetrics(): string {
    return `
# HELP openclaw_requests_total Total number of requests
# TYPE openclaw_requests_total counter
openclaw_requests_total ${this.metrics.totalRequests}

# HELP openclaw_request_latency_ms Average request latency in milliseconds
# TYPE openclaw_request_latency_ms gauge
openclaw_request_latency_ms ${this.metrics.averageLatencyMs}

# HELP openclaw_security_events_total Security events by type
# TYPE openclaw_security_events_total counter
openclaw_security_events_total{type="rate_limit"} ${this.metrics.rateLimitViolations}
openclaw_security_events_total{type="ddos"} ${this.metrics.ddosBlockedIPs}
openclaw_security_events_total{type="prompt_injection"} ${this.metrics.promptInjectionDetected}
openclaw_security_events_total{type="sql_injection"} ${this.metrics.sqlInjectionDetected}
openclaw_security_events_total{type="xss"} ${this.metrics.xssDetected}
openclaw_security_events_total{type="csrf"} ${this.metrics.csrfFailures}
openclaw_security_events_total{type="unauthorized"} ${this.metrics.unauthorizedAccess}

# HELP openclaw_login_attempts_total Total login attempts
# TYPE openclaw_login_attempts_total counter
openclaw_login_attempts_total{result="success"} ${this.metrics.loginSuccesses}
openclaw_login_attempts_total{result="failure"} ${this.metrics.loginFailures}

# HELP openclaw_active_tenants Number of active tenants
# TYPE openclaw_active_tenants gauge
openclaw_active_tenants ${this.metrics.activeTenants}

# HELP openclaw_active_users Number of active users
# TYPE openclaw_active_users gauge
openclaw_active_users ${this.metrics.activeUsers}

# HELP openclaw_active_sessions Number of active sessions
# TYPE openclaw_active_sessions gauge
openclaw_active_sessions ${this.metrics.activeSessions}
    `.trim();
  }

  /**
   * Start metrics server
   */
  startMetricsServer(): void {
    if (!securityConfig.monitoring.enabled) {
      console.log('[MONITORING] Metrics disabled');
      return;
    }

    const express = require('express');
    const app = express();

    app.get('/metrics', (req: any, res: any) => {
      res.set('Content-Type', 'text/plain');
      res.send(this.exportPrometheusMetrics());
    });

    app.get('/health', (req: any, res: any) => {
      res.json({ status: 'healthy', timestamp: new Date() });
    });

    const port = securityConfig.monitoring.metricsPort;
    app.listen(port, () => {
      console.log(`📊 [MONITORING] Metrics server running on port ${port}`);
      console.log(`   Prometheus: http://localhost:${port}/metrics`);
      console.log(`   Health: http://localhost:${port}/health`);
    });
  }

  /**
   * Send alert
   */
  async sendAlert(severity: 'INFO' | 'WARNING' | 'CRITICAL', message: string): Promise<void> {
    console.log(`🚨 [ALERT] ${severity}: ${message}`);

    // Send to Slack
    if (securityConfig.monitoring.slackWebhook) {
      await this.sendSlackAlert(severity, message);
    }

    // Send to PagerDuty (CRITICAL only)
    if (severity === 'CRITICAL' && securityConfig.monitoring.pagerDutyKey) {
      await this.sendPagerDutyAlert(message);
    }
  }

  /**
   * Send Slack alert
   */
  private async sendSlackAlert(severity: string, message: string): Promise<void> {
    const color = severity === 'CRITICAL' ? 'danger' : severity === 'WARNING' ? 'warning' : 'good';

    const payload = {
      attachments: [
        {
          color,
          title: `Security Alert: ${severity}`,
          text: message,
          ts: Math.floor(Date.now() / 1000),
        },
      ],
    };

    // TODO: Send to Slack webhook
    // await fetch(securityConfig.monitoring.slackWebhook!, {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify(payload),
    // });
  }

  /**
   * Send PagerDuty alert
   */
  private async sendPagerDutyAlert(message: string): Promise<void> {
    const payload = {
      routing_key: securityConfig.monitoring.pagerDutyKey,
      event_action: 'trigger',
      payload: {
        summary: message,
        severity: 'critical',
        source: 'openclaw-security',
      },
    };

    // TODO: Send to PagerDuty
    // await fetch('https://events.pagerduty.com/v2/enqueue', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify(payload),
    // });
  }
}

/**
 * Export singleton instance
 */
export const securityMonitoring = new SecurityMonitoring();
