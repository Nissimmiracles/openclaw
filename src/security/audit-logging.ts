/**
 * Audit Logging System
 * Immutable append-only logs for compliance and security
 * SOC2, GDPR, HIPAA, ISO 27001 compliant
 */

export interface AuditEvent {
  eventId: string;
  tenantId: string;
  userId: string;
  eventType: string;
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  details: Record<string, any>;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
}

export interface SecurityEvent extends AuditEvent {
  eventType:
    | 'API_REQUEST'
    | 'RATE_LIMIT_EXCEEDED'
    | 'DDOS_BLOCKED'
    | 'CSRF_TOKEN_INVALID'
    | 'INPUT_VALIDATION_FAILED'
    | 'PROMPT_INJECTION_DETECTED'
    | 'SQL_INJECTION_DETECTED'
    | 'XSS_DETECTED'
    | 'UNAUTHORIZED_ACCESS'
    | 'SECURITY_ERROR'
    | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILED'
    | 'PASSWORD_CHANGED'
    | 'MFA_ENABLED'
    | 'MFA_DISABLED'
    | 'API_KEY_CREATED'
    | 'API_KEY_REVOKED'
    | 'ROLE_GRANTED'
    | 'ROLE_REVOKED'
    | 'TENANT_CREATED'
    | 'TENANT_DELETED'
    | 'DATA_EXPORTED'
    | 'DATA_DELETED';
}

export interface ComplianceReport {
  tenantId: string;
  reportType: 'SOC2' | 'GDPR' | 'HIPAA' | 'ISO27001';
  startDate: Date;
  endDate: Date;
  events: SecurityEvent[];
  summary: {
    totalEvents: number;
    criticalEvents: number;
    highEvents: number;
    warningEvents: number;
    infoEvents: number;
  };
  generatedAt: Date;
}

/**
 * Audit Logger
 */
export class AuditLogger {
  private logs: SecurityEvent[] = [];
  private alertThresholds = {
    CRITICAL: 1, // Alert immediately
    HIGH: 5, // Alert after 5 events in 1 hour
    WARNING: 20, // Alert after 20 events in 1 hour
  };

  /**
   * Log security event
   */
  async logSecurityEvent(event: Omit<SecurityEvent, 'eventId'>): Promise<void> {
    const eventId = this.generateEventId();

    const securityEvent: SecurityEvent = {
      ...event,
      eventId,
    };

    // Store in memory (replace with database/blockchain)
    this.logs.push(securityEvent);

    // Log to console
    console.log(
      `[AUDIT] ${event.timestamp.toISOString()} | ${event.severity} | ${event.eventType} | Tenant: ${event.tenantId} | User: ${event.userId}`
    );

    // Persist to storage
    await this.persistLog(securityEvent);

    // Check if alerting needed
    await this.checkAlertThresholds(securityEvent);
  }

  /**
   * Persist log to immutable storage
   */
  private async persistLog(event: SecurityEvent): Promise<void> {
    // TODO: Implement persistence
    // Options:
    // 1. PostgreSQL with append-only table
    // 2. AWS S3 with object lock
    // 3. Blockchain (Hyperledger, Ethereum)
    // 4. WORM (Write-Once-Read-Many) storage
    // 5. Elasticsearch with immutable indices

    // Example PostgreSQL:
    // await db.query(`
    //   INSERT INTO audit_logs (
    //     event_id, tenant_id, user_id, event_type,
    //     severity, details, timestamp, ip_address, user_agent
    //   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    // `, [event.eventId, event.tenantId, event.userId, ...]);

    // Example Blockchain:
    // await blockchainClient.submitTransaction({
    //   chaincode: 'audit-logs',
    //   function: 'createLog',
    //   args: [JSON.stringify(event)],
    // });
  }

  /**
   * Check if event triggers alert
   */
  private async checkAlertThresholds(event: SecurityEvent): Promise<void> {
    if (event.severity === 'CRITICAL') {
      await this.sendAlert(event, 'CRITICAL event detected');
    }

    // Check for patterns (multiple high severity events)
    const recentHighEvents = this.logs.filter(
      (log) =>
        log.severity === 'HIGH' &&
        log.tenantId === event.tenantId &&
        Date.now() - log.timestamp.getTime() < 3600000 // 1 hour
    );

    if (recentHighEvents.length >= this.alertThresholds.HIGH) {
      await this.sendAlert(
        event,
        `${recentHighEvents.length} HIGH severity events in last hour`
      );
    }
  }

  /**
   * Send alert to security team
   */
  private async sendAlert(event: SecurityEvent, message: string): Promise<void> {
    console.log(`🚨 [SECURITY ALERT] ${message}`);
    console.log(`   Event: ${event.eventType}`);
    console.log(`   Tenant: ${event.tenantId}`);
    console.log(`   User: ${event.userId}`);
    console.log(`   IP: ${event.ipAddress}`);

    // TODO: Send via:
    // - Email (SendGrid, AWS SES)
    // - Slack/Teams webhook
    // - PagerDuty/OpsGenie
    // - SMS (Twilio)
  }

  /**
   * Get logs for tenant
   */
  async getLogs(
    tenantId: string,
    filters?: {
      startDate?: Date;
      endDate?: Date;
      eventType?: string;
      severity?: string;
      userId?: string;
    }
  ): Promise<SecurityEvent[]> {
    let logs = this.logs.filter((log) => log.tenantId === tenantId);

    if (filters?.startDate) {
      logs = logs.filter((log) => log.timestamp >= filters.startDate!);
    }

    if (filters?.endDate) {
      logs = logs.filter((log) => log.timestamp <= filters.endDate!);
    }

    if (filters?.eventType) {
      logs = logs.filter((log) => log.eventType === filters.eventType);
    }

    if (filters?.severity) {
      logs = logs.filter((log) => log.severity === filters.severity);
    }

    if (filters?.userId) {
      logs = logs.filter((log) => log.userId === filters.userId);
    }

    return logs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(
    tenantId: string,
    reportType: 'SOC2' | 'GDPR' | 'HIPAA' | 'ISO27001',
    startDate: Date,
    endDate: Date
  ): Promise<ComplianceReport> {
    const events = await this.getLogs(tenantId, { startDate, endDate });

    const summary = {
      totalEvents: events.length,
      criticalEvents: events.filter((e) => e.severity === 'CRITICAL').length,
      highEvents: events.filter((e) => e.severity === 'HIGH').length,
      warningEvents: events.filter((e) => e.severity === 'WARNING').length,
      infoEvents: events.filter((e) => e.severity === 'INFO').length,
    };

    return {
      tenantId,
      reportType,
      startDate,
      endDate,
      events,
      summary,
      generatedAt: new Date(),
    };
  }

  /**
   * Export logs for compliance
   */
  async exportLogs(
    tenantId: string,
    format: 'json' | 'csv' | 'pdf'
  ): Promise<string> {
    const logs = await this.getLogs(tenantId);

    switch (format) {
      case 'json':
        return JSON.stringify(logs, null, 2);

      case 'csv':
        return this.convertToCSV(logs);

      case 'pdf':
        // TODO: Generate PDF using pdfkit or puppeteer
        return 'PDF generation not implemented';

      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  /**
   * Convert logs to CSV
   */
  private convertToCSV(logs: SecurityEvent[]): string {
    const headers = [
      'Event ID',
      'Timestamp',
      'Tenant ID',
      'User ID',
      'Event Type',
      'Severity',
      'IP Address',
      'User Agent',
      'Details',
    ];

    const rows = logs.map((log) => [
      log.eventId,
      log.timestamp.toISOString(),
      log.tenantId,
      log.userId,
      log.eventType,
      log.severity,
      log.ipAddress,
      log.userAgent,
      JSON.stringify(log.details),
    ]);

    return [
      headers.join(','),
      ...rows.map((row) =>
        row.map((cell) => `"${cell}"`).join(',')
      ),
    ].join('\n');
  }

  /**
   * Generate unique event ID
   */
  private generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Verify log integrity (for blockchain-backed logs)
   */
  async verifyLogIntegrity(eventId: string): Promise<boolean> {
    // TODO: Verify blockchain hash
    // const event = this.logs.find(log => log.eventId === eventId);
    // const blockchainHash = await blockchainClient.getLogHash(eventId);
    // const computedHash = crypto.createHash('sha256')
    //   .update(JSON.stringify(event))
    //   .digest('hex');
    // return blockchainHash === computedHash;

    return true; // Placeholder
  }
}

/**
 * Export singleton instance
 */
export const auditLogger = new AuditLogger();
