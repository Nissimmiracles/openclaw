/**
 * Security Configuration Management
 * Environment-based configuration with secrets management
 */

import { config as dotenvConfig } from 'dotenv';

// Load environment variables
dotenvConfig();

export interface SecurityConfig {
  // Environment
  nodeEnv: 'development' | 'staging' | 'production';
  port: number;
  framework: 'express' | 'fastify';

  // JWT
  jwtSecret: string;
  jwtExpiry: string;
  jwtRefreshExpiry: string;
  jwtIssuer: string;

  // CSRF
  csrfSecret: string;
  csrfTokenExpiry: number;

  // Tenant
  defaultTenantId: string;
  defaultIsolationLevel: 'standard' | 'enhanced' | 'dedicated';
  defaultDataResidency: string;

  // Database
  databaseUrl: string;
  redisUrl: string;
  qdrantUrl: string;
  neo4jUrl: string;

  // Encryption
  encryptionKeyId: string;
  kmsProvider: 'aws' | 'azure' | 'gcp' | 'vault';
  kmsEndpoint?: string;

  // Rate Limiting
  rateLimitTier: 'standard' | 'enhanced' | 'dedicated';
  rateLimitEnabled: boolean;

  // DDoS Protection
  ddosProtectionEnabled: boolean;
  ddosBlockDuration: number;
  ddosThreshold: number;

  // Injection Prevention
  promptInjectionEnabled: boolean;
  sqlInjectionEnabled: boolean;
  xssProtectionEnabled: boolean;
  csrfProtectionEnabled: boolean;

  // Compliance
  gdprEnabled: boolean;
  hipaaEnabled: boolean;
  soc2Enabled: boolean;
  iso27001Enabled: boolean;

  // Monitoring
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  auditLogEnabled: boolean;
  metricsEnabled: boolean;
  sentryDsn?: string;
  prometheusPort?: number;

  // Sandbox
  sandboxEnabled: boolean;
  sandboxRuntime: 'firecracker' | 'gvisor' | 'docker';

  // CORS
  corsEnabled: boolean;
  corsOrigins: string[];

  // TLS
  tlsEnabled: boolean;
  tlsCertPath?: string;
  tlsKeyPath?: string;
}

/**
 * Load configuration from environment variables
 */
export function loadSecurityConfig(): SecurityConfig {
  return {
    // Environment
    nodeEnv: (process.env.NODE_ENV as any) || 'development',
    port: parseInt(process.env.PORT || '3000'),
    framework: (process.env.FRAMEWORK as any) || 'express',

    // JWT
    jwtSecret: process.env.JWT_SECRET || 'change-me-in-production',
    jwtExpiry: process.env.JWT_EXPIRY || '15m',
    jwtRefreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
    jwtIssuer: process.env.JWT_ISSUER || 'openclaw-auth-service',

    // CSRF
    csrfSecret: process.env.CSRF_SECRET || 'change-me-in-production',
    csrfTokenExpiry: parseInt(process.env.CSRF_TOKEN_EXPIRY || '900'),

    // Tenant
    defaultTenantId: process.env.TENANT_ID || 'tenant-default',
    defaultIsolationLevel: (process.env.ISOLATION_LEVEL as any) || 'standard',
    defaultDataResidency: process.env.DATA_RESIDENCY || 'us-east-1',

    // Database
    databaseUrl:
      process.env.DATABASE_URL ||
      'postgresql://localhost:5432/openclaw',
    redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
    qdrantUrl: process.env.QDRANT_URL || 'http://localhost:6333',
    neo4jUrl: process.env.NEO4J_URL || 'bolt://localhost:7687',

    // Encryption
    encryptionKeyId: process.env.ENCRYPTION_KEY_ID || 'default-key',
    kmsProvider: (process.env.KMS_PROVIDER as any) || 'aws',
    kmsEndpoint: process.env.KMS_ENDPOINT,

    // Rate Limiting
    rateLimitTier: (process.env.RATE_LIMIT_TIER as any) || 'standard',
    rateLimitEnabled: process.env.RATE_LIMIT_ENABLED !== 'false',

    // DDoS Protection
    ddosProtectionEnabled: process.env.DDOS_PROTECTION_ENABLED !== 'false',
    ddosBlockDuration: parseInt(process.env.DDOS_BLOCK_DURATION || '3600'),
    ddosThreshold: parseInt(process.env.DDOS_THRESHOLD || '1000'),

    // Injection Prevention
    promptInjectionEnabled: process.env.PROMPT_INJECTION_ENABLED !== 'false',
    sqlInjectionEnabled: process.env.SQL_INJECTION_ENABLED !== 'false',
    xssProtectionEnabled: process.env.XSS_PROTECTION_ENABLED !== 'false',
    csrfProtectionEnabled: process.env.CSRF_PROTECTION_ENABLED !== 'false',

    // Compliance
    gdprEnabled: process.env.ENABLE_GDPR === 'true',
    hipaaEnabled: process.env.ENABLE_HIPAA === 'true',
    soc2Enabled: process.env.ENABLE_SOC2 === 'true',
    iso27001Enabled: process.env.ENABLE_ISO27001 === 'true',

    // Monitoring
    logLevel: (process.env.LOG_LEVEL as any) || 'info',
    auditLogEnabled: process.env.AUDIT_LOG_ENABLED !== 'false',
    metricsEnabled: process.env.METRICS_ENABLED !== 'false',
    sentryDsn: process.env.SENTRY_DSN,
    prometheusPort: process.env.PROMETHEUS_PORT
      ? parseInt(process.env.PROMETHEUS_PORT)
      : 9090,

    // Sandbox
    sandboxEnabled: process.env.SANDBOX_ENABLED !== 'false',
    sandboxRuntime: (process.env.SANDBOX_RUNTIME as any) || 'docker',

    // CORS
    corsEnabled: process.env.CORS_ENABLED !== 'false',
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || [
      'http://localhost:3000',
    ],

    // TLS
    tlsEnabled: process.env.TLS_ENABLED === 'true',
    tlsCertPath: process.env.TLS_CERT_PATH,
    tlsKeyPath: process.env.TLS_KEY_PATH,
  };
}

/**
 * Validate configuration
 */
export function validateConfig(config: SecurityConfig): void {
  const errors: string[] = [];

  // Production checks
  if (config.nodeEnv === 'production') {
    if (config.jwtSecret === 'change-me-in-production') {
      errors.push('JWT_SECRET must be set in production');
    }
    if (config.csrfSecret === 'change-me-in-production') {
      errors.push('CSRF_SECRET must be set in production');
    }
    if (!config.tlsEnabled) {
      errors.push('TLS must be enabled in production');
    }
    if (!config.sentryDsn) {
      console.warn('Warning: SENTRY_DSN not set in production');
    }
  }

  // Database checks
  if (!config.databaseUrl.startsWith('postgresql://')) {
    errors.push('DATABASE_URL must be a PostgreSQL connection string');
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
  }
}

/**
 * Export singleton config instance
 */
export const securityConfig = loadSecurityConfig();

// Validate on load
if (process.env.NODE_ENV !== 'test') {
  validateConfig(securityConfig);
}
