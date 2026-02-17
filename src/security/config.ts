/**
 * Security Configuration Management
 * Environment-based configuration with secrets management
 */

import { config as dotenvConfig } from 'dotenv';

// Load environment variables
dotenvConfig();

export interface SecurityConfig {
  environment: 'development' | 'staging' | 'production';
  
  // Security Features
  security: {
    enableRateLimiting: boolean;
    enableDDoSProtection: boolean;
    enablePromptInjection: boolean;
    enableSQLInjection: boolean;
    enableXSS: boolean;
    enableCSRF: boolean;
    enableInputValidation: boolean;
    enableAuditLogging: boolean;
  };

  // JWT Configuration
  jwt: {
    secret: string;
    algorithm: 'RS256' | 'HS256';
    accessExpiry: string;
    refreshExpiry: string;
    publicKey?: string;
    privateKey?: string;
  };

  // Database Configuration
  database: {
    url: string;
    ssl: boolean;
    poolSize: number;
    enableRLS: boolean;
  };

  // Redis Configuration
  redis: {
    url: string;
    tls: boolean;
    keyPrefix: string;
  };

  // Vector Store Configuration
  qdrant: {
    url: string;
    apiKey?: string;
  };

  // Graph Database Configuration
  neo4j: {
    url: string;
    username: string;
    password: string;
  };

  // Encryption Configuration
  encryption: {
    algorithm: 'aes-256-gcm';
    keyId: string;
    kmsProvider: 'aws' | 'azure' | 'gcp' | 'vault' | 'local';
    kmsConfig?: any;
  };

  // Rate Limiting Configuration
  rateLimiting: {
    defaultTier: 'standard' | 'enhanced' | 'dedicated';
    redisUrl: string;
    enableDistributed: boolean;
  };

  // DDoS Protection Configuration
  ddos: {
    ipLimit: number;
    blockDuration: number;
    enableAutoBlock: boolean;
  };

  // Audit Logging Configuration
  auditLogging: {
    storage: 'postgresql' | 's3' | 'blockchain';
    retentionDays: number;
    enableBlockchain: boolean;
    blockchainProvider?: 'hyperledger' | 'ethereum';
  };

  // Monitoring Configuration
  monitoring: {
    enabled: boolean;
    metricsPort: number;
    alertWebhook?: string;
    slackWebhook?: string;
    pagerDutyKey?: string;
  };

  // Secrets Management
  secrets: {
    provider: 'vault' | 'aws' | 'azure' | 'gcp' | 'local';
    vaultUrl?: string;
    vaultToken?: string;
    awsRegion?: string;
    azureKeyVault?: string;
  };
}

/**
 * Load configuration based on environment
 */
export function loadSecurityConfig(): SecurityConfig {
  const env = (process.env.NODE_ENV as any) || 'development';

  // Base configuration
  const baseConfig: SecurityConfig = {
    environment: env,

    security: {
      enableRateLimiting: getEnvBool('ENABLE_RATE_LIMITING', true),
      enableDDoSProtection: getEnvBool('ENABLE_DDOS_PROTECTION', true),
      enablePromptInjection: getEnvBool('ENABLE_PROMPT_INJECTION', true),
      enableSQLInjection: getEnvBool('ENABLE_SQL_INJECTION', true),
      enableXSS: getEnvBool('ENABLE_XSS', true),
      enableCSRF: getEnvBool('ENABLE_CSRF', true),
      enableInputValidation: getEnvBool('ENABLE_INPUT_VALIDATION', true),
      enableAuditLogging: getEnvBool('ENABLE_AUDIT_LOGGING', true),
    },

    jwt: {
      secret: getEnvString('JWT_SECRET', 'change-me-in-production'),
      algorithm: (getEnvString('JWT_ALGORITHM', 'RS256') as any),
      accessExpiry: getEnvString('JWT_ACCESS_EXPIRY', '15m'),
      refreshExpiry: getEnvString('JWT_REFRESH_EXPIRY', '7d'),
      publicKey: getEnvString('JWT_PUBLIC_KEY'),
      privateKey: getEnvString('JWT_PRIVATE_KEY'),
    },

    database: {
      url: getEnvString('DATABASE_URL', 'postgresql://localhost:5432/openclaw'),
      ssl: getEnvBool('DATABASE_SSL', env === 'production'),
      poolSize: getEnvNumber('DATABASE_POOL_SIZE', 20),
      enableRLS: getEnvBool('DATABASE_ENABLE_RLS', true),
    },

    redis: {
      url: getEnvString('REDIS_URL', 'redis://localhost:6379'),
      tls: getEnvBool('REDIS_TLS', env === 'production'),
      keyPrefix: getEnvString('REDIS_KEY_PREFIX', 'openclaw:'),
    },

    qdrant: {
      url: getEnvString('QDRANT_URL', 'http://localhost:6333'),
      apiKey: getEnvString('QDRANT_API_KEY'),
    },

    neo4j: {
      url: getEnvString('NEO4J_URL', 'bolt://localhost:7687'),
      username: getEnvString('NEO4J_USERNAME', 'neo4j'),
      password: getEnvString('NEO4J_PASSWORD', 'password'),
    },

    encryption: {
      algorithm: 'aes-256-gcm',
      keyId: getEnvString('ENCRYPTION_KEY_ID', 'default-key'),
      kmsProvider: (getEnvString('KMS_PROVIDER', 'local') as any),
      kmsConfig: {},
    },

    rateLimiting: {
      defaultTier: (getEnvString('RATE_LIMIT_TIER', 'standard') as any),
      redisUrl: getEnvString('RATE_LIMIT_REDIS_URL', 'redis://localhost:6379'),
      enableDistributed: getEnvBool('RATE_LIMIT_DISTRIBUTED', true),
    },

    ddos: {
      ipLimit: getEnvNumber('DDOS_IP_LIMIT', 1000),
      blockDuration: getEnvNumber('DDOS_BLOCK_DURATION', 3600),
      enableAutoBlock: getEnvBool('DDOS_AUTO_BLOCK', true),
    },

    auditLogging: {
      storage: (getEnvString('AUDIT_LOG_STORAGE', 'postgresql') as any),
      retentionDays: getEnvNumber('AUDIT_LOG_RETENTION_DAYS', 2555),
      enableBlockchain: getEnvBool('AUDIT_LOG_BLOCKCHAIN', false),
    },

    monitoring: {
      enabled: getEnvBool('MONITORING_ENABLED', true),
      metricsPort: getEnvNumber('METRICS_PORT', 9090),
      alertWebhook: getEnvString('ALERT_WEBHOOK_URL'),
      slackWebhook: getEnvString('SLACK_WEBHOOK_URL'),
      pagerDutyKey: getEnvString('PAGERDUTY_API_KEY'),
    },

    secrets: {
      provider: (getEnvString('SECRETS_PROVIDER', 'local') as any),
      vaultUrl: getEnvString('VAULT_URL'),
      vaultToken: getEnvString('VAULT_TOKEN'),
      awsRegion: getEnvString('AWS_REGION', 'us-east-1'),
      azureKeyVault: getEnvString('AZURE_KEY_VAULT_NAME'),
    },
  };

  // Environment-specific overrides
  if (env === 'production') {
    return {
      ...baseConfig,
      jwt: {
        ...baseConfig.jwt,
        algorithm: 'RS256', // Force RS256 in production
      },
      database: {
        ...baseConfig.database,
        ssl: true, // Force SSL in production
      },
      monitoring: {
        ...baseConfig.monitoring,
        enabled: true, // Force monitoring in production
      },
    };
  }

  return baseConfig;
}

/**
 * Helper: Get environment variable as string
 */
function getEnvString(key: string, defaultValue?: string): string {
  return process.env[key] || defaultValue || '';
}

/**
 * Helper: Get environment variable as boolean
 */
function getEnvBool(key: string, defaultValue: boolean = false): boolean {
  const value = process.env[key];
  if (!value) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

/**
 * Helper: Get environment variable as number
 */
function getEnvNumber(key: string, defaultValue: number = 0): number {
  const value = process.env[key];
  if (!value) return defaultValue;
  return parseInt(value, 10) || defaultValue;
}

/**
 * Secrets Manager Integration
 */
export class SecretsManager {
  private config: SecurityConfig;
  private cache = new Map<string, any>();

  constructor(config: SecurityConfig) {
    this.config = config;
  }

  /**
   * Get secret from provider
   */
  async getSecret(key: string): Promise<string> {
    // Check cache first
    if (this.cache.has(key)) {
      return this.cache.get(key);
    }

    let value: string;

    switch (this.config.secrets.provider) {
      case 'vault':
        value = await this.getFromVault(key);
        break;
      case 'aws':
        value = await this.getFromAWS(key);
        break;
      case 'azure':
        value = await this.getFromAzure(key);
        break;
      case 'gcp':
        value = await this.getFromGCP(key);
        break;
      default:
        value = process.env[key] || '';
    }

    // Cache for 5 minutes
    this.cache.set(key, value);
    setTimeout(() => this.cache.delete(key), 5 * 60 * 1000);

    return value;
  }

  /**
   * Get secret from HashiCorp Vault
   */
  private async getFromVault(key: string): Promise<string> {
    // TODO: Implement Vault integration
    // const vault = require('node-vault')({
    //   endpoint: this.config.secrets.vaultUrl,
    //   token: this.config.secrets.vaultToken,
    // });
    // const secret = await vault.read(`secret/data/${key}`);
    // return secret.data.data.value;

    return process.env[key] || '';
  }

  /**
   * Get secret from AWS Secrets Manager
   */
  private async getFromAWS(key: string): Promise<string> {
    // TODO: Implement AWS Secrets Manager
    // const AWS = require('aws-sdk');
    // const secretsManager = new AWS.SecretsManager({
    //   region: this.config.secrets.awsRegion,
    // });
    // const data = await secretsManager.getSecretValue({ SecretId: key }).promise();
    // return data.SecretString;

    return process.env[key] || '';
  }

  /**
   * Get secret from Azure Key Vault
   */
  private async getFromAzure(key: string): Promise<string> {
    // TODO: Implement Azure Key Vault
    // const { SecretClient } = require('@azure/keyvault-secrets');
    // const { DefaultAzureCredential } = require('@azure/identity');
    // const credential = new DefaultAzureCredential();
    // const url = `https://${this.config.secrets.azureKeyVault}.vault.azure.net`;
    // const client = new SecretClient(url, credential);
    // const secret = await client.getSecret(key);
    // return secret.value;

    return process.env[key] || '';
  }

  /**
   * Get secret from Google Cloud Secret Manager
   */
  private async getFromGCP(key: string): Promise<string> {
    // TODO: Implement GCP Secret Manager
    // const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');
    // const client = new SecretManagerServiceClient();
    // const [version] = await client.accessSecretVersion({
    //   name: `projects/PROJECT_ID/secrets/${key}/versions/latest`,
    // });
    // return version.payload.data.toString();

    return process.env[key] || '';
  }
}

/**
 * Export configuration singleton
 */
export const securityConfig = loadSecurityConfig();
export const secretsManager = new SecretsManager(securityConfig);
