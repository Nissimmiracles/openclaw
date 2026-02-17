# 🔒 OpenClaw Security Architecture

**Enterprise-Grade Security for Multi-Tenant AI Agent Platform**

## Table of Contents

1. [Overview](#overview)
2. [Security Architecture](#security-architecture)
3. [Components](#components)
4. [Deployment Guide](#deployment-guide)
5. [Configuration](#configuration)
6. [Compliance](#compliance)
7. [Threat Model](#threat-model)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Overview

OpenClaw implements a **8-layer defense-in-depth** security architecture designed for enterprise multi-tenant AI agent deployments.

### Security Principles

- ✅ **Zero Trust**: Verify every request, trust nothing by default
- ✅ **Defense in Depth**: Multiple security layers (network → data → execution)
- ✅ **Least Privilege**: Minimal permissions by default (RBAC)
- ✅ **Tenant Isolation**: Complete data separation (RLS + sandboxing)
- ✅ **Audit Everything**: Immutable logs for compliance
- ✅ **Secure by Default**: Security enabled out-of-the-box

### Threat Protection

| Threat | Protection | Component |
|--------|------------|----------|
| DDoS Attacks | IP blocking, rate limiting | `rate-limiter.ts` |
| Prompt Injection | Pattern detection, sanitization | `injection-prevention.ts` |
| SQL Injection | Parameterized queries, detection | `injection-prevention.ts` |
| XSS | HTML encoding, CSP headers | `middleware.ts` |
| CSRF | Token validation | `injection-prevention.ts` |
| Data Breaches | Encryption (AES-256), RLS | `encryption.ts`, `database-rls.ts` |
| Privilege Escalation | RBAC enforcement | `rbac.ts` |
| Malicious Agents | MicroVM sandboxing | `agent-sandbox.ts` |

---

## Security Architecture

### 8-Layer Defense Model

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Network Security                                  │
│  • DDoS Protection (IP blocking)                            │
│  • Rate Limiting (token bucket)                             │
│  • TLS 1.3 Encryption                                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Request Validation                                │
│  • CSRF Token Validation                                    │
│  • Input Validation (schema-based)                          │
│  • Content-Type Verification                                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Injection Prevention                              │
│  • Prompt Injection Detection (30+ patterns)                │
│  • SQL Injection Prevention                                 │
│  • XSS Protection (HTML encoding)                           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Authentication & Authorization                    │
│  • JWT Token Validation                                     │
│  • RBAC (Roles, Permissions, Scopes)                        │
│  • Tenant Context Validation                                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: Data Isolation                                    │
│  • Postgres Row-Level Security (RLS)                        │
│  • Vector Store Isolation (QDRANT)                          │
│  • Redis Cache Prefixing                                    │
│  • Neo4j Graph Isolation                                    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 6: Encryption                                        │
│  • Data at Rest (AES-256-GCM)                               │
│  • Data in Transit (TLS 1.3)                                │
│  • Key Rotation (AWS KMS, Vault)                            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 7: Agent Sandboxing                                  │
│  • MicroVM Isolation (Firecracker/gVisor)                   │
│  • Resource Limits (CPU, memory, network)                   │
│  • Execution Timeouts                                       │
│  • Kill Switch (emergency stop)                             │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  Layer 8: Audit & Monitoring                                │
│  • Immutable Audit Logs                                     │
│  • Security Event Tracking                                  │
│  • Compliance Reports (SOC 2, GDPR)                         │
│  • Real-time Alerting                                       │
└─────────────────────────────────────────────────────────────┘
```

### Request Flow

```
Client Request
      ↓
[DDoS Check] → Blocked IP? → 429 Response
      ↓ Allowed
[Rate Limit] → Quota exceeded? → 429 Response
      ↓ Within limit
[CSRF Token] → Invalid token? → 403 Response
      ↓ Valid
[Input Validation] → Schema violation? → 400 Response
      ↓ Valid
[Injection Detection] → Threat detected? → 400 Response
      ↓ Safe
[JWT Validation] → Invalid/expired? → 401 Response
      ↓ Valid
[RBAC Check] → Insufficient permissions? → 403 Response
      ↓ Authorized
[Set Tenant Context] → Database RLS enabled
      ↓
[Process Request] → Business logic
      ↓
[Audit Log] → Record event
      ↓
[XSS Protection] → Sanitize response
      ↓
Client Response
```

---

## Components

### 1. Multi-Tenant Isolation

**File:** `src/security/tenant-isolation.ts`

**Features:**
- Tenant-specific data storage schemas
- Resource quota enforcement (storage, API calls, agents)
- Network isolation per tenant
- Automatic tenant context injection

**Usage:**
```typescript
import { tenantIsolation } from './security/tenant-isolation';

// Validate tenant access
const hasAccess = await tenantIsolation.validateTenantAccess(
  userId,
  tenantId
);

// Enforce resource quota
await tenantIsolation.enforceResourceQuota(
  tenantId,
  'storage',
  1024 * 1024 * 1024 // 1 GB
);
```

### 2. Role-Based Access Control (RBAC)

**File:** `src/security/rbac.ts`

**Roles:**
- `TENANT_OWNER`: Full tenant control
- `TENANT_ADMIN`: User and agent management
- `DEVELOPER`: Agent creation and testing
- `VIEWER`: Read-only access

**Permissions:**
- `agents.create`, `agents.read`, `agents.update`, `agents.delete`
- `memory.read`, `memory.write`, `memory.delete`
- `settings.read`, `settings.write`

**Usage:**
```typescript
import { rbacManager } from './security/rbac';

// Check permission
const canCreate = await rbacManager.checkPermission(
  userId,
  'agents.create'
);

// Check scope
const canAccess = await rbacManager.checkScope(
  userId,
  'agent',
  agentId
);
```

### 3. Encryption

**File:** `src/security/encryption.ts`

**Features:**
- AES-256-GCM for data at rest
- TLS 1.3 for data in transit
- Key rotation (AWS KMS, HashiCorp Vault)
- Field-level encryption

**Usage:**
```typescript
import { encryptionManager } from './security/encryption';

// Encrypt sensitive data
const encrypted = await encryptionManager.encryptField(
  'sensitive-data',
  'api_key'
);

// Decrypt
const decrypted = await encryptionManager.decryptField(
  encrypted,
  'api_key'
);
```

### 4. Audit Logging

**File:** `src/security/audit-logging.ts`

**Event Types:**
- API requests
- Authentication events
- Data access
- Security violations
- Configuration changes

**Usage:**
```typescript
import { auditLogger } from './security/audit-logging';

// Log security event
await auditLogger.logSecurityEvent({
  tenantId,
  userId,
  eventType: 'DATA_ACCESS',
  severity: 'INFO',
  details: { resource: 'agent:123' },
  timestamp: new Date(),
  ipAddress: req.ip,
  userAgent: req.headers['user-agent'],
});
```

### 5. Database Row-Level Security (RLS)

**File:** `src/security/database-rls.ts`

**Features:**
- Postgres RLS policies
- Automatic `tenant_id` filtering
- Vector store isolation (QDRANT)
- Redis cache prefixing
- Neo4j graph isolation

**Usage:**
```typescript
import { databaseRLS } from './security/database-rls';

// Set tenant context (at request start)
await databaseRLS.setTenantContext(tenantId, dbConnection);

// All queries now automatically filtered by tenant_id
```

### 6. Agent Sandboxing

**File:** `src/security/agent-sandbox.ts`

**Features:**
- MicroVM isolation (Firecracker/gVisor)
- Resource limits (CPU, memory, network)
- Execution timeouts
- Kill switch

**Usage:**
```typescript
import { agentSandbox, SANDBOX_CONFIGS } from './security/agent-sandbox';

// Create sandbox
const sandbox = await agentSandbox.createSandbox(
  tenantId,
  agentId,
  SANDBOX_CONFIGS.enhanced
);

// Execute code
const result = await agentSandbox.executeInSandbox(
  sandbox.sandboxId,
  code,
  'python'
);

// Stop sandbox
await agentSandbox.stopSandbox(sandbox.sandboxId);
```

### 7. Rate Limiting & DDoS Protection

**File:** `src/security/rate-limiter.ts`

**Rate Limits by Tier:**

| Tier | Per Minute | Per Hour | Per Day | Concurrent |
|------|-----------|----------|---------|------------|
| Standard | 60 | 2,000 | 20,000 | 10 |
| Enhanced | 300 | 10,000 | 100,000 | 50 |
| Dedicated | 1,000 | 50,000 | 500,000 | 200 |

**Usage:**
```typescript
import { distributedRateLimiter, ddosProtection } from './security/rate-limiter';

// Check rate limit
const result = await distributedRateLimiter.checkTenantRateLimit(
  tenantId,
  tier,
  endpoint
);

// Check IP
const ipCheck = await ddosProtection.checkIP(ipAddress);
```

### 8. Injection Prevention

**File:** `src/security/injection-prevention.ts`

**Detects:**
- Prompt injection (30+ patterns)
- SQL injection
- XSS attacks
- CSRF attacks

**Usage:**
```typescript
import { promptInjectionDetector } from './security/injection-prevention';

// Check user input
const result = promptInjectionDetector.detectInjection(userInput);
if (!result.isSafe) {
  throw new Error('Prompt injection detected');
}
```

### 9. Security Middleware

**File:** `src/security/middleware.ts`

**Applies all security layers automatically:**

```typescript
import { securityMiddleware } from './security/middleware';

app.use(securityMiddleware.create());
app.use(securityMiddleware.xssProtection());
app.use(securityMiddleware.concurrentRequests());
app.use(securityMiddleware.errorHandler());
```

---

## Deployment Guide

### Prerequisites

- Node.js 18+
- PostgreSQL 14+ (with RLS support)
- Redis 7+ (for rate limiting)
- QDRANT (for vector storage)
- Neo4j 5+ (for graph storage)
- Firecracker or gVisor (for agent sandboxing)

### Environment Variables

```bash
# Security
JWT_SECRET=your-jwt-secret-key-min-32-chars
ENCRYPTION_KEY=your-encryption-key-32-bytes
CSRF_SECRET=your-csrf-secret-key

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/openclaw
REDIS_URL=redis://localhost:6379
QDRANT_URL=http://localhost:6333
NEO4J_URL=bolt://localhost:7687

# Rate Limiting
RATE_LIMIT_ENABLED=true
DDOS_PROTECTION_ENABLED=true

# Sandbox
SANDBOX_RUNTIME=firecracker # or gvisor
SANDBOX_CPU_LIMIT=2
SANDBOX_MEMORY_LIMIT_MB=2048

# Audit Logging
AUDIT_LOG_DESTINATION=database # or elasticsearch, s3
AUDIT_LOG_RETENTION_DAYS=365

# Encryption
KEY_MANAGEMENT_SERVICE=aws-kms # or vault, local
AWS_KMS_KEY_ID=your-kms-key-id
VAULT_URL=http://localhost:8200
VAULT_TOKEN=your-vault-token
```

### Installation

```bash
# Install dependencies
npm install

# Run database migrations
npm run db:migrate

# Create RLS policies
npm run db:create-rls

# Start server
npm start
```

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  openclaw:
    build: .
    ports:
      - "3000:3000"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
      - DATABASE_URL=${DATABASE_URL}
    depends_on:
      - postgres
      - redis
      - qdrant

  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: openclaw
      POSTGRES_USER: openclaw
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}

  redis:
    image: redis:7-alpine

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
```

### Kubernetes Deployment

See `k8s/` directory for complete manifests.

---

## Configuration

### Security Middleware Config

```typescript
const config = {
  enableRateLimiting: true,
  enableDDoSProtection: true,
  enablePromptInjection: true,
  enableSQLInjection: true,
  enableXSS: true,
  enableCSRF: true,
  enableInputValidation: true,
  enableAuditLogging: true,
};

app.use(securityMiddleware.create(config));
```

### Tenant Tier Configuration

```typescript
const tierConfig = {
  standard: {
    maxAgents: 10,
    maxMemoryMB: 1024,
    maxStorageGB: 10,
    requestsPerMinute: 60,
    sandboxCPU: 1,
    sandboxMemoryMB: 512,
  },
  enhanced: {
    maxAgents: 50,
    maxMemoryMB: 5120,
    maxStorageGB: 100,
    requestsPerMinute: 300,
    sandboxCPU: 2,
    sandboxMemoryMB: 2048,
  },
  dedicated: {
    maxAgents: -1, // unlimited
    maxMemoryMB: -1,
    maxStorageGB: -1,
    requestsPerMinute: 1000,
    sandboxCPU: 8,
    sandboxMemoryMB: 8192,
  },
};
```

---

## Compliance

### SOC 2 Type II

✅ **Security Controls:**
- Encryption at rest and in transit
- Role-based access control
- Audit logging (365-day retention)
- Regular security assessments

✅ **Availability Controls:**
- Rate limiting and DDoS protection
- Resource quotas per tenant
- Health checks and monitoring

✅ **Confidentiality Controls:**
- Tenant data isolation (RLS)
- Agent sandboxing
- Secret management (Vault/KMS)

### GDPR Compliance

✅ **Data Protection:**
- Encryption (Article 32)
- Data minimization (Article 5)
- Right to erasure (Article 17)
- Data portability (Article 20)

✅ **Audit Requirements:**
- Complete audit trail
- Data access logging
- Consent management
- Breach notification

### HIPAA Compliance

✅ **Technical Safeguards:**
- Access control (RBAC)
- Audit controls (logging)
- Integrity controls (encryption)
- Transmission security (TLS 1.3)

✅ **Administrative Safeguards:**
- Security management
- Workforce training
- Incident response
- Business associate agreements

---

## Threat Model

### Threat Actors

1. **External Attackers**
   - Motivation: Data theft, service disruption
   - Capabilities: DDoS, injection attacks, brute force
   - Mitigation: Rate limiting, injection detection, encryption

2. **Malicious Tenants**
   - Motivation: Resource abuse, cross-tenant access
   - Capabilities: API abuse, privilege escalation
   - Mitigation: Tenant isolation, RBAC, sandboxing

3. **Compromised Agents**
   - Motivation: System access, data exfiltration
   - Capabilities: Code execution, network access
   - Mitigation: Sandboxing, resource limits, network isolation

4. **Insider Threats**
   - Motivation: Data theft, sabotage
   - Capabilities: Direct database access, admin privileges
   - Mitigation: RBAC, audit logging, least privilege

### Security Boundaries

```
┌─────────────────────────────────────────────────┐
│  Trust Boundary 1: Internet → API Gateway      │
│  • TLS termination                              │
│  • DDoS protection                              │
│  • Rate limiting                                │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│  Trust Boundary 2: API Gateway → Application   │
│  • JWT validation                               │
│  • RBAC enforcement                             │
│  • Input validation                             │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│  Trust Boundary 3: Application → Database      │
│  • RLS policies                                 │
│  • Parameterized queries                        │
│  • Encryption                                   │
└─────────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────┐
│  Trust Boundary 4: Application → Agent Sandbox │
│  • MicroVM isolation                            │
│  • Resource limits                              │
│  • Network restrictions                         │
└─────────────────────────────────────────────────┘
```

---

## Best Practices

### 1. Key Management

- **DO:** Use AWS KMS or HashiCorp Vault for key storage
- **DO:** Rotate encryption keys every 90 days
- **DO:** Use separate keys per tenant (enhanced/dedicated tiers)
- **DON'T:** Store keys in environment variables in production
- **DON'T:** Hardcode keys in source code

### 2. Secret Management

- **DO:** Use secret management service (Vault, AWS Secrets Manager)
- **DO:** Rotate secrets regularly
- **DO:** Audit secret access
- **DON'T:** Store secrets in git
- **DON'T:** Log secrets

### 3. Database Security

- **DO:** Always use parameterized queries
- **DO:** Enable RLS on all tenant tables
- **DO:** Set `app.current_tenant_id` at request start
- **DON'T:** Concatenate user input into SQL
- **DON'T:** Disable RLS in production

### 4. API Security

- **DO:** Require authentication on all endpoints (except health)
- **DO:** Validate input on every request
- **DO:** Set rate limits per tenant tier
- **DON'T:** Trust client-provided tenant IDs
- **DON'T:** Expose internal error details

### 5. Agent Security

- **DO:** Run agents in sandboxes
- **DO:** Set resource limits (CPU, memory, network)
- **DO:** Use timeouts on all operations
- **DON'T:** Allow agents network access to internal services
- **DON'T:** Run agent code with elevated privileges

---

## Troubleshooting

### Rate Limit Errors

**Symptom:** `429 Too Many Requests`

**Causes:**
- Exceeding tier quota
- Burst traffic spike
- Multiple clients sharing IP

**Solutions:**
```typescript
// Check current rate limit status
const status = await distributedRateLimiter.checkTenantRateLimit(
  tenantId,
  tier,
  endpoint
);
console.log('Remaining:', status.remaining);
console.log('Reset at:', status.resetAt);

// Upgrade tenant tier if needed
await tenantManager.upgradeTier(tenantId, 'enhanced');
```

### Prompt Injection Detected

**Symptom:** `400 Security Violation: Potential prompt injection detected`

**Causes:**
- User input contains injection patterns
- False positive detection

**Solutions:**
```typescript
// Use sanitized input
const result = promptInjectionDetector.detectInjection(userInput);
if (!result.isSafe) {
  // Use sanitized version
  const safeInput = result.sanitizedInput;
}

// Adjust detection threshold (if false positives)
const customDetector = new PromptInjectionDetector();
customDetector.confidenceThreshold = 0.7; // Default: 0.5
```

### Sandbox Timeout

**Symptom:** Agent execution killed after timeout

**Causes:**
- Long-running operation
- Infinite loop
- Resource contention

**Solutions:**
```typescript
// Increase timeout for long operations
const customConfig = {
  ...SANDBOX_CONFIGS.enhanced,
  executionTimeoutSeconds: 1800, // 30 minutes
};

const sandbox = await agentSandbox.createSandbox(
  tenantId,
  agentId,
  customConfig
);
```

### Database RLS Not Filtering

**Symptom:** Users seeing data from other tenants

**Causes:**
- Tenant context not set
- RLS policies not enabled
- Direct database access bypassing RLS

**Solutions:**
```sql
-- Verify RLS is enabled
SELECT tablename, rowsecurity 
FROM pg_tables 
WHERE schemaname = 'public';

-- Verify policies exist
SELECT * FROM pg_policies;

-- Test policy
SET app.current_tenant_id = 'tenant-123';
SELECT * FROM memories; -- Should only return tenant-123 data
```

```typescript
// Always set context at request start
app.use(async (req, res, next) => {
  const tenantId = extractTenantId(req);
  await databaseRLS.setTenantContext(tenantId, req.db);
  next();
});
```

---

## Support

For security issues, contact: security@openclaw.ai

For general support: support@openclaw.ai

**Security Disclosure Policy:** [SECURITY_DISCLOSURE.md](./SECURITY_DISCLOSURE.md)

---

**Last Updated:** February 17, 2026

**Version:** 1.0.0
