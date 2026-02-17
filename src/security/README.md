# OpenClaw Enterprise Security Architecture

## 🛡️ Overview

OpenClaw implements **Zero-Trust Security** with defense-in-depth for B2B SaaS deployments. This architecture ensures:

- **Multi-tenant isolation** with hardware-enforced boundaries
- **Zero-trust access control** (never trust, always verify)
- **End-to-end encryption** (data at rest + in transit)
- **Compliance-ready** (GDPR, HIPAA, SOC2, ISO27001)
- **Real-time threat detection** with automated response

---

## 📐 Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 1: NETWORK                         │
│  • DDoS Protection  • IP Blocking  • Rate Limiting          │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    LAYER 2: API GATEWAY                     │
│  • JWT Validation  • CSRF Protection  • Request Sanitization│
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    LAYER 3: INJECTION PREVENTION            │
│  • Prompt Injection  • SQL Injection  • XSS Protection      │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    LAYER 4: ACCESS CONTROL                  │
│  • RBAC (Roles)  • ABAC (Attributes)  • Tenant Isolation    │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    LAYER 5: DATA SECURITY                   │
│  • Encryption (AES-256)  • Database RLS  • Vector Isolation │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    LAYER 6: AGENT SANDBOXING                │
│  • MicroVM (Firecracker)  • Resource Limits  • Kill Switch  │
└───────────────────────┬─────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                    LAYER 7: MONITORING                      │
│  • Audit Logging  • Threat Detection  • Compliance Reports  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Modules

### 1. **Tenant Isolation** (`tenant-isolation.ts`)

**Purpose**: Prevent cross-tenant data access

**Features**:
- Hardware-enforced boundaries (separate schemas, namespaces)
- Per-tenant encryption keys (AES-256-GCM)
- Network micro-segmentation
- Compliance profiles (GDPR, HIPAA, SOC2, ISO27001)

**Usage**:
```typescript
import { tenantIsolationManager } from './tenant-isolation';

// Register new tenant
await tenantIsolationManager.registerTenant({
  tenantId: 'tenant-123',
  organizationId: 'org-456',
  isolationLevel: 'enhanced',
  dataResidency: 'eu-west-1',
  encryptionKeyId: 'kms-key-789',
  complianceProfile: {
    gdpr: true,
    hipaa: false,
    soc2: true,
    iso27001: true,
    pciDss: false,
  },
  createdAt: new Date(),
  updatedAt: new Date(),
});

// Validate access
tenantIsolationManager.validateTenantAccess(
  'tenant-123',
  'resource-id',
  'READ'
);
```

---

### 2. **IAM (Identity & Access Management)** (`iam.ts`)

**Purpose**: Role-Based and Attribute-Based Access Control

**Roles**:
- `TENANT_ADMIN` - Full tenant access
- `ORG_ADMIN` - User and settings management
- `DEVELOPER` - Agent creation and management
- `OPERATOR` - Agent execution
- `ANALYST` - Read-only analytics
- `VIEWER` - Read-only access
- `AGENT` - Agent execution permissions
- `SERVICE_ACCOUNT` - M2M API access

**Usage**:
```typescript
import { iamManager, Role } from './iam';

// Create user
const user = await iamManager.createUser(
  'tenant-123',
  'alice@example.com',
  [Role.DEVELOPER, Role.OPERATOR]
);

// Generate access token (15-min expiry)
const token = await iamManager.generateAccessToken(
  user.userId,
  user.tenantId
);

// Check permission
const allowed = await iamManager.checkPermission(
  user.userId,
  'agent',
  'execute'
);
```

---

### 3. **API Gateway** (`api-gateway.ts`)

**Purpose**: Zero-Trust API entry point

**Security Features**:
- JWT validation with tenant claims
- Rate limiting (token bucket algorithm)
- Request sanitization (SQL, XSS, NoSQL injection)
- Circuit breakers (fault tolerance)
- Security headers (HSTS, CSP, X-Frame-Options)

**Rate Limits by Tier**:
- **Standard**: 100 req/min, 5K/hour, 100K/day
- **Enhanced**: 500 req/min, 25K/hour, 500K/day
- **Dedicated**: 2K req/min, 100K/hour, 2M/day

**Usage**:
```typescript
import { apiGateway } from './api-gateway';

const result = await apiGateway.handleRequest(request);
// Returns: { tenantContext, request, headers }
```

---

### 4. **Database RLS (Row-Level Security)** (`database-rls.ts`)

**Purpose**: Automatic tenant_id filtering at database level

**Supported Databases**:
- **Postgres**: RLS policies with `current_setting('app.current_tenant_id')`
- **QDRANT**: Separate collections per tenant
- **Redis**: Key prefixing `tenant:{id}:*`
- **Neo4j**: Tenant-specific graphs or labels

**Usage**:
```typescript
import { databaseRLS, vectorIsolation } from './database-rls';

// Create RLS policies
await databaseRLS.createPostgresRLSPolicies('tenant-123');

// Set tenant context (MUST be called per request)
await databaseRLS.setTenantContext('tenant-123', dbConnection);

// All queries automatically filtered by tenant_id!
```

**Example SQL**:
```sql
-- Enable RLS
ALTER TABLE memories ENABLE ROW LEVEL SECURITY;

-- Create policy
CREATE POLICY tenant_isolation ON memories
FOR ALL
USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

---

### 5. **Agent Sandboxing** (`agent-sandbox.ts`)

**Purpose**: Isolate agent code execution

**Technology**: Firecracker MicroVMs or gVisor

**Resource Limits**:
- **Standard**: 1 CPU, 512 MB, 5 min timeout
- **Enhanced**: 2 CPU, 2 GB, 15 min timeout
- **Dedicated**: 8 CPU, 8 GB, 1 hour timeout

**Usage**:
```typescript
import { agentSandbox, SANDBOX_CONFIGS } from './agent-sandbox';

// Create sandbox
const sandbox = await agentSandbox.createSandbox(
  'tenant-123',
  'agent-456',
  SANDBOX_CONFIGS['enhanced']
);

// Execute code
const result = await agentSandbox.executeInSandbox(
  sandbox.sandboxId,
  'print("Hello from sandbox!")',
  'python'
);

// Stop sandbox
await agentSandbox.stopSandbox(sandbox.sandboxId);
```

---

### 6. **Rate Limiting** (`rate-limiter.ts`)

**Purpose**: Prevent abuse and enforce quotas

**Algorithm**: Token Bucket (distributed via Redis)

**Limits**:
- Per-minute, per-hour, per-day
- Per-endpoint granularity
- Concurrent request limits

**Usage**:
```typescript
import { distributedRateLimiter } from './rate-limiter';

const result = await distributedRateLimiter.checkTenantRateLimit(
  'tenant-123',
  'enhanced',
  '/api/chat'
);

if (!result.allowed) {
  throw new Error(`Rate limit exceeded. Retry after ${result.retryAfterSeconds}s`);
}
```

---

### 7. **Injection Prevention** (`injection-prevention.ts`)

**Purpose**: Detect and prevent injection attacks

**Detection Types**:
1. **Prompt Injection** (30+ patterns)
2. **SQL Injection** (parameterized queries)
3. **XSS** (HTML entity encoding)
4. **CSRF** (token validation)

**Usage**:
```typescript
import { 
  promptInjectionDetector,
  sqlInjectionPrevention,
  xssPrevention,
  csrfProtection 
} from './injection-prevention';

// Check prompt injection
const result = promptInjectionDetector.detectInjection(userInput);
if (!result.isSafe) {
  console.log('Threats:', result.threats);
  console.log('Confidence:', result.confidence);
  // Use sanitized input
  const safe = result.sanitizedInput;
}

// Parameterized SQL
const { sql, values } = sqlInjectionPrevention.createParameterizedQuery(
  'SELECT * FROM users WHERE id = :userId AND tenant_id = :tenantId',
  { userId: '123', tenantId: 'tenant-456' }
);
// Returns: { sql: 'SELECT * FROM users WHERE id = $1 AND tenant_id = $2', values: ['123', 'tenant-456'] }

// Sanitize HTML
const safe = xssPrevention.sanitizeHTML('<script>alert(1)</script>');
// Returns: '&lt;script&gt;alert(1)&lt;/script&gt;'

// CSRF token
const token = csrfProtection.generateToken(sessionId);
const isValid = csrfProtection.validateToken(token, sessionId);
```

---

### 8. **Security Middleware** (`middleware.ts`)

**Purpose**: Unified security pipeline

**Middleware Order**:
1. DDoS Protection (IP check)
2. Rate Limiting (quota check)
3. CSRF Validation (token check)
4. Input Validation (schema check)
5. Prompt Injection Detection
6. SQL Injection Detection
7. Database RLS Context (set tenant_id)
8. Audit Logging

**Usage**:
```typescript
import { securityMiddleware } from './middleware';
import express from 'express';

const app = express();

// Apply security middleware
app.use(securityMiddleware.create({
  enableRateLimiting: true,
  enableDDoSProtection: true,
  enablePromptInjection: true,
  enableSQLInjection: true,
  enableXSS: true,
  enableCSRF: true,
  enableInputValidation: true,
  enableAuditLogging: true,
}));

// XSS protection for responses
app.use(securityMiddleware.xssProtection());

// Error handler
app.use(securityMiddleware.errorHandler());
```

---

## 🚀 Deployment

### Kubernetes Deployment

**Multi-Tenant Isolation**:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tenant-{tenant-id}
  labels:
    tenant: {tenant-id}
    isolation: strict
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-isolation
  namespace: tenant-{tenant-id}
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          tenant: {tenant-id}
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          tenant: {tenant-id}
```

**OpenClaw Deployment**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw-api
  namespace: tenant-{tenant-id}
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: openclaw
        image: openclaw/api:latest
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "1"
            memory: "2Gi"
        env:
        - name: TENANT_ID
          value: "{tenant-id}"
        - name: ISOLATION_LEVEL
          value: "enhanced"
        - name: ENCRYPTION_KEY_ID
          valueFrom:
            secretKeyRef:
              name: encryption-keys
              key: key-id
```

### Docker Compose (Development)

```yaml
version: '3.8'

services:
  openclaw-api:
    image: openclaw/api:latest
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - TENANT_ID=tenant-dev
      - DATABASE_URL=postgresql://user:pass@postgres:5432/openclaw
      - REDIS_URL=redis://redis:6379
      - QDRANT_URL=http://qdrant:6333
    depends_on:
      - postgres
      - redis
      - qdrant

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=openclaw
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres-data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
    volumes:
      - qdrant-data:/qdrant/storage

volumes:
  postgres-data:
  redis-data:
  qdrant-data:
```

---

## 🔧 Configuration

### Environment Variables

```bash
# Server
NODE_ENV=production
PORT=3000
FRAMEWORK=express  # or 'fastify'

# Security
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRY=15m
CSRF_SECRET=your-csrf-secret-key

# Tenant
TENANT_ID=tenant-123
ISOLATION_LEVEL=enhanced  # standard, enhanced, dedicated
DATA_RESIDENCY=us-east-1

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/openclaw
REDIS_URL=redis://localhost:6379
QDRANT_URL=http://localhost:6333
NEO4J_URL=bolt://localhost:7687

# Encryption
ENCRYPTION_KEY_ID=kms-key-123
KMS_PROVIDER=aws  # aws, azure, gcp

# Rate Limiting
RATE_LIMIT_TIER=enhanced
RATE_LIMIT_REQUESTS_PER_MINUTE=300
RATE_LIMIT_REQUESTS_PER_HOUR=10000

# Compliance
ENABLE_GDPR=true
ENABLE_HIPAA=false
ENABLE_SOC2=true
ENABLE_ISO27001=true

# Monitoring
LOG_LEVEL=info
AUDIT_LOG_ENABLED=true
METRICS_ENABLED=true
SENTRY_DSN=https://sentry.io/...
```

---

## 📊 Compliance

### GDPR Compliance

**Features**:
- ✅ Data residency enforcement (EU regions)
- ✅ Right to erasure (data deletion)
- ✅ Right to access (data export)
- ✅ Data portability (JSON export)
- ✅ Consent management
- ✅ Audit trails (who accessed what, when)

### HIPAA Compliance

**Features**:
- ✅ Encryption at rest (AES-256)
- ✅ Encryption in transit (TLS 1.3)
- ✅ Access controls (RBAC)
- ✅ Audit logging (immutable logs)
- ✅ Data integrity checks

### SOC 2 Type II

**Controls**:
- ✅ Security (access control, encryption)
- ✅ Availability (99.9% uptime)
- ✅ Processing Integrity (data validation)
- ✅ Confidentiality (tenant isolation)
- ✅ Privacy (GDPR compliance)

### ISO 27001

**Requirements**:
- ✅ Information security management system (ISMS)
- ✅ Risk assessment and treatment
- ✅ Security policies and procedures
- ✅ Incident management
- ✅ Business continuity

---

## 🎯 Threat Model

### Attack Surface

| **Attack Vector** | **Mitigation** | **Status** |
|---|---|---|
| **DDoS** | IP blocking, rate limiting | ✅ |
| **Brute Force** | Rate limiting, account lockout | ✅ |
| **Prompt Injection** | Pattern detection, sanitization | ✅ |
| **SQL Injection** | Parameterized queries, RLS | ✅ |
| **XSS** | HTML encoding, CSP headers | ✅ |
| **CSRF** | Token validation | ✅ |
| **Data Exfiltration** | Tenant isolation, RLS | ✅ |
| **Privilege Escalation** | RBAC, least privilege | ✅ |
| **Code Injection** | Agent sandboxing, MicroVM | ✅ |
| **Man-in-the-Middle** | TLS 1.3, certificate pinning | ✅ |

---

## 🔍 Monitoring & Alerting

See `monitoring.ts` for Prometheus metrics and alerting configuration.

**Key Metrics**:
- Request latency (p50, p95, p99)
- Rate limit violations
- Security events (injection attempts, failed auth)
- Resource usage (CPU, memory, network)
- Audit log volume

---

## 📚 Additional Resources

- [Zero-Trust Architecture (NIST SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)

---

## 🆘 Support

For security issues, contact: security@openclaw.ai

For general questions: support@openclaw.ai
