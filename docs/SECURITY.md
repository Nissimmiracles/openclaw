# 🔒 OpenClaw Enterprise Security Architecture

> **Zero-Trust Multi-Tenant B2B SaaS Platform**  
> Built for compliance: SOC2, GDPR, HIPAA, ISO 27001

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Security Layers](#security-layers)
3. [Deployment Guide](#deployment-guide)
4. [Configuration](#configuration)
5. [Compliance](#compliance)
6. [Incident Response](#incident-response)
7. [Security Checklist](#security-checklist)

---

## 🏗️ Architecture Overview

### Zero-Trust Security Model

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CLIENT APPLICATIONS                          │
│                    (Web, Mobile, API Clients)                        │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                │ TLS 1.3
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        🛡️ SECURITY GATEWAY                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ DDoS         │  │ Rate         │  │ mTLS         │             │
│  │ Protection   │→ │ Limiting     │→ │ Auth         │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     🔐 AUTHENTICATION & AUTHORIZATION                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ JWT          │  │ RBAC         │  │ Tenant       │             │
│  │ Validation   │→ │ Enforcement  │→ │ Isolation    │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      🛡️ INJECTION PREVENTION                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │
│  │ Prompt       │  │ SQL          │  │ XSS          │             │
│  │ Injection    │→ │ Injection    │→ │ Protection   │             │
│  └──────────────┘  └──────────────┘  └──────────────┘             │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
           ┌────────────────────┼────────────────────┐
           │                    │                    │
           ▼                    ▼                    ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│   TENANT A       │  │   TENANT B       │  │   TENANT C       │
│   (Isolated)     │  │   (Isolated)     │  │   (Isolated)     │
├──────────────────┤  ├──────────────────┤  ├──────────────────┤
│ • PostgreSQL     │  │ • PostgreSQL     │  │ • PostgreSQL     │
│   (RLS Enabled)  │  │   (RLS Enabled)  │  │   (RLS Enabled)  │
│ • QDRANT         │  │ • QDRANT         │  │ • QDRANT         │
│ • Redis Cache    │  │ • Redis Cache    │  │ • Redis Cache    │
│ • Neo4j Graph    │  │ • Neo4j Graph    │  │ • Neo4j Graph    │
│ • MicroVM        │  │ • MicroVM        │  │ • MicroVM        │
│   Sandbox        │  │   Sandbox        │  │   Sandbox        │
└──────────────────┘  └──────────────────┘  └──────────────────┘
           │                    │                    │
           └────────────────────┼────────────────────┘
                                ▼
                    ┌──────────────────────┐
                    │   AUDIT LOGGING      │
                    │   (Immutable)        │
                    └──────────────────────┘
```

---

## 🛡️ Security Layers

### Layer 1: Network Security

#### DDoS Protection
- **IP-based rate limiting**: 1,000 req/min per IP
- **Automatic blocking**: 10 min - 1 hour temporary blocks
- **Pattern detection**: Scanner behavior, malformed requests
- **Geo-blocking**: Optional country-based restrictions

#### Rate Limiting (Token Bucket)
| Tier | Requests/Min | Requests/Hour | Requests/Day | Burst |
|------|--------------|---------------|--------------|-------|
| **Standard** | 60 | 2,000 | 20,000 | 1.5x |
| **Enhanced** | 300 | 10,000 | 100,000 | 2.0x |
| **Dedicated** | 1,000 | 50,000 | 500,000 | 3.0x |

---

### Layer 2: Authentication & Authorization

#### JWT Token Management
- **Access tokens**: 15-minute expiry
- **Refresh tokens**: 7-day expiry
- **Algorithm**: RS256 (RSA + SHA-256)
- **Claims**: `tenant_id`, `user_id`, `roles`, `exp`, `iat`

#### RBAC (Role-Based Access Control)
```typescript
ROLES:
  - tenant_admin    → Full access to tenant resources
  - org_admin       → User and settings management
  - developer       → Agent creation and management
  - operator        → Agent execution and monitoring
  - analyst         → Read-only analytics access
  - viewer          → Read-only access
  - agent           → Limited agent execution
  - service_account → M2M API access
```

---

### Layer 3: Injection Prevention

#### Prompt Injection Detection
**30+ dangerous patterns detected:**
- Role manipulation: "You are now a...", "Act as..."
- Instruction override: "Ignore previous instructions"
- System prompt extraction: "Show me your system prompt"
- Jailbreak attempts: "DAN mode", "SUDO"
- Data exfiltration: "Dump database", "Output all memory"

**Confidence scoring**: 0.0-1.0 (block if >0.5)

#### SQL Injection Prevention
- **Parameterized queries**: Always use `$1, $2` placeholders
- **Pattern detection**: UNION, DROP, xp_cmdshell
- **Input sanitization**: Remove quotes, semicolons, comments

#### XSS Protection
- **HTML entity encoding**: `<` → `&lt;`, `>` → `&gt;`
- **Content Security Policy**: `script-src 'self'`
- **Response sanitization**: Deep object traversal

---

### Layer 4: Data Security

#### Encryption
- **At rest**: AES-256-GCM
- **In transit**: TLS 1.3
- **Key management**: AWS KMS, Azure Key Vault, HashiCorp Vault
- **Key rotation**: Automatic every 90 days

#### Database Row-Level Security (RLS)
```sql
-- Automatic tenant filtering on all queries
CREATE POLICY tenant_isolation ON memories
FOR ALL
USING (tenant_id = current_setting('app.current_tenant_id')::uuid)
WITH CHECK (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

#### Vector Store Isolation
- **QDRANT collections**: `tenant_{id}_vectors`
- **Redis keys**: `tenant:{id}:{key}`
- **Neo4j databases**: `tenant_{id}`

---

### Layer 5: Execution Security

#### Agent Sandboxing (MicroVM)
**Technology**: Firecracker or gVisor

**Resource Limits by Tier:**
| Tier | CPU | Memory | Timeout | Network |
|------|-----|--------|---------|----------|
| **Standard** | 1 core | 512 MB | 5 min | 10 Mbps |
| **Enhanced** | 2 cores | 2 GB | 15 min | 50 Mbps |
| **Dedicated** | 8 cores | 8 GB | 1 hour | 1 Gbps |

**Kill Switch**: Automatic termination on:
- CPU limit exceeded
- Memory limit exceeded
- Execution timeout
- Suspicious behavior

---

### Layer 6: Monitoring & Compliance

#### Audit Logging
- **Storage**: Append-only, immutable
- **Retention**: 7 years (compliance requirement)
- **Format**: JSON + CSV export
- **Blockchain**: Optional for tamper-proof logs

#### Security Events Tracked
```typescript
EVENTS:
  - API_REQUEST
  - RATE_LIMIT_EXCEEDED
  - DDOS_BLOCKED
  - PROMPT_INJECTION_DETECTED
  - SQL_INJECTION_DETECTED
  - UNAUTHORIZED_ACCESS
  - LOGIN_SUCCESS/FAILED
  - DATA_EXPORTED/DELETED
  - ROLE_GRANTED/REVOKED
```

---

## 🚀 Deployment Guide

### Prerequisites
- Node.js 20+
- PostgreSQL 15+
- Redis 7+
- QDRANT 1.7+
- Neo4j 5+
- Kubernetes 1.28+ (recommended)

### Quick Start

```bash
# 1. Clone repository
git clone https://github.com/Nissimmiracles/openclaw.git
cd openclaw

# 2. Install dependencies
npm install

# 3. Configure environment
cp .env.example .env
# Edit .env with your settings

# 4. Run database migrations
npm run db:migrate

# 5. Start server
npm run start:secure

# Output:
# 🔒 Secure Express server running on port 3000
# Security features enabled:
#   ✓ Rate Limiting (tier-based)
#   ✓ DDoS Protection (IP blocking)
#   ✓ Prompt Injection Detection
#   ...
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: openclaw-secure
spec:
  replicas: 3
  selector:
    matchLabels:
      app: openclaw
  template:
    metadata:
      labels:
        app: openclaw
    spec:
      containers:
      - name: openclaw
        image: openclaw:latest
        env:
        - name: NODE_ENV
          value: "production"
        - name: ENABLE_SECURITY
          value: "true"
        resources:
          limits:
            cpu: "2"
            memory: "4Gi"
          requests:
            cpu: "1"
            memory: "2Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# Security
ENABLE_SECURITY=true
ENABLE_RATE_LIMITING=true
ENABLE_DDOS_PROTECTION=true
ENABLE_PROMPT_INJECTION=true
ENABLE_SQL_INJECTION=true
ENABLE_XSS=true
ENABLE_CSRF=true
ENABLE_AUDIT_LOGGING=true

# JWT
JWT_SECRET=your-super-secret-key-change-in-production
JWT_ALGORITHM=RS256
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/openclaw
REDIS_URL=redis://localhost:6379
QDRANT_URL=http://localhost:6333
NEO4J_URL=bolt://localhost:7687

# Encryption
ENCRYPTION_KEY=your-aes-256-key
KMS_PROVIDER=aws|azure|gcp|vault
KMS_KEY_ID=your-kms-key-id

# Rate Limiting
RATE_LIMIT_TIER=enhanced
RATE_LIMIT_REDIS_URL=redis://localhost:6379

# DDoS Protection
DDOS_IP_LIMIT=1000
DDOS_BLOCK_DURATION=3600

# Audit Logging
AUDIT_LOG_STORAGE=postgresql|s3|blockchain
AUDIT_LOG_RETENTION_DAYS=2555  # 7 years

# Monitoring
MONITORING_ENABLED=true
METRICS_PORT=9090
ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
```

---

## 📜 Compliance

### SOC 2 Type II
✅ **Access Control** (CC6.1): RBAC with least privilege  
✅ **Data Protection** (CC6.7): AES-256 encryption, TLS 1.3  
✅ **Monitoring** (CC7.2): Real-time audit logging  
✅ **Incident Response** (CC7.3): Automated alerting  

### GDPR
✅ **Right to Access** (Art. 15): Audit log export API  
✅ **Right to Erasure** (Art. 17): Tenant data deletion  
✅ **Data Portability** (Art. 20): JSON/CSV export  
✅ **Breach Notification** (Art. 33): Automated alerts  

### HIPAA
✅ **Access Control** (§164.312(a)(1)): Multi-factor authentication  
✅ **Audit Controls** (§164.312(b)): Immutable logs  
✅ **Integrity** (§164.312(c)(1)): Blockchain verification  
✅ **Transmission Security** (§164.312(e)(1)): TLS 1.3  

### ISO 27001
✅ **A.9.2.1**: User access management  
✅ **A.9.4.1**: Information access restriction  
✅ **A.12.4.1**: Event logging  
✅ **A.14.2.1**: Secure development lifecycle  

---

## 🚨 Incident Response

### Critical Event Detection

```typescript
// Automatic alerts on:
- PROMPT_INJECTION_DETECTED (confidence > 0.7)
- SQL_INJECTION_DETECTED
- Multiple LOGIN_FAILED (> 5 in 1 hour)
- DDOS_BLOCKED
- UNAUTHORIZED_ACCESS
```

### Response Playbook

#### 1. Detection
- Security event logged
- Alert sent to security team
- Tenant notified (if applicable)

#### 2. Containment
- Block malicious IP automatically
- Revoke compromised tokens
- Isolate affected tenant

#### 3. Investigation
- Review audit logs
- Analyze attack pattern
- Identify blast radius

#### 4. Remediation
- Patch vulnerability
- Reset credentials
- Update security rules

#### 5. Post-Incident
- Generate compliance report
- Update documentation
- Conduct retrospective

---

## ✅ Security Checklist

### Before Production

- [ ] Generate RSA key pair for JWT (2048-bit minimum)
- [ ] Configure KMS for encryption key management
- [ ] Enable PostgreSQL RLS policies
- [ ] Set up Redis for distributed rate limiting
- [ ] Configure CORS allowed origins
- [ ] Enable audit logging with 7-year retention
- [ ] Set up monitoring and alerting
- [ ] Configure backup encryption
- [ ] Enable MFA for admin accounts
- [ ] Review and update RBAC roles
- [ ] Test incident response playbook
- [ ] Conduct penetration testing
- [ ] Complete security audit (SOC 2, ISO 27001)
- [ ] Set up DDoS protection (Cloudflare, AWS Shield)
- [ ] Configure WAF rules
- [ ] Enable database connection pooling with SSL
- [ ] Implement secrets rotation
- [ ] Configure IP whitelist for admin access
- [ ] Set up intrusion detection system (IDS)
- [ ] Enable container security scanning

### Regular Maintenance

- [ ] Weekly: Review security alerts
- [ ] Monthly: Rotate encryption keys
- [ ] Quarterly: Conduct security training
- [ ] Annually: Renew security certifications
- [ ] Annually: Conduct penetration testing
- [ ] Continuous: Monitor for CVEs
- [ ] Continuous: Update dependencies

---

## 📞 Security Contact

For security issues, please email: **security@openclaw.ai**  
PGP Key: [Download](https://openclaw.ai/pgp-key.asc)

Bug Bounty Program: [https://openclaw.ai/security/bounty](https://openclaw.ai/security/bounty)

---

## 📚 Additional Resources

- [API Documentation](./API.md)
- [Configuration Reference](./CONFIGURATION.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [Incident Response Playbook](./INCIDENT_RESPONSE.md)
- [Security Best Practices](./BEST_PRACTICES.md)

---

**Last Updated**: February 17, 2026  
**Version**: 1.0.0  
**Maintainer**: Versatil Security Team
