# 🐾 OpenClaw - Enterprise Zero-Trust AI Agent Platform

> **Secure, Multi-Tenant, B2B SaaS Platform** with enterprise-grade security built-in.  
> SOC2, GDPR, HIPAA, ISO 27001 compliant.

[![Security](https://img.shields.io/badge/Security-Enterprise-green.svg)](docs/SECURITY.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/Node-20+-green.svg)](https://nodejs.org)

---

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/Nissimmiracles/openclaw.git
cd openclaw

# 2. Install dependencies
npm install

# 3. Configure environment
cp .env.example .env
# Edit .env with your settings

# 4. Start services (Docker Compose)
docker-compose up -d postgres redis qdrant neo4j

# 5. Run migrations
npm run db:migrate

# 6. Start secure server
npm run start:secure

# Output:
# 🔒 Secure Express server running on port 3000
# Security features enabled:
#   ✓ Rate Limiting (tier-based)
#   ✓ DDoS Protection (IP blocking)
#   ✓ Prompt Injection Detection
#   ✓ SQL Injection Prevention
#   ✓ XSS Protection
#   ✓ CSRF Token Validation
#   ✓ Input Validation
#   ✓ Audit Logging
```

---

## 🔒 Security Architecture

### 8-Layer Defense-in-Depth

```
╔═════════════════════════════════╗
║   Layer 1: Network Security     ║  DDoS Protection + Rate Limiting
╠═════════════════════════════════╣
║   Layer 2: Authentication        ║  JWT + RBAC + ABAC
╠═════════════════════════════════╣
║   Layer 3: Injection Prevention  ║  Prompt/SQL/XSS/CSRF
╠═════════════════════════════════╣
║   Layer 4: Data Security         ║  AES-256 + TLS 1.3 + Database RLS
╠═════════════════════════════════╣
║   Layer 5: Tenant Isolation      ║  Hardware-enforced boundaries
╠═════════════════════════════════╣
║   Layer 6: Execution Sandboxing  ║  MicroVM (Firecracker/gVisor)
╠═════════════════════════════════╣
║   Layer 7: Monitoring            ║  Real-time threat detection
╠═════════════════════════════════╣
║   Layer 8: Audit & Compliance    ║  Immutable logs + Blockchain
╚═════════════════════════════════╝
```

### Key Features

| Feature | Description | Status |
|---------|-------------|--------|
| **Multi-Tenant Isolation** | Hardware-enforced tenant boundaries | ✅ |
| **Zero-Trust Architecture** | Never trust, always verify | ✅ |
| **Prompt Injection Detection** | 30+ attack patterns detected | ✅ |
| **SQL Injection Prevention** | Parameterized queries + pattern detection | ✅ |
| **XSS Protection** | HTML entity encoding + CSP | ✅ |
| **Rate Limiting** | Token bucket (tier-based) | ✅ |
| **DDoS Protection** | Automatic IP blocking | ✅ |
| **Agent Sandboxing** | MicroVM isolation (Firecracker) | ✅ |
| **Database RLS** | Postgres row-level security | ✅ |
| **Audit Logging** | Immutable, blockchain-backed | ✅ |
| **RBAC/ABAC** | Role & attribute-based access | ✅ |
| **Encryption** | AES-256 at rest, TLS 1.3 in transit | ✅ |

---

## 🏗️ Architecture

### Multi-Tenant Data Isolation

```typescript
// Automatic tenant filtering on all database queries
const users = await db.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);
// → Postgres RLS automatically adds: AND tenant_id = 'current-tenant'

// Vector store isolation
const collection = `tenant_${tenantId}_vectors`;
await qdrant.search(collection, vector);

// Redis cache isolation
const cacheKey = `tenant:${tenantId}:user:${userId}`;
await redis.get(cacheKey);
```

### Security Middleware Pipeline

```typescript
import { securityMiddleware } from './src/security/middleware';

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
```

---

## 📊 Monitoring & Metrics

### Prometheus Metrics

```bash
# Start metrics server
http://localhost:9090/metrics

# Available metrics:
- openclaw_requests_total
- openclaw_request_latency_ms
- openclaw_security_events_total{type="prompt_injection"}
- openclaw_security_events_total{type="sql_injection"}
- openclaw_security_events_total{type="ddos"}
- openclaw_active_tenants
- openclaw_active_users
```

### Grafana Dashboard

```bash
# Import dashboard template
# Located in: monitoring/grafana-dashboard.json
```

---

## 📜 Compliance

### SOC 2 Type II
✅ Access Control (CC6.1)  
✅ Data Protection (CC6.7)  
✅ Monitoring (CC7.2)  
✅ Incident Response (CC7.3)  

### GDPR
✅ Right to Access (Art. 15)  
✅ Right to Erasure (Art. 17)  
✅ Data Portability (Art. 20)  
✅ Breach Notification (Art. 33)  

### HIPAA
✅ Access Control (§164.312(a)(1))  
✅ Audit Controls (§164.312(b))  
✅ Integrity (§164.312(c)(1))  
✅ Transmission Security (§164.312(e)(1))  

### ISO 27001
✅ A.9.2.1 User access management  
✅ A.9.4.1 Information access restriction  
✅ A.12.4.1 Event logging  
✅ A.14.2.1 Secure development  

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Run security tests only
npm test -- --grep "Security"

# Run with coverage
npm run test:coverage

# Load testing
npm run test:load
```

---

## 🚀 Deployment

### Docker

```bash
# Build image
docker build -t openclaw:latest .

# Run container
docker run -p 3000:3000 \
  -e NODE_ENV=production \
  -e DATABASE_URL=postgresql://... \
  openclaw:latest
```

### Kubernetes

```bash
# Apply manifests
kubectl apply -f k8s/

# Check deployment
kubectl get pods -l app=openclaw

# View logs
kubectl logs -f deployment/openclaw
```

### AWS

```bash
# Deploy to ECS
aws ecs create-service \
  --cluster openclaw-cluster \
  --service-name openclaw-service \
  --task-definition openclaw:1
```

---

## 📚 Documentation

- **[🔒 Security Architecture](docs/SECURITY.md)** - Complete security documentation
- **[⚙️ Configuration Guide](docs/CONFIGURATION.md)** - Environment variables and settings
- **[🚀 Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[🚨 Incident Response](docs/INCIDENT_RESPONSE.md)** - Security incident playbook
- **[📋 API Documentation](docs/API.md)** - REST API reference

---

## 👥 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Security

For security issues, please email: **security@openclaw.ai**  
PGP Key: [Download](https://openclaw.ai/pgp-key.asc)

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 📞 Support

- **Documentation**: [https://docs.openclaw.ai](https://docs.openclaw.ai)
- **Discord**: [https://discord.gg/openclaw](https://discord.gg/openclaw)
- **Email**: support@openclaw.ai

---

**Built with ❤️ by [Versatil](https://versatil.ai)**
