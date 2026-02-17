# Security Deployment Checklist

## Pre-Deployment

### Environment Configuration

- [ ] Generate secure random keys (min 32 characters)
  - [ ] `JWT_SECRET`
  - [ ] `ENCRYPTION_KEY`
  - [ ] `CSRF_SECRET`
- [ ] Configure key management service
  - [ ] AWS KMS keys created
  - [ ] HashiCorp Vault initialized
  - [ ] Key rotation policy defined
- [ ] Set up secret management
  - [ ] Secrets stored in Vault/AWS Secrets Manager
  - [ ] Access policies configured
  - [ ] Audit logging enabled

### Database Setup

- [ ] PostgreSQL 14+ installed
- [ ] Enable Row-Level Security (RLS)
  ```sql
  ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
  ```
- [ ] Create RLS policies for all tenant tables
- [ ] Enable encryption at rest
- [ ] Configure automated backups
- [ ] Set up replication (if required)
- [ ] Create database users with least privilege

### Redis Setup

- [ ] Redis 7+ installed
- [ ] Enable password authentication
- [ ] Configure persistence (AOF + RDB)
- [ ] Set up replication (master-slave)
- [ ] Enable TLS for client connections

### Vector Store Setup (QDRANT)

- [ ] QDRANT installed
- [ ] Create tenant-specific collections
- [ ] Enable authentication
- [ ] Configure persistence

### Graph Database Setup (Neo4j)

- [ ] Neo4j 5+ installed
- [ ] Create tenant-specific databases or labels
- [ ] Enable authentication
- [ ] Configure encryption

### Sandbox Environment

- [ ] Choose sandbox runtime (Firecracker or gVisor)
- [ ] Install sandbox dependencies
  - [ ] Firecracker binary
  - [ ] or gVisor (runsc)
- [ ] Configure kernel parameters
- [ ] Set up cgroups for resource limits
- [ ] Test sandbox creation and execution

## Security Configuration

### Rate Limiting

- [ ] Configure Redis for distributed rate limiting
- [ ] Set tier-based rate limits
  - [ ] Standard: 60/min, 2K/hour, 20K/day
  - [ ] Enhanced: 300/min, 10K/hour, 100K/day
  - [ ] Dedicated: 1K/min, 50K/hour, 500K/day
- [ ] Test rate limit enforcement
- [ ] Set up alerts for rate limit violations

### DDoS Protection

- [ ] Configure CDN/WAF (Cloudflare, AWS WAF)
- [ ] Set up IP blocklist
- [ ] Configure automatic IP blocking thresholds
- [ ] Test DDoS protection

### Injection Prevention

- [ ] Enable prompt injection detection
- [ ] Test with known injection patterns
- [ ] Configure false positive threshold
- [ ] Enable SQL injection prevention
- [ ] Enable XSS protection
- [ ] Test CSRF token validation

### RBAC

- [ ] Define roles and permissions
- [ ] Assign roles to users
- [ ] Test permission enforcement
- [ ] Configure default role for new users

### Encryption

- [ ] Enable TLS 1.3 for all connections
- [ ] Configure SSL certificates
- [ ] Enable encryption at rest (database)
- [ ] Test key rotation
- [ ] Configure encryption for backups

### Audit Logging

- [ ] Configure audit log destination
  - [ ] Database
  - [ ] Elasticsearch
  - [ ] S3
- [ ] Set retention period (min 365 days for compliance)
- [ ] Enable log immutability
- [ ] Set up log monitoring and alerts
- [ ] Test audit log ingestion

## Monitoring & Alerting

### Metrics

- [ ] Set up Prometheus
- [ ] Configure metric exporters
- [ ] Create Grafana dashboards
  - [ ] API request rate
  - [ ] Rate limit violations
  - [ ] Security events
  - [ ] Sandbox resource usage
  - [ ] Database performance

### Logging

- [ ] Set up centralized logging (ELK, Splunk)
- [ ] Configure log aggregation
- [ ] Create log queries for security events
- [ ] Set up log retention policies

### Alerts

- [ ] Configure alerting service (PagerDuty, Opsgenie)
- [ ] Create alert rules
  - [ ] High rate of failed authentications
  - [ ] DDoS attack detected
  - [ ] Prompt injection attempts
  - [ ] SQL injection attempts
  - [ ] Sandbox resource limit exceeded
  - [ ] Database connection failures
- [ ] Test alert delivery
- [ ] Define on-call rotation

## Testing

### Security Testing

- [ ] Run security audit
- [ ] Penetration testing
  - [ ] Authentication bypass
  - [ ] Authorization bypass
  - [ ] Injection attacks
  - [ ] Rate limit bypass
- [ ] Vulnerability scanning
- [ ] Dependency audit (`npm audit`)

### Load Testing

- [ ] Test rate limiting under load
- [ ] Test sandbox concurrency
- [ ] Test database connection pooling
- [ ] Test cache performance

### Disaster Recovery

- [ ] Test database backup and restore
- [ ] Test failover scenarios
- [ ] Test key rotation
- [ ] Document recovery procedures

## Compliance

### SOC 2

- [ ] Document security controls
- [ ] Implement access reviews
- [ ] Enable audit logging
- [ ] Conduct regular security assessments

### GDPR

- [ ] Implement data encryption
- [ ] Enable audit logging
- [ ] Implement data deletion (right to erasure)
- [ ] Implement data export (data portability)
- [ ] Document data processing activities
- [ ] Obtain user consent

### HIPAA

- [ ] Implement access controls (RBAC)
- [ ] Enable audit logging
- [ ] Implement encryption
- [ ] Sign Business Associate Agreements
- [ ] Conduct risk assessment
- [ ] Implement breach notification procedures

## Deployment

### Pre-Deployment Verification

- [ ] Run all tests (unit, integration, security)
- [ ] Review security configuration
- [ ] Verify environment variables
- [ ] Check SSL certificate expiration
- [ ] Review recent security advisories

### Deployment

- [ ] Deploy to staging environment
- [ ] Run smoke tests
- [ ] Verify security middleware
- [ ] Test authentication and authorization
- [ ] Verify rate limiting
- [ ] Test sandbox execution
- [ ] Deploy to production
- [ ] Monitor logs and metrics

### Post-Deployment

- [ ] Verify all services running
- [ ] Check health endpoints
- [ ] Verify SSL/TLS
- [ ] Test end-to-end flows
- [ ] Monitor error rates
- [ ] Review security logs

## Ongoing Maintenance

### Daily

- [ ] Review security alerts
- [ ] Check error logs
- [ ] Monitor performance metrics

### Weekly

- [ ] Review audit logs
- [ ] Check for security updates
- [ ] Review rate limit violations
- [ ] Check sandbox resource usage

### Monthly

- [ ] Review access permissions
- [ ] Rotate secrets and keys
- [ ] Update dependencies
- [ ] Review security incidents
- [ ] Conduct security training

### Quarterly

- [ ] Security audit
- [ ] Penetration testing
- [ ] Disaster recovery drill
- [ ] Review and update security policies
- [ ] Compliance assessment

### Annually

- [ ] SOC 2 audit
- [ ] Third-party security assessment
- [ ] Update security documentation
- [ ] Review incident response plan

---

**Last Updated:** February 17, 2026
