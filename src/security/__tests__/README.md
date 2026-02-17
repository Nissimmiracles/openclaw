# Security Test Suite

## Running Tests

```bash
# Run all security tests
npm test src/security/__tests__

# Run specific test file
npm test src/security/__tests__/injection-prevention.test.ts

# Run with coverage
npm test -- --coverage src/security

# Watch mode
npm test -- --watch src/security
```

## Test Coverage Goals

- **Unit Tests**: >90% code coverage
- **Integration Tests**: All middleware workflows
- **Security Tests**: All attack vectors

## Test Categories

### 1. **Injection Tests** (`injection-prevention.test.ts`)
- Prompt injection detection (30+ patterns)
- SQL injection prevention
- XSS protection
- CSRF token validation

### 2. **Rate Limiting Tests** (`rate-limiter.test.ts`)
- Token bucket algorithm
- Burst allowance
- Per-tier limits
- Concurrent requests

### 3. **IAM Tests** (`iam.test.ts`)
- Role-based access control
- Permission checks
- Token generation/validation
- Role grant/revoke

### 4. **Tenant Isolation Tests** (`tenant-isolation.test.ts`)
- Tenant registration
- Access validation
- Cross-tenant prevention
- Metrics tracking

### 5. **Middleware Tests** (`middleware.test.ts`)
- Security pipeline integration
- Request validation
- Error handling

## Adding New Tests

1. Create test file: `<module>.test.ts`
2. Import module under test
3. Write test cases using Jest
4. Run tests and verify coverage

## CI/CD Integration

Tests run automatically on:
- Every commit to main branch
- Pull requests
- Pre-deployment checks

## Security Test Best Practices

1. **Test Real Attack Vectors**: Use actual malicious payloads
2. **Test Edge Cases**: Boundary conditions, empty inputs, etc.
3. **Test Performance**: Rate limiting under load
4. **Test Isolation**: No cross-test contamination
5. **Test Compliance**: Verify audit logging, encryption
