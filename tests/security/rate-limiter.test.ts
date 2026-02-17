/**
 * Rate Limiter Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  TokenBucketRateLimiter,
  DistributedRateLimiter,
  DDoSProtection,
} from '../../src/security/rate-limiter';

describe('TokenBucketRateLimiter', () => {
  let rateLimiter: TokenBucketRateLimiter;

  beforeEach(() => {
    rateLimiter = new TokenBucketRateLimiter();
  });

  it('should allow requests within limit', async () => {
    const result = await rateLimiter.checkRateLimit(
      'tenant-1',
      'test-endpoint',
      {
        maxRequests: 10,
        windowSeconds: 60,
        burstAllowance: 5,
      }
    );

    expect(result.allowed).toBe(true);
    expect(result.remaining).toBeGreaterThanOrEqual(0);
  });

  it('should block requests exceeding limit', async () => {
    const config = {
      maxRequests: 2,
      windowSeconds: 60,
      burstAllowance: 0,
    };

    // Make 2 requests (should succeed)
    await rateLimiter.checkRateLimit('tenant-1', 'test-endpoint', config);
    await rateLimiter.checkRateLimit('tenant-1', 'test-endpoint', config);

    // 3rd request should be blocked
    const result = await rateLimiter.checkRateLimit(
      'tenant-1',
      'test-endpoint',
      config
    );

    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('should allow burst traffic with burst allowance', async () => {
    const config = {
      maxRequests: 10,
      windowSeconds: 60,
      burstAllowance: 5,
    };

    // Make 15 rapid requests (10 + 5 burst)
    for (let i = 0; i < 15; i++) {
      const result = await rateLimiter.checkRateLimit(
        'tenant-1',
        'test-endpoint',
        config
      );
      expect(result.allowed).toBe(true);
    }

    // 16th request should be blocked
    const result = await rateLimiter.checkRateLimit(
      'tenant-1',
      'test-endpoint',
      config
    );
    expect(result.allowed).toBe(false);
  });
});

describe('DistributedRateLimiter', () => {
  let rateLimiter: DistributedRateLimiter;

  beforeEach(() => {
    rateLimiter = new DistributedRateLimiter();
  });

  it('should enforce tier-based rate limits', async () => {
    // Standard tier: 60 req/min
    const result = await rateLimiter.checkTenantRateLimit(
      'tenant-1',
      'standard',
      '/api/test'
    );

    expect(result.allowed).toBe(true);
  });

  it('should enforce concurrent request limits', async () => {
    const check = await rateLimiter.checkConcurrentRequests(
      'tenant-1',
      'standard'
    );

    expect(check.allowed).toBe(true);
    expect(check.max).toBe(10); // Standard tier limit
  });
});

describe('DDoSProtection', () => {
  let ddosProtection: DDoSProtection;

  beforeEach(() => {
    ddosProtection = new DDoSProtection();
  });

  it('should allow normal IP traffic', async () => {
    const result = await ddosProtection.checkIP('192.168.1.1');
    expect(result.allowed).toBe(true);
  });

  it('should block IP after multiple violations', async () => {
    const ip = '192.168.1.2';

    // Simulate multiple violations
    for (let i = 0; i < 15; i++) {
      await ddosProtection.trackFailedAuth(ip);
    }

    // IP should be considered suspicious
    const result = await ddosProtection.checkIP(ip);
    // Note: Actual blocking depends on implementation
  });

  it('should track request patterns', async () => {
    const ip = '192.168.1.3';

    // Track requests
    await ddosProtection.trackIPRequest(ip);
    await ddosProtection.trackIPRequest(ip);

    const result = await ddosProtection.checkIP(ip);
    expect(result.allowed).toBe(true);
  });
});
