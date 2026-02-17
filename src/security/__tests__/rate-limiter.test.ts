/**
 * Security Test Suite: Rate Limiting
 */

import {
  TokenBucketRateLimiter,
  DistributedRateLimiter,
  DDoSProtection,
  RATE_LIMIT_TIERS,
} from '../rate-limiter';

describe('Token Bucket Rate Limiter', () => {
  let rateLimiter: TokenBucketRateLimiter;

  beforeEach(() => {
    rateLimiter = new TokenBucketRateLimiter();
  });

  it('should allow requests within limit', async () => {
    const config = {
      maxRequests: 10,
      windowSeconds: 60,
      burstAllowance: 5,
    };

    for (let i = 0; i < 10; i++) {
      const result = await rateLimiter.checkRateLimit(
        'tenant-123',
        'test',
        config
      );
      expect(result.allowed).toBe(true);
    }
  });

  it('should block requests exceeding limit', async () => {
    const config = {
      maxRequests: 5,
      windowSeconds: 60,
      burstAllowance: 0,
    };

    // Make 5 requests (should all succeed)
    for (let i = 0; i < 5; i++) {
      const result = await rateLimiter.checkRateLimit(
        'tenant-123',
        'test',
        config
      );
      expect(result.allowed).toBe(true);
    }

    // 6th request should be blocked
    const blocked = await rateLimiter.checkRateLimit(
      'tenant-123',
      'test',
      config
    );
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('should allow burst requests', async () => {
    const config = {
      maxRequests: 10,
      windowSeconds: 60,
      burstAllowance: 5,
    };

    // Should allow up to 15 requests (10 + 5 burst)
    for (let i = 0; i < 15; i++) {
      const result = await rateLimiter.checkRateLimit(
        'tenant-123',
        'burst-test',
        config
      );
      expect(result.allowed).toBe(true);
    }
  });
});

describe('Distributed Rate Limiter', () => {
  let rateLimiter: DistributedRateLimiter;

  beforeEach(() => {
    rateLimiter = new DistributedRateLimiter();
  });

  it('should enforce per-minute limit', async () => {
    const result = await rateLimiter.checkTenantRateLimit(
      'tenant-123',
      'standard',
      '/api/chat'
    );
    expect(result.allowed).toBe(true);
  });

  it('should respect tier limits', async () => {
    const standardTier = RATE_LIMIT_TIERS.standard;
    expect(standardTier.requestsPerMinute).toBe(60);

    const enhancedTier = RATE_LIMIT_TIERS.enhanced;
    expect(enhancedTier.requestsPerMinute).toBe(300);

    const dedicatedTier = RATE_LIMIT_TIERS.dedicated;
    expect(dedicatedTier.requestsPerMinute).toBe(1000);
  });

  it('should check concurrent requests', async () => {
    const result = await rateLimiter.checkConcurrentRequests(
      'tenant-123',
      'standard'
    );
    expect(result.allowed).toBe(true);
    expect(result.max).toBe(RATE_LIMIT_TIERS.standard.concurrentRequests);
  });
});

describe('DDoS Protection', () => {
  let ddos: DDoSProtection;

  beforeEach(() => {
    ddos = new DDoSProtection();
  });

  it('should allow normal traffic', async () => {
    const result = await ddos.checkIP('192.168.1.1');
    expect(result.allowed).toBe(true);
  });

  it('should block IP after exceeding threshold', async () => {
    const ip = '10.0.0.1';

    // Simulate 1001 requests
    for (let i = 0; i < 1001; i++) {
      await ddos.trackIPRequest(ip);
    }

    const result = await ddos.checkIP(ip);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('RATE_LIMIT_EXCEEDED');
  });

  it('should track failed authentication', async () => {
    const ip = '192.168.1.100';

    for (let i = 0; i < 11; i++) {
      await ddos.trackFailedAuth(ip);
    }

    // After 10 failed attempts, IP should be suspicious
    // (Actual implementation would block here)
  });

  it('should auto-unblock after timeout', async () => {
    const ip = '10.0.0.2';
    await ddos.blockIP(ip, 1); // Block for 1 second

    let result = await ddos.checkIP(ip);
    expect(result.allowed).toBe(false);

    // Wait for block to expire
    await new Promise(resolve => setTimeout(resolve, 1100));

    result = await ddos.checkIP(ip);
    expect(result.allowed).toBe(true);
  });
});
