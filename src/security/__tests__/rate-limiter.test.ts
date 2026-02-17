/**
 * Rate Limiter Tests
 */

import { TokenBucketRateLimiter, RateLimitConfig } from '../rate-limiter';

describe('TokenBucketRateLimiter', () => {
  let rateLimiter: TokenBucketRateLimiter;

  beforeEach(() => {
    rateLimiter = new TokenBucketRateLimiter();
  });

  const config: RateLimitConfig = {
    maxRequests: 10,
    windowSeconds: 60,
    burstAllowance: 5,
  };

  it('should allow requests within limit', async () => {
    for (let i = 0; i < 10; i++) {
      const result = await rateLimiter.checkRateLimit(
        'tenant-123',
        'test-endpoint',
        config
      );
      expect(result.allowed).toBe(true);
    }
  });

  it('should block requests exceeding limit', async () => {
    // Exhaust limit
    for (let i = 0; i < 15; i++) {
      await rateLimiter.checkRateLimit('tenant-123', 'test-endpoint', config);
    }

    const result = await rateLimiter.checkRateLimit(
      'tenant-123',
      'test-endpoint',
      config
    );
    expect(result.allowed).toBe(false);
    expect(result.retryAfterSeconds).toBeDefined();
  });

  it('should track remaining tokens', async () => {
    const result1 = await rateLimiter.checkRateLimit(
      'tenant-123',
      'test-endpoint',
      config
    );
    expect(result1.remaining).toBeLessThan(config.maxRequests);

    const result2 = await rateLimiter.checkRateLimit(
      'tenant-123',
      'test-endpoint',
      config
    );
    expect(result2.remaining).toBeLessThan(result1.remaining);
  });

  it('should allow burst requests', async () => {
    const burstSize = config.maxRequests + config.burstAllowance;

    for (let i = 0; i < burstSize; i++) {
      const result = await rateLimiter.checkRateLimit(
        'tenant-123',
        'test-endpoint',
        config
      );
      if (i < burstSize - 1) {
        expect(result.allowed).toBe(true);
      }
    }
  });
});
