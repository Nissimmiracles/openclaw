/**
 * API Rate Limiting & DDoS Protection
 * Token bucket algorithm with Redis for distributed rate limiting
 * Per-tenant and per-endpoint rate limits
 */

import { cacheIsolation } from './database-rls';

export interface RateLimitConfig {
  maxRequests: number;
  windowSeconds: number;
  burstAllowance: number;
}

export interface RateLimitTier {
  requestsPerMinute: number;
  requestsPerHour: number;
  requestsPerDay: number;
  concurrentRequests: number;
  burstMultiplier: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  retryAfterSeconds?: number;
}

/**
 * Rate limit tiers by tenant subscription
 */
export const RATE_LIMIT_TIERS: Record<string, RateLimitTier> = {
  standard: {
    requestsPerMinute: 60,
    requestsPerHour: 2000,
    requestsPerDay: 20000,
    concurrentRequests: 10,
    burstMultiplier: 1.5,
  },
  enhanced: {
    requestsPerMinute: 300,
    requestsPerHour: 10000,
    requestsPerDay: 100000,
    concurrentRequests: 50,
    burstMultiplier: 2.0,
  },
  dedicated: {
    requestsPerMinute: 1000,
    requestsPerHour: 50000,
    requestsPerDay: 500000,
    concurrentRequests: 200,
    burstMultiplier: 3.0,
  },
};

/**
 * Token Bucket Rate Limiter
 */
export class TokenBucketRateLimiter {
  /**
   * Check rate limit using token bucket algorithm
   */
  async checkRateLimit(
    tenantId: string,
    identifier: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const key = `ratelimit:${tenantId}:${identifier}`;
    const now = Date.now();

    // Get current bucket state from Redis
    const bucketData = await this.getBucketState(key);

    const {
      tokens = config.maxRequests,
      lastRefill = now,
    } = bucketData;

    // Calculate tokens to add based on time elapsed
    const elapsedSeconds = (now - lastRefill) / 1000;
    const tokensToAdd =
      elapsedSeconds * (config.maxRequests / config.windowSeconds);
    const newTokens = Math.min(
      config.maxRequests + config.burstAllowance,
      tokens + tokensToAdd
    );

    // Check if request allowed
    const allowed = newTokens >= 1;
    const remaining = allowed ? Math.floor(newTokens - 1) : 0;

    // Update bucket state
    if (allowed) {
      await this.updateBucketState(key, {
        tokens: newTokens - 1,
        lastRefill: now,
      });
    }

    const resetAt = new Date(
      now + config.windowSeconds * 1000
    );

    const result: RateLimitResult = {
      allowed,
      remaining,
      resetAt,
    };

    if (!allowed) {
      result.retryAfterSeconds = Math.ceil(
        config.windowSeconds - elapsedSeconds
      );
    }

    console.log(
      `[RATE_LIMIT] ${identifier} - Allowed: ${allowed}, Remaining: ${remaining}`
    );

    return result;
  }

  /**
   * Get bucket state from Redis
   */
  private async getBucketState(
    key: string
  ): Promise<{ tokens: number; lastRefill: number }> {
    // TODO: Get from Redis
    // const data = await redis.hgetall(key);
    // return {
    //   tokens: parseFloat(data.tokens) || 0,
    //   lastRefill: parseInt(data.lastRefill) || Date.now(),
    // };

    return { tokens: 0, lastRefill: Date.now() };
  }

  /**
   * Update bucket state in Redis
   */
  private async updateBucketState(
    key: string,
    state: { tokens: number; lastRefill: number }
  ): Promise<void> {
    // TODO: Set in Redis with expiration
    // await redis.hset(key, {
    //   tokens: state.tokens.toString(),
    //   lastRefill: state.lastRefill.toString(),
    // });
    // await redis.expire(key, 3600); // 1 hour expiration
  }
}

/**
 * Distributed Rate Limiter
 */
export class DistributedRateLimiter {
  private tokenBucket = new TokenBucketRateLimiter();

  /**
   * Check rate limit for tenant
   */
  async checkTenantRateLimit(
    tenantId: string,
    tier: string,
    endpoint: string
  ): Promise<RateLimitResult> {
    const tierConfig = RATE_LIMIT_TIERS[tier];
    if (!tierConfig) {
      throw new Error(`Unknown tier: ${tier}`);
    }

    // Check per-minute limit
    const minuteResult = await this.tokenBucket.checkRateLimit(
      tenantId,
      `${endpoint}:minute`,
      {
        maxRequests: tierConfig.requestsPerMinute,
        windowSeconds: 60,
        burstAllowance: Math.floor(
          tierConfig.requestsPerMinute * (tierConfig.burstMultiplier - 1)
        ),
      }
    );

    if (!minuteResult.allowed) {
      return minuteResult;
    }

    // Check per-hour limit
    const hourResult = await this.tokenBucket.checkRateLimit(
      tenantId,
      `${endpoint}:hour`,
      {
        maxRequests: tierConfig.requestsPerHour,
        windowSeconds: 3600,
        burstAllowance: 0,
      }
    );

    if (!hourResult.allowed) {
      return hourResult;
    }

    // Check per-day limit
    const dayResult = await this.tokenBucket.checkRateLimit(
      tenantId,
      `${endpoint}:day`,
      {
        maxRequests: tierConfig.requestsPerDay,
        windowSeconds: 86400,
        burstAllowance: 0,
      }
    );

    return dayResult;
  }

  /**
   * Check concurrent requests
   */
  async checkConcurrentRequests(
    tenantId: string,
    tier: string
  ): Promise<{ allowed: boolean; current: number; max: number }> {
    const tierConfig = RATE_LIMIT_TIERS[tier];
    const key = `concurrent:${tenantId}`;

    // TODO: Get current count from Redis
    // const current = await redis.get(key);
    const current = 0;

    const allowed = current < tierConfig.concurrentRequests;

    if (allowed) {
      // Increment counter
      // await redis.incr(key);
      // await redis.expire(key, 60);
    }

    return {
      allowed,
      current,
      max: tierConfig.concurrentRequests,
    };
  }

  /**
   * Release concurrent request slot
   */
  async releaseConcurrentSlot(tenantId: string): Promise<void> {
    const key = `concurrent:${tenantId}`;
    // await redis.decr(key);
  }
}

/**
 * DDoS Protection
 */
export class DDoSProtection {
  private blockedIPs = new Set<string>();
  private suspiciousIPs = new Map<string, number>();

  /**
   * Check if IP is blocked or suspicious
   */
  async checkIP(ip: string): Promise<{
    allowed: boolean;
    reason?: string;
    blockUntil?: Date;
  }> {
    // Check if IP is blocked
    if (await this.isIPBlocked(ip)) {
      return {
        allowed: false,
        reason: 'IP_BLOCKED',
        blockUntil: await this.getBlockExpiry(ip),
      };
    }

    // Check request pattern
    const requestCount = await this.getIPRequestCount(ip);

    // Threshold: 1000 requests per minute from single IP
    if (requestCount > 1000) {
      await this.blockIP(ip, 3600); // Block for 1 hour
      return {
        allowed: false,
        reason: 'RATE_LIMIT_EXCEEDED',
      };
    }

    // Check if IP is making suspicious patterns
    const isSuspicious = await this.detectSuspiciousPattern(ip);
    if (isSuspicious) {
      await this.blockIP(ip, 600); // Block for 10 minutes
      return {
        allowed: false,
        reason: 'SUSPICIOUS_PATTERN',
      };
    }

    return { allowed: true };
  }

  /**
   * Track request from IP
   */
  async trackIPRequest(ip: string): Promise<void> {
    const key = `ip:requests:${ip}:${Math.floor(Date.now() / 60000)}`;
    // await redis.incr(key);
    // await redis.expire(key, 120); // Keep for 2 minutes
  }

  /**
   * Get IP request count
   */
  private async getIPRequestCount(ip: string): Promise<number> {
    const key = `ip:requests:${ip}:${Math.floor(Date.now() / 60000)}`;
    // const count = await redis.get(key);
    // return parseInt(count || '0');
    return 0;
  }

  /**
   * Block IP address
   */
  async blockIP(ip: string, durationSeconds: number): Promise<void> {
    const key = `ip:blocked:${ip}`;
    const expiryTime = Date.now() + durationSeconds * 1000;

    // await redis.set(key, expiryTime.toString());
    // await redis.expire(key, durationSeconds);

    this.blockedIPs.add(ip);

    console.log(
      `[DDOS_PROTECTION] Blocked IP ${ip} for ${durationSeconds} seconds`
    );
  }

  /**
   * Check if IP is blocked
   */
  private async isIPBlocked(ip: string): Promise<boolean> {
    const key = `ip:blocked:${ip}`;
    // const blocked = await redis.exists(key);
    // return blocked === 1;
    return this.blockedIPs.has(ip);
  }

  /**
   * Get block expiry time
   */
  private async getBlockExpiry(ip: string): Promise<Date | undefined> {
    const key = `ip:blocked:${ip}`;
    // const expiryTime = await redis.get(key);
    // return expiryTime ? new Date(parseInt(expiryTime)) : undefined;
    return undefined;
  }

  /**
   * Detect suspicious patterns
   */
  private async detectSuspiciousPattern(ip: string): Promise<boolean> {
    // Check for:
    // 1. Rapid sequential requests to different endpoints
    // 2. Many failed authentication attempts
    // 3. Requests with malformed headers
    // 4. Scanner-like behavior (probing endpoints)

    const failedAuthKey = `ip:failed_auth:${ip}`;
    // const failedAuthCount = await redis.get(failedAuthKey);

    // Block after 10 failed auth attempts
    // if (parseInt(failedAuthCount || '0') > 10) {
    //   return true;
    // }

    return false;
  }

  /**
   * Track failed authentication
   */
  async trackFailedAuth(ip: string): Promise<void> {
    const key = `ip:failed_auth:${ip}`;
    // await redis.incr(key);
    // await redis.expire(key, 3600); // Reset after 1 hour
  }
}

/**
 * Export singleton instances
 */
export const distributedRateLimiter = new DistributedRateLimiter();
export const ddosProtection = new DDoSProtection();
