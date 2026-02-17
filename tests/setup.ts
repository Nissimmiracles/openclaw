/**
 * Jest Test Setup
 */

// Mock environment variables
process.env.JWT_SECRET = 'test-jwt-secret-key-minimum-32-characters-long';
process.env.ENCRYPTION_KEY = 'test-encryption-key-32-bytes!!';
process.env.CSRF_SECRET = 'test-csrf-secret-key';
process.env.NODE_ENV = 'test';

// Mock Redis
jest.mock('redis', () => ({
  createClient: jest.fn(() => ({
    connect: jest.fn(),
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    incr: jest.fn(),
    decr: jest.fn(),
    expire: jest.fn(),
    hgetall: jest.fn(),
    hset: jest.fn(),
    exists: jest.fn(),
    keys: jest.fn(),
  })),
}));

// Mock database connection
jest.mock('pg', () => ({
  Pool: jest.fn(() => ({
    query: jest.fn(),
    connect: jest.fn(),
    end: jest.fn(),
  })),
}));

// Increase timeout for integration tests
jest.setTimeout(30000);

// Global test utilities
global.console = {
  ...console,
  // Suppress console logs in tests
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};
