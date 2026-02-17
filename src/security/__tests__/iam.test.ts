/**
 * IAM Tests
 */

import { IAMManager, Role } from '../iam';

describe('IAMManager', () => {
  let iamManager: IAMManager;

  beforeEach(() => {
    iamManager = new IAMManager();
  });

  describe('createUser', () => {
    it('should create user with roles', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'alice@example.com',
        [Role.DEVELOPER]
      );

      expect(user.userId).toBeDefined();
      expect(user.email).toBe('alice@example.com');
      expect(user.roles).toContain(Role.DEVELOPER);
    });

    it('should create user with attributes', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'bob@example.com',
        [Role.OPERATOR],
        { department: 'Engineering', level: 'Senior' }
      );

      expect(user.attributes.department).toBe('Engineering');
      expect(user.attributes.level).toBe('Senior');
    });
  });

  describe('checkPermission', () => {
    it('should allow TENANT_ADMIN full access', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'admin@example.com',
        [Role.TENANT_ADMIN]
      );

      const allowed = await iamManager.checkPermission(
        user.userId,
        'any-resource',
        'any-action'
      );

      expect(allowed).toBe(true);
    });

    it('should allow DEVELOPER to create agents', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'dev@example.com',
        [Role.DEVELOPER]
      );

      const allowed = await iamManager.checkPermission(
        user.userId,
        'agent',
        'write'
      );

      expect(allowed).toBe(true);
    });

    it('should deny VIEWER from writing', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'viewer@example.com',
        [Role.VIEWER]
      );

      const allowed = await iamManager.checkPermission(
        user.userId,
        'agent',
        'write'
      );

      expect(allowed).toBe(false);
    });

    it('should allow VIEWER to read', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'viewer@example.com',
        [Role.VIEWER]
      );

      const allowed = await iamManager.checkPermission(
        user.userId,
        'agent',
        'read'
      );

      expect(allowed).toBe(true);
    });
  });

  describe('generateAccessToken', () => {
    it('should generate short-lived token', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'user@example.com',
        [Role.DEVELOPER]
      );

      const token = await iamManager.generateAccessToken(
        user.userId,
        user.tenantId
      );

      expect(token.token).toBeDefined();
      expect(token.type).toBe('access');
      expect(token.expiresAt.getTime()).toBeGreaterThan(Date.now());
      expect(token.expiresAt.getTime()).toBeLessThan(
        Date.now() + 16 * 60 * 1000
      );
    });
  });

  describe('grantRole and revokeRole', () => {
    it('should grant role to user', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'user@example.com',
        [Role.VIEWER]
      );

      await iamManager.grantRole(user.userId, Role.DEVELOPER);

      const updatedUser = iamManager.getUser(user.userId);
      expect(updatedUser?.roles).toContain(Role.DEVELOPER);
    });

    it('should revoke role from user', async () => {
      const user = await iamManager.createUser(
        'tenant-123',
        'user@example.com',
        [Role.DEVELOPER, Role.OPERATOR]
      );

      await iamManager.revokeRole(user.userId, Role.OPERATOR);

      const updatedUser = iamManager.getUser(user.userId);
      expect(updatedUser?.roles).not.toContain(Role.OPERATOR);
      expect(updatedUser?.roles).toContain(Role.DEVELOPER);
    });
  });
});
