/**
 * RBAC Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  RBACManager,
  Role,
  Permission,
  ROLES,
} from '../../src/security/rbac';

describe('RBACManager', () => {
  let rbacManager: RBACManager;

  beforeEach(() => {
    rbacManager = new RBACManager();
  });

  describe('Role Assignment', () => {
    it('should assign role to user', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'DEVELOPER');

      const roles = await rbacManager.getUserRoles('user-1', 'tenant-1');
      expect(roles).toContain('DEVELOPER');
    });

    it('should remove role from user', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'DEVELOPER');
      await rbacManager.removeRole('user-1', 'tenant-1', 'DEVELOPER');

      const roles = await rbacManager.getUserRoles('user-1', 'tenant-1');
      expect(roles).not.toContain('DEVELOPER');
    });

    it('should get all roles for user', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'DEVELOPER');
      await rbacManager.assignRole('user-1', 'tenant-1', 'VIEWER');

      const roles = await rbacManager.getUserRoles('user-1', 'tenant-1');
      expect(roles).toContain('DEVELOPER');
      expect(roles).toContain('VIEWER');
    });
  });

  describe('Permission Checks', () => {
    it('should allow permission for role', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'DEVELOPER');

      const canCreate = await rbacManager.checkPermission(
        'user-1',
        'agents.create'
      );
      expect(canCreate).toBe(true);
    });

    it('should deny permission not in role', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'VIEWER');

      const canDelete = await rbacManager.checkPermission(
        'user-1',
        'agents.delete'
      );
      expect(canDelete).toBe(false);
    });

    it('should allow wildcard permissions', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'TENANT_OWNER');

      const canDoAnything = await rbacManager.checkPermission(
        'user-1',
        'agents.anything'
      );
      expect(canDoAnything).toBe(true);
    });

    it('should check multiple permissions', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'DEVELOPER');

      const canCreate = await rbacManager.checkPermission(
        'user-1',
        'agents.create'
      );
      const canRead = await rbacManager.checkPermission(
        'user-1',
        'agents.read'
      );
      const canDelete = await rbacManager.checkPermission(
        'user-1',
        'agents.delete'
      );

      expect(canCreate).toBe(true);
      expect(canRead).toBe(true);
      expect(canDelete).toBe(false); // Only owners/admins can delete
    });
  });

  describe('Scope Checks', () => {
    it('should allow access to owned resource', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'DEVELOPER');
      await rbacManager.assignScope('user-1', 'agent', 'agent-1');

      const canAccess = await rbacManager.checkScope(
        'user-1',
        'agent',
        'agent-1'
      );
      expect(canAccess).toBe(true);
    });

    it('should deny access to non-owned resource', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'DEVELOPER');

      const canAccess = await rbacManager.checkScope(
        'user-1',
        'agent',
        'agent-999'
      );
      expect(canAccess).toBe(false);
    });

    it('should allow tenant owners access to all resources', async () => {
      await rbacManager.assignRole('user-1', 'tenant-1', 'TENANT_OWNER');

      const canAccess = await rbacManager.checkScope(
        'user-1',
        'agent',
        'any-agent'
      );
      expect(canAccess).toBe(true);
    });
  });

  describe('Role Hierarchy', () => {
    it('should respect role hierarchy', () => {
      const ownerRole = ROLES.find((r) => r.name === 'TENANT_OWNER');
      const viewerRole = ROLES.find((r) => r.name === 'VIEWER');

      expect(ownerRole?.permissions.length).toBeGreaterThan(
        viewerRole?.permissions.length || 0
      );
    });

    it('should include all viewer permissions in developer role', () => {
      const developerRole = ROLES.find((r) => r.name === 'DEVELOPER');
      const viewerRole = ROLES.find((r) => r.name === 'VIEWER');

      viewerRole?.permissions.forEach((permission) => {
        expect(developerRole?.permissions).toContain(permission);
      });
    });
  });
});
