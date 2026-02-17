/**
 * Tenant Isolation Tests
 */

import { TenantIsolationManager, TenantContext } from '../tenant-isolation';

describe('TenantIsolationManager', () => {
  let manager: TenantIsolationManager;

  beforeEach(() => {
    manager = new TenantIsolationManager();
  });

  describe('registerTenant', () => {
    it('should register new tenant successfully', async () => {
      const context: TenantContext = {
        tenantId: 'tenant-test-123',
        organizationId: 'org-456',
        isolationLevel: 'enhanced',
        dataResidency: 'eu-west-1',
        encryptionKeyId: 'kms-789',
        complianceProfile: {
          gdpr: true,
          hipaa: false,
          soc2: true,
          iso27001: true,
          pciDss: false,
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      await manager.registerTenant(context);

      const retrieved = manager.getTenantContext('tenant-test-123');
      expect(retrieved).toBeDefined();
      expect(retrieved?.isolationLevel).toBe('enhanced');
    });

    it('should reject duplicate tenant registration', async () => {
      const context: TenantContext = {
        tenantId: 'tenant-test-123',
        organizationId: 'org-456',
        isolationLevel: 'standard',
        dataResidency: 'us-east-1',
        encryptionKeyId: 'kms-789',
        complianceProfile: {
          gdpr: false,
          hipaa: false,
          soc2: false,
          iso27001: false,
          pciDss: false,
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      await manager.registerTenant(context);

      await expect(manager.registerTenant(context)).rejects.toThrow(
        'already registered'
      );
    });

    it('should reject invalid tenant context', async () => {
      const context: any = {
        tenantId: 'short',
        organizationId: 'org-456',
      };

      await expect(manager.registerTenant(context)).rejects.toThrow();
    });
  });

  describe('validateTenantAccess', () => {
    beforeEach(async () => {
      await manager.registerTenant({
        tenantId: 'tenant-test-123',
        organizationId: 'org-456',
        isolationLevel: 'standard',
        dataResidency: 'us-east-1',
        encryptionKeyId: 'kms-789',
        complianceProfile: {
          gdpr: false,
          hipaa: false,
          soc2: false,
          iso27001: false,
          pciDss: false,
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });

    it('should allow access for valid tenant and resource', () => {
      expect(
        manager.validateTenantAccess('tenant-test-123', 'resource-123', 'READ')
      ).toBe(true);
    });

    it('should reject access for unknown tenant', () => {
      expect(() =>
        manager.validateTenantAccess('tenant-unknown', 'resource-123', 'READ')
      ).toThrow('Unauthorized: Tenant not found');
    });
  });

  describe('getTenantMetrics', () => {
    it('should return metrics for registered tenant', async () => {
      await manager.registerTenant({
        tenantId: 'tenant-test-123',
        organizationId: 'org-456',
        isolationLevel: 'standard',
        dataResidency: 'us-east-1',
        encryptionKeyId: 'kms-789',
        complianceProfile: {
          gdpr: false,
          hipaa: false,
          soc2: false,
          iso27001: false,
          pciDss: false,
        },
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const metrics = manager.getTenantMetrics('tenant-test-123');
      expect(metrics).toBeDefined();
      expect(metrics?.requestCount).toBe(0);
    });
  });
});
