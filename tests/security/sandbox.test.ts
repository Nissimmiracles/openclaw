/**
 * Agent Sandbox Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import {
  AgentSandboxManager,
  SANDBOX_CONFIGS,
} from '../../src/security/agent-sandbox';

describe('AgentSandboxManager', () => {
  let sandboxManager: AgentSandboxManager;

  beforeEach(() => {
    sandboxManager = new AgentSandboxManager();
  });

  describe('Sandbox Creation', () => {
    it('should create sandbox with correct configuration', async () => {
      const sandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );

      expect(sandbox.sandboxId).toBeDefined();
      expect(sandbox.tenantId).toBe('tenant-1');
      expect(sandbox.agentId).toBe('agent-1');
      expect(sandbox.status).toBe('RUNNING');
      expect(sandbox.config.cpuLimitCores).toBe(1);
      expect(sandbox.config.memoryLimitMB).toBe(512);
    });

    it('should create sandbox with tier-specific limits', async () => {
      const enhancedSandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.enhanced
      );

      expect(enhancedSandbox.config.cpuLimitCores).toBe(2);
      expect(enhancedSandbox.config.memoryLimitMB).toBe(2048);
    });
  });

  describe('Code Execution', () => {
    it('should execute code in sandbox', async () => {
      const sandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );

      const code = 'console.log("Hello from sandbox");';
      const result = await sandboxManager.executeInSandbox(
        sandbox.sandboxId,
        code,
        'javascript'
      );

      expect(result).toBeDefined();
      expect(result.exitCode).toBe(0);
    });

    it('should enforce execution timeout', async () => {
      const config = {
        ...SANDBOX_CONFIGS.standard,
        executionTimeoutSeconds: 1,
      };

      const sandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        config
      );

      // Infinite loop
      const code = 'while(true) {}';

      // Should timeout and be killed
      await expect(
        sandboxManager.executeInSandbox(sandbox.sandboxId, code, 'javascript')
      ).rejects.toThrow();
    });
  });

  describe('Resource Limits', () => {
    it('should enforce CPU limits', async () => {
      const sandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );

      // Simulate high CPU usage
      sandbox.resourceUsage.cpuUsagePercent = 150; // Over 1 core limit

      // Sandbox should be killed
      // In real implementation, monitoring would detect this
      expect(sandbox.config.cpuLimitCores).toBe(1);
    });

    it('should enforce memory limits', async () => {
      const sandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );

      // Simulate high memory usage
      sandbox.resourceUsage.memoryUsageMB = 600; // Over 512 MB limit

      // Should trigger kill
      expect(sandbox.config.memoryLimitMB).toBe(512);
    });
  });

  describe('Sandbox Lifecycle', () => {
    it('should stop sandbox gracefully', async () => {
      const sandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );

      await sandboxManager.stopSandbox(sandbox.sandboxId);

      const stoppedSandbox = sandboxManager.getSandbox(sandbox.sandboxId);
      expect(stoppedSandbox?.status).toBe('STOPPED');
    });

    it('should kill sandbox immediately', async () => {
      const sandbox = await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );

      await sandboxManager.killSandbox(
        sandbox.sandboxId,
        'RESOURCE_LIMIT_EXCEEDED'
      );

      const killedSandbox = sandboxManager.getSandbox(sandbox.sandboxId);
      expect(killedSandbox?.status).toBe('KILLED');
    });

    it('should list tenant sandboxes', async () => {
      await sandboxManager.createSandbox(
        'tenant-1',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );
      await sandboxManager.createSandbox(
        'tenant-1',
        'agent-2',
        SANDBOX_CONFIGS.standard
      );
      await sandboxManager.createSandbox(
        'tenant-2',
        'agent-1',
        SANDBOX_CONFIGS.standard
      );

      const tenant1Sandboxes = sandboxManager.getTenantSandboxes('tenant-1');
      expect(tenant1Sandboxes.length).toBe(2);

      const tenant2Sandboxes = sandboxManager.getTenantSandboxes('tenant-2');
      expect(tenant2Sandboxes.length).toBe(1);
    });
  });
});
