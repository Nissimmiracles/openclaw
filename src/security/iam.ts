/**
 * Identity & Access Management (IAM)
 * Implements RBAC (Role-Based) and ABAC (Attribute-Based) Access Control
 * Zero Trust principle: Least privilege access
 */

import { randomUUID } from 'crypto';
import { TenantContext } from './tenant-isolation';

export interface User {
  userId: string;
  tenantId: string;
  email: string;
  roles: Role[];
  attributes: Record<string, any>;
  createdAt: Date;
  lastLogin?: Date;
  mfaEnabled: boolean;
}

export interface ServiceAccount {
  serviceAccountId: string;
  tenantId: string;
  name: string;
  description: string;
  roles: Role[];
  apiKeyHash: string;
  createdAt: Date;
  expiresAt?: Date;
  active: boolean;
}

export enum Role {
  // Admin roles
  TENANT_ADMIN = 'tenant_admin',
  ORG_ADMIN = 'org_admin',

  // User roles
  DEVELOPER = 'developer',
  OPERATOR = 'operator',
  ANALYST = 'analyst',
  VIEWER = 'viewer',

  // Agent roles
  AGENT = 'agent',
  AGENT_ADMIN = 'agent_admin',

  // Service roles
  SERVICE_ACCOUNT = 'service_account',
  API_CLIENT = 'api_client',
}

export interface Permission {
  resource: string; // e.g., 'agent', 'memory', 'plugin', 'channel'
  action: string; // e.g., 'read', 'write', 'delete', 'execute'
  conditions?: Condition[];
}

export interface Condition {
  attribute: string;
  operator: 'equals' | 'notEquals' | 'contains' | 'greaterThan' | 'lessThan';
  value: any;
}

export interface AccessToken {
  token: string;
  userId: string;
  tenantId: string;
  roles: Role[];
  issuedAt: Date;
  expiresAt: Date;
  type: 'access' | 'refresh';
}

export class IAMManager {
  private users = new Map<string, User>();
  private serviceAccounts = new Map<string, ServiceAccount>();
  private rolePermissions = new Map<Role, Permission[]>();
  private activeTokens = new Map<string, AccessToken>();

  constructor() {
    this.initializeRolePermissions();
  }

  /**
   * Initialize default role permissions (RBAC)
   */
  private initializeRolePermissions(): void {
    // Tenant Admin - Full access to tenant resources
    this.rolePermissions.set(Role.TENANT_ADMIN, [
      { resource: '*', action: '*' },
    ]);

    // Org Admin - Manage users and settings
    this.rolePermissions.set(Role.ORG_ADMIN, [
      { resource: 'user', action: '*' },
      { resource: 'settings', action: '*' },
      { resource: 'billing', action: 'read' },
    ]);

    // Developer - Create and manage agents
    this.rolePermissions.set(Role.DEVELOPER, [
      { resource: 'agent', action: '*' },
      { resource: 'plugin', action: '*' },
      { resource: 'memory', action: 'read' },
      { resource: 'memory', action: 'write' },
      { resource: 'channel', action: 'read' },
    ]);

    // Operator - Run and monitor agents
    this.rolePermissions.set(Role.OPERATOR, [
      { resource: 'agent', action: 'read' },
      { resource: 'agent', action: 'execute' },
      { resource: 'memory', action: 'read' },
      { resource: 'channel', action: 'read' },
      { resource: 'channel', action: 'write' },
    ]);

    // Analyst - View data and analytics
    this.rolePermissions.set(Role.ANALYST, [
      { resource: 'agent', action: 'read' },
      { resource: 'memory', action: 'read' },
      { resource: 'analytics', action: 'read' },
      { resource: 'logs', action: 'read' },
    ]);

    // Viewer - Read-only access
    this.rolePermissions.set(Role.VIEWER, [
      { resource: '*', action: 'read' },
    ]);

    // Agent - Limited agent execution permissions
    this.rolePermissions.set(Role.AGENT, [
      { resource: 'memory', action: 'read' },
      { resource: 'memory', action: 'write' },
      { resource: 'plugin', action: 'execute' },
      { resource: 'channel', action: 'write' },
    ]);

    // Agent Admin - Manage agent infrastructure
    this.rolePermissions.set(Role.AGENT_ADMIN, [
      { resource: 'agent', action: '*' },
      { resource: 'plugin', action: '*' },
      { resource: 'memory', action: '*' },
    ]);

    // Service Account - M2M API access
    this.rolePermissions.set(Role.SERVICE_ACCOUNT, [
      { resource: 'api', action: '*' },
    ]);
  }

  /**
   * Create new user with roles
   */
  async createUser(
    tenantId: string,
    email: string,
    roles: Role[],
    attributes?: Record<string, any>
  ): Promise<User> {
    const user: User = {
      userId: randomUUID(),
      tenantId,
      email,
      roles,
      attributes: attributes || {},
      createdAt: new Date(),
      mfaEnabled: false,
    };

    this.users.set(user.userId, user);

    console.log(`[IAM] Created user: ${user.email} with roles: ${roles.join(', ')}`);

    return user;
  }

  /**
   * Create service account for M2M authentication
   */
  async createServiceAccount(
    tenantId: string,
    name: string,
    roles: Role[],
    expiresAt?: Date
  ): Promise<{ serviceAccount: ServiceAccount; apiKey: string }> {
    const apiKey = this.generateAPIKey();
    const apiKeyHash = await this.hashAPIKey(apiKey);

    const serviceAccount: ServiceAccount = {
      serviceAccountId: randomUUID(),
      tenantId,
      name,
      description: `Service account for ${name}`,
      roles,
      apiKeyHash,
      createdAt: new Date(),
      expiresAt,
      active: true,
    };

    this.serviceAccounts.set(serviceAccount.serviceAccountId, serviceAccount);

    console.log(
      `[IAM] Created service account: ${name} with roles: ${roles.join(', ')}`
    );

    return { serviceAccount, apiKey };
  }

  /**
   * Generate short-lived access token (15 minutes)
   */
  async generateAccessToken(
    userId: string,
    tenantId: string
  ): Promise<AccessToken> {
    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    if (user.tenantId !== tenantId) {
      throw new Error('User does not belong to this tenant');
    }

    const token: AccessToken = {
      token: this.generateJWT(user),
      userId: user.userId,
      tenantId: user.tenantId,
      roles: user.roles,
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      type: 'access',
    };

    this.activeTokens.set(token.token, token);

    // Auto-cleanup expired tokens
    setTimeout(() => {
      this.activeTokens.delete(token.token);
    }, 15 * 60 * 1000);

    return token;
  }

  /**
   * Generate refresh token (7 days)
   */
  async generateRefreshToken(
    userId: string,
    tenantId: string
  ): Promise<AccessToken> {
    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const token: AccessToken = {
      token: this.generateJWT(user, true),
      userId: user.userId,
      tenantId: user.tenantId,
      roles: user.roles,
      issuedAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      type: 'refresh',
    };

    this.activeTokens.set(token.token, token);

    return token;
  }

  /**
   * Check if user has permission (RBAC + ABAC)
   */
  async checkPermission(
    userId: string,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): Promise<boolean> {
    const user = this.users.get(userId);
    if (!user) {
      return false;
    }

    // Check RBAC permissions
    for (const role of user.roles) {
      const permissions = this.rolePermissions.get(role) || [];

      for (const permission of permissions) {
        // Check wildcard permissions
        if (permission.resource === '*' && permission.action === '*') {
          return true;
        }

        // Check resource match
        const resourceMatch =
          permission.resource === resource || permission.resource === '*';
        const actionMatch = permission.action === action || permission.action === '*';

        if (resourceMatch && actionMatch) {
          // If conditions exist, evaluate ABAC
          if (permission.conditions && context) {
            const conditionsMet = this.evaluateConditions(
              permission.conditions,
              { ...user.attributes, ...context }
            );
            if (conditionsMet) {
              return true;
            }
          } else {
            return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Evaluate ABAC conditions
   */
  private evaluateConditions(
    conditions: Condition[],
    context: Record<string, any>
  ): boolean {
    return conditions.every((condition) => {
      const attributeValue = context[condition.attribute];

      switch (condition.operator) {
        case 'equals':
          return attributeValue === condition.value;
        case 'notEquals':
          return attributeValue !== condition.value;
        case 'contains':
          return (
            Array.isArray(attributeValue) &&
            attributeValue.includes(condition.value)
          );
        case 'greaterThan':
          return attributeValue > condition.value;
        case 'lessThan':
          return attributeValue < condition.value;
        default:
          return false;
      }
    });
  }

  /**
   * Grant role to user
   */
  async grantRole(userId: string, role: Role): Promise<void> {
    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    if (!user.roles.includes(role)) {
      user.roles.push(role);
      console.log(`[IAM] Granted role ${role} to user ${user.email}`);
    }
  }

  /**
   * Revoke role from user
   */
  async revokeRole(userId: string, role: Role): Promise<void> {
    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    user.roles = user.roles.filter((r) => r !== role);
    console.log(`[IAM] Revoked role ${role} from user ${user.email}`);
  }

  /**
   * Get user by ID
   */
  getUser(userId: string): User | undefined {
    return this.users.get(userId);
  }

  /**
   * Get service account by ID
   */
  getServiceAccount(serviceAccountId: string): ServiceAccount | undefined {
    return this.serviceAccounts.get(serviceAccountId);
  }

  /**
   * Validate access token
   */
  async validateAccessToken(token: string): Promise<AccessToken | null> {
    const accessToken = this.activeTokens.get(token);

    if (!accessToken) {
      return null;
    }

    // Check expiration
    if (accessToken.expiresAt < new Date()) {
      this.activeTokens.delete(token);
      return null;
    }

    return accessToken;
  }

  /**
   * Revoke token (logout)
   */
  async revokeToken(token: string): Promise<void> {
    this.activeTokens.delete(token);
    console.log('[IAM] Token revoked');
  }

  /**
   * Generate JWT token
   */
  private generateJWT(user: User, isRefreshToken = false): string {
    // TODO: Implement actual JWT generation using jsonwebtoken library
    // Include claims:
    // - sub: user.userId
    // - tenant_id: user.tenantId
    // - roles: user.roles
    // - exp: expiration timestamp
    // - iat: issued at timestamp
    // - iss: 'openclaw-auth-service'

    const payload = {
      sub: user.userId,
      tenant_id: user.tenantId,
      email: user.email,
      roles: user.roles,
      type: isRefreshToken ? 'refresh' : 'access',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(
        Date.now() / 1000 + (isRefreshToken ? 7 * 24 * 60 * 60 : 15 * 60)
      ),
      iss: 'openclaw-auth-service',
    };

    // Placeholder - implement actual JWT signing
    return Buffer.from(JSON.stringify(payload)).toString('base64');
  }

  /**
   * Generate API key for service accounts
   */
  private generateAPIKey(): string {
    const prefix = 'oc_'; // OpenClaw prefix
    const randomPart = randomUUID().replace(/-/g, '');
    return `${prefix}${randomPart}`;
  }

  /**
   * Hash API key for secure storage
   */
  private async hashAPIKey(apiKey: string): Promise<string> {
    // TODO: Implement actual hashing using bcrypt or argon2
    // This is a placeholder
    return Buffer.from(apiKey).toString('base64');
  }
}

/**
 * Export singleton instance
 */
export const iamManager = new IAMManager();
