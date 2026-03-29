// OpenIDX API Examples - JavaScript / TypeScript

// Note: This file contains both JavaScript and TypeScript examples.
// TypeScript users should install types: npm install @types/node

// ============================================
// Authentication
// ============================================

/**
 * OAuth 2.0 Client Class
 * Handles token acquisition and refresh
 */
class OpenIDXOAuthClient {
  constructor(config) {
    this.tokenUrl = config.tokenUrl || 'http://localhost:8006/oauth/token';
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.scope = config.scope || 'openid profile email';
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = null;
  }

  /**
   * Get access token using client credentials grant
   */
  async getClientCredentialsToken() {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        scope: this.scope
      })
    });

    if (!response.ok) {
      throw new Error(`Authentication failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.tokenExpiresAt = Date.now() + (data.expires_in * 1000);
    return this.accessToken;
  }

  /**
   * Get access token using resource owner password grant
   */
  async getPasswordGrantToken(username, password) {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'password',
        username: username,
        password: password,
        scope: this.scope
      })
    });

    if (!response.ok) {
      throw new Error(`Authentication failed: ${response.statusText}`);
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    this.tokenExpiresAt = Date.now() + (data.expires_in * 1000);
    return this.accessToken;
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshAccessToken() {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'refresh_token',
        refresh_token: this.refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret
      })
    });

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token || this.refreshToken;
    this.tokenExpiresAt = Date.now() + (data.expires_in * 1000);
    return this.accessToken;
  }

  /**
   * Get valid access token, refreshing if necessary
   */
  async getValidToken() {
    if (!this.accessToken || !this.tokenExpiresAt || Date.now() >= this.tokenExpiresAt - 60000) {
      if (this.refreshToken) {
        return this.refreshAccessToken();
      }
      return this.getClientCredentialsToken();
    }
    return this.accessToken;
  }
}

// ============================================
// API Client Class
// ============================================

/**
 * Main API Client for OpenIDX
 */
class OpenIDXClient {
  constructor(config) {
    this.oauth = new OpenIDXOAuthClient(config);
    this.baseUrl = config.baseUrl || 'http://localhost:8001';
  }

  /**
   * Make authenticated API request
   */
  async request(method, path, data = null, options = {}) {
    const token = await this.oauth.getValidToken();

    const headers = {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers
    };

    const config = {
      method,
      headers,
      ...options
    };

    if (data) {
      config.body = JSON.stringify(data);
    }

    const response = await fetch(`${this.baseUrl}${path}`, config);

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || `Request failed: ${response.statusText}`);
    }

    return response.json();
  }

  // Convenience methods
  get(path, options) { return this.request('GET', path, null, options); }
  post(path, data, options) { return this.request('POST', path, data, options); }
  put(path, data, options) { return this.request('PUT', path, data, options); }
  delete(path, options) { return this.request('DELETE', path, null, options); }
  patch(path, data, options) { return this.request('PATCH', path, data, options); }
}

// ============================================
// Identity Service
// ============================================

class IdentityService extends OpenIDXClient {
  constructor(config) {
    super({ ...config, baseUrl: config.baseUrl || 'http://localhost:8001' });
  }

  /**
   * List users with pagination
   */
  async listUsers(params = {}) {
    const query = new URLSearchParams({
      offset: params.offset || 0,
      limit: params.limit || 20,
      ...params
    }).toString();
    return this.get(`/api/v1/identity/users?${query}`);
  }

  /**
   * Get user by ID
   */
  async getUser(userId) {
    return this.get(`/api/v1/identity/users/${userId}`);
  }

  /**
   * Create new user
   */
  async createUser(userData) {
    return this.post('/api/v1/identity/users', userData);
  }

  /**
   * Update user
   */
  async updateUser(userId, userData) {
    return this.put(`/api/v1/identity/users/${userId}`, userData);
  }

  /**
   * Delete user
   */
  async deleteUser(userId) {
    return this.delete(`/api/v1/identity/users/${userId}`);
  }

  /**
   * Get user sessions
   */
  async getUserSessions(userId) {
    return this.get(`/api/v1/identity/users/${userId}/sessions`);
  }

  /**
   * Create group
   */
  async createGroup(groupData) {
    return this.post('/api/v1/identity/groups', groupData);
  }

  /**
   * List groups
   */
  async listGroups(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.get(`/api/v1/identity/groups?${query}`);
  }
}

// ============================================
// Governance Service
// ============================================

class GovernanceService extends OpenIDXClient {
  constructor(config) {
    super({ ...config, baseUrl: config.baseUrl || 'http://localhost:8002' });
  }

  /**
   * List access reviews
   */
  async listReviews(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.get(`/api/v1/governance/reviews?${query}`);
  }

  /**
   * Create access review
   */
  async createReview(reviewData) {
    return this.post('/api/v1/governance/reviews', reviewData);
  }

  /**
   * Submit review decision
   */
  async submitDecision(reviewId, itemId, decisionData) {
    return this.post(
      `/api/v1/governance/reviews/${reviewId}/items/${itemId}/decision`,
      decisionData
    );
  }
}

// ============================================
// Provisioning Service (SCIM)
// ============================================

class ProvisioningService extends OpenIDXClient {
  constructor(config) {
    super({ ...config, baseUrl: config.baseUrl || 'http://localhost:8003' });
  }

  /**
   * List SCIM users
   */
  async listSCIMUsers(params = {}) {
    const query = new URLSearchParams({
      count: params.count || 100,
      startIndex: params.startIndex || 1,
      ...params
    }).toString();
    return this.get(`/scim/v2/Users?${query}`);
  }

  /**
   * Create SCIM user
   */
  async createSCIMUser(userData) {
    return this.post('/scim/v2/Users', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      ...userData
    });
  }

  /**
   * Update SCIM user (PATCH operation)
   */
  async patchSCIMUser(userId, operations) {
    return this.patch(`/scim/v2/Users/${userId}`, {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: operations
    });
  }

  /**
   * Delete SCIM user
   */
  async deleteSCIMUser(userId) {
    return this.delete(`/scim/v2/Users/${userId}`);
  }
}

// ============================================
// Audit Service
// ============================================

class AuditService extends OpenIDXClient {
  constructor(config) {
    super({ ...config, baseUrl: config.baseUrl || 'http://localhost:8004' });
  }

  /**
   * Query audit events
   */
  async queryEvents(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.get(`/api/v1/audit/events?${query}`);
  }

  /**
   * Generate compliance report
   */
  async generateReport(reportData) {
    return this.post('/api/v1/audit/reports', reportData);
  }

  /**
   * Get audit statistics
   */
  async getStatistics(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.get(`/api/v1/audit/statistics?${query}`);
  }
}

// ============================================
// Admin API
// ============================================

class AdminAPIService extends OpenIDXClient {
  constructor(config) {
    super({ ...config, baseUrl: config.baseUrl || 'http://localhost:8005' });
  }

  /**
   * Get dashboard statistics
   */
  async getDashboard() {
    return this.get('/api/v1/dashboard');
  }

  /**
   * Create application
   */
  async createApplication(appData) {
    return this.post('/api/v1/applications', appData);
  }

  /**
   * Update system settings
   */
  async updateSettings(settings) {
    return this.put('/api/v1/settings', settings);
  }
}

// ============================================
// TypeScript Interfaces
// ============================================

/**
 * TypeScript type definitions for common API responses
 */

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
  scope: string;
}

interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  created_at: string;
  updated_at: string;
  role_id?: string;
  active: boolean;
}

interface Group {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  member_count?: number;
}

interface AccessReview {
  id: string;
  name: string;
  description?: string;
  start_date: string;
  end_date: string;
  status: 'pending' | 'in_progress' | 'completed';
  reviewer_ids: string[];
}

interface APIError {
  error: string;
  message: string;
  status: number;
  details?: Record<string, unknown>;
}

interface PaginatedResponse<T> {
  data: T[];
  meta: {
    total: number;
    page: number;
    per_page: number;
  };
}

// ============================================
// Usage Examples
// ============================================

// Initialize client
const client = new IdentityService({
  clientId: 'your_client_id',
  clientSecret: 'your_client_secret',
  baseUrl: 'http://localhost:8001'
});

// Example: List users
async function exampleListUsers() {
  try {
    const users = await client.listUsers({ limit: 10 });
    console.log('Users:', users.data);
    console.log('Total:', users.meta.total);
  } catch (error) {
    console.error('Error listing users:', error.message);
  }
}

// Example: Create a user
async function exampleCreateUser() {
  try {
    const newUser = await client.createUser({
      email: 'newuser@example.com',
      first_name: 'John',
      last_name: 'Doe',
      password: 'SecurePassword123!',
      role_id: 'role-id-here'
    });
    console.log('Created user:', newUser);
  } catch (error) {
    console.error('Error creating user:', error.message);
  }
}

// Example: Working with multiple services
async function exampleMultiService() {
  const config = {
    clientId: 'your_client_id',
    clientSecret: 'your_client_secret'
  };

  const identity = new IdentityService(config);
  const governance = new GovernanceService(config);
  const audit = new AuditService(config);

  // Get users from identity service
  const users = await identity.listUsers({ limit: 5 });

  // Get pending reviews from governance
  const reviews = await governance.listReviews({ status: 'pending' });

  // Query audit events
  const events = await audit.queryEvents({ limit: 50, sort: 'timestamp:desc' });

  return { users, reviews, events };
}

// Export for use in modules
export {
  OpenIDXOAuthClient,
  OpenIDXClient,
  IdentityService,
  GovernanceService,
  ProvisioningService,
  AuditService,
  AdminAPIService
};

export type {
  TokenResponse,
  User,
  Group,
  AccessReview,
  APIError,
  PaginatedResponse
};
