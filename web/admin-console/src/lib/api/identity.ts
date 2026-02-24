import { apiClient } from './client'
import type {
  User,
  CreateUserRequest,
  UpdateUserRequest,
  UserSession,
  PaginatedResponse,
  ListParams,
} from './types'

export const identityApi = {
  // User management
  async getUsers(params?: ListParams): Promise<PaginatedResponse<User>> {
    const response = await apiClient.get<PaginatedResponse<User>>('/api/v1/identity/users', {
      params,
    })
    return response.data
  },

  async getUser(id: string): Promise<User> {
    const response = await apiClient.get<User>(`/api/v1/identity/users/${id}`)
    return response.data
  },

  async createUser(data: CreateUserRequest): Promise<User> {
    const response = await apiClient.post<User>('/api/v1/identity/users', data)
    return response.data
  },

  async updateUser(id: string, data: UpdateUserRequest): Promise<User> {
    const response = await apiClient.put<User>(`/api/v1/identity/users/${id}`, data)
    return response.data
  },

  async deleteUser(id: string): Promise<void> {
    await apiClient.delete(`/api/v1/identity/users/${id}`)
  },

  // User sessions
  async getUserSessions(id: string): Promise<UserSession[]> {
    const response = await apiClient.get<UserSession[]>(`/api/v1/identity/users/${id}/sessions`)
    return response.data
  },

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    await apiClient.delete(`/api/v1/identity/users/${userId}/sessions/${sessionId}`)
  },

  async revokeAllSessions(userId: string): Promise<void> {
    await apiClient.delete(`/api/v1/identity/users/${userId}/sessions`)
  },
}
