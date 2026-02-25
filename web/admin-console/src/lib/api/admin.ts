import { apiClient } from './client'
import type { DashboardStats, SystemSettings, Application } from './types'

export const adminApi = {
  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await apiClient.get<DashboardStats>('/api/v1/dashboard')
    return response.data
  },

  // Settings
  async getSettings(): Promise<SystemSettings> {
    const response = await apiClient.get<SystemSettings>('/api/v1/settings')
    return response.data
  },

  async updateSettings(data: Partial<SystemSettings>): Promise<SystemSettings> {
    const response = await apiClient.put<SystemSettings>('/api/v1/settings', data)
    return response.data
  },

  // Applications
  async getApplications(): Promise<Application[]> {
    const response = await apiClient.get<Application[]>('/api/v1/applications')
    return response.data
  },

  async getApplication(id: string): Promise<Application> {
    const response = await apiClient.get<Application>(`/api/v1/applications/${id}`)
    return response.data
  },

  async createApplication(data: {
    name: string
    description?: string
    redirect_uris: string[]
    grant_types: string[]
  }): Promise<Application> {
    const response = await apiClient.post<Application>('/api/v1/applications', data)
    return response.data
  },

  async updateApplication(
    id: string,
    data: Partial<{
      name: string
      description: string
      redirect_uris: string[]
      grant_types: string[]
      status: Application['status']
    }>,
  ): Promise<Application> {
    const response = await apiClient.put<Application>(`/api/v1/applications/${id}`, data)
    return response.data
  },

  async deleteApplication(id: string): Promise<void> {
    await apiClient.delete(`/api/v1/applications/${id}`)
  },
}
