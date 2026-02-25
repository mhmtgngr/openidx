import { apiClient } from './client'
import type {
  AccessReview,
  AccessReviewItem,
  SubmitDecisionRequest,
  Policy,
  CreatePolicyRequest,
  PaginatedResponse,
  ListParams,
} from './types'

export const governanceApi = {
  // Access reviews
  async getReviews(params?: ListParams & { status?: AccessReview['status'] }): Promise<PaginatedResponse<AccessReview>> {
    const response = await apiClient.get<PaginatedResponse<AccessReview>>('/api/v1/governance/reviews', {
      params,
    })
    return response.data
  },

  async getReview(id: string): Promise<AccessReview & { items: AccessReviewItem[] }> {
    const response = await apiClient.get<AccessReview & { items: AccessReviewItem[] }>(
      `/api/v1/governance/reviews/${id}`,
    )
    return response.data
  },

  async submitDecision(
    reviewId: string,
    itemId: string,
    decision: SubmitDecisionRequest,
  ): Promise<AccessReviewItem> {
    const response = await apiClient.post<AccessReviewItem>(
      `/api/v1/governance/reviews/${reviewId}/items/${itemId}/decision`,
      decision,
    )
    return response.data
  },

  async submitBulkDecision(
    reviewId: string,
    decision: SubmitDecisionRequest,
    itemIds?: string[],
  ): Promise<AccessReviewItem[]> {
    const response = await apiClient.post<AccessReviewItem[]>(
      `/api/v1/governance/reviews/${reviewId}/bulk-decision`,
      {
        ...decision,
        item_ids: itemIds,
      },
    )
    return response.data
  },

  // Policies
  async getPolicies(params?: ListParams & { status?: Policy['status'] }): Promise<PaginatedResponse<Policy>> {
    const response = await apiClient.get<PaginatedResponse<Policy>>('/api/v1/governance/policies', {
      params,
    })
    return response.data
  },

  async getPolicy(id: string): Promise<Policy> {
    const response = await apiClient.get<Policy>(`/api/v1/governance/policies/${id}`)
    return response.data
  },

  async createPolicy(data: CreatePolicyRequest): Promise<Policy> {
    const response = await apiClient.post<Policy>('/api/v1/governance/policies', data)
    return response.data
  },

  async updatePolicy(id: string, data: Partial<CreatePolicyRequest>): Promise<Policy> {
    const response = await apiClient.put<Policy>(`/api/v1/governance/policies/${id}`, data)
    return response.data
  },

  async deletePolicy(id: string): Promise<void> {
    await apiClient.delete(`/api/v1/governance/policies/${id}`)
  },

  async activatePolicy(id: string): Promise<Policy> {
    const response = await apiClient.post<Policy>(`/api/v1/governance/policies/${id}/activate`)
    return response.data
  },

  async deactivatePolicy(id: string): Promise<Policy> {
    const response = await apiClient.post<Policy>(`/api/v1/governance/policies/${id}/deactivate`)
    return response.data
  },
}
