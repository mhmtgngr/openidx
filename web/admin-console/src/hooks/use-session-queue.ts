import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, PamAccessRequest } from '../lib/api'

// A launch approval in the queue, and the route that decides it: the
// sponsor's for one of the caller's external users, else the administrators'.
export type QueuedLaunch = PamAccessRequest & { asSponsor: boolean }
// A moderation request, likewise.
export type QueuedModeration = {
  id: string
  name: string
  requester: string
  reason?: string
  created_at: string
  asSponsor: boolean
}

/** useSessionQueue loads the caller's queues; count is what waits on them. */
export function useSessionQueue(isAdmin: boolean) {
  const adminLaunches = useQuery({
    queryKey: ['pam-entry-requests'],
    enabled: isAdmin,
    queryFn: () => api.pam.listRequests(),
  })
  const sponsorLaunches = useQuery({
    queryKey: ['pam-sponsored-requests'],
    queryFn: () => api.pam.listSponsoredRequests(),
  })
  const adminModeration = useQuery({
    queryKey: ['pam-moderation-pending'],
    enabled: isAdmin,
    queryFn: () => api.pam.listPendingModeration(),
  })
  const sponsorModeration = useQuery({
    queryKey: ['pam-sponsored-moderation'],
    queryFn: () => api.pam.listSponsoredModeration(),
  })
  const moderating = useQuery({
    queryKey: ['pam-moderating'],
    queryFn: () => api.pam.listModerating(),
  })
  const sponsoredSessions = useQuery({
    queryKey: ['pam-sponsored-sessions'],
    queryFn: () => api.pam.listSponsoredSessions(),
  })

  const launches = useMemo<QueuedLaunch[]>(() => {
    // The sponsor's copy of a request wins: it is the one they may approve.
    const bySponsor = new Map((sponsorLaunches.data?.requests ?? []).map((r) => [r.id, { ...r, asSponsor: true }]))
    const rest = (adminLaunches.data?.requests ?? [])
      .filter((r) => !bySponsor.has(r.id))
      .map((r) => ({ ...r, asSponsor: false }))
    return [...bySponsor.values(), ...rest]
  }, [adminLaunches.data, sponsorLaunches.data])

  const moderation = useMemo<QueuedModeration[]>(() => {
    const bySponsor = new Map(
      (sponsorModeration.data?.pending ?? []).map((m) => [
        m.id,
        { id: m.id, name: m.entry_name, requester: m.user, reason: m.reason, created_at: m.created_at, asSponsor: true },
      ]),
    )
    const rest = (adminModeration.data?.pending ?? [])
      .filter((m) => !bySponsor.has(m.id))
      .map((m) => ({
        id: m.id,
        name: m.entry_name || m.connection || m.connection_id || '',
        requester: m.requester || m.requester_id,
        reason: m.reason,
        created_at: m.created_at,
        asSponsor: false,
      }))
    return [...bySponsor.values(), ...rest]
  }, [adminModeration.data, sponsorModeration.data])

  const moderated = moderating.data?.moderations ?? []
  const sessions = sponsoredSessions.data?.sessions ?? []
  return {
    launches,
    moderation,
    moderated,
    sessions,
    count: launches.length + moderation.length,
    loading: sponsorLaunches.isLoading || sponsorModeration.isLoading,
  }
}
